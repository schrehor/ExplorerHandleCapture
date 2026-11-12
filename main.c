#include "Decode.h"

#include <stdio.h>

#define MAX_FUNC_SIZE       0x180
#define SHELLCODE_SIZE      0x12
#define RSP_SLOT_SIZE       0x08
#define INLINE_HOOK_SIZE    0x05
#define PROLOGUE_FRAME_SIZE 0x58

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

int wmain(int argc, wchar_t* argv[]) {
    if (2 == argc && 0 == wcscmp(argv[1], L"--assess")) {
        return AssessMain();
    }

    fwprintf(stderr, L"Usage: %s --assess\n", argv[0]);
    return EXIT_FAILURE;
}