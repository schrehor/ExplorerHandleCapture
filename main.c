#include "Decode.h"

#include <stdio.h>

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        fwprintf(stderr, L"Usage: %s <EXPLORER_PID> [--assess]\n", argv[0]);
        return EXIT_FAILURE;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (NULL == hKernel32) {
        fprintf(stderr, "[-] GetModuleHandleW: E%lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    FARPROC fpCreateProcessW = GetProcAddress(hKernel32, "CreateProcessW");
    if (NULL == fpCreateProcessW) {
        fprintf(stderr, "[-] GetProcAddress: E%lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    printf("[+] kernel32!CreateProcessW: 0x%p\n", (LPCVOID) fpCreateProcessW);
    return EXIT_SUCCESS;
}