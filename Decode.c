#include "Decode.h"

ZyanStatus DisassembleInstruction(
    _In_ LPCVOID lpAddress,
    _Out_ ZydisDisassembledInstruction* pDecoded
) {
    if (NULL == pDecoded) {
        return ZYAN_STATUS_INVALID_ARGUMENT;
    }

    ZeroMemory(pDecoded, sizeof(*pDecoded));

    return ZydisDisassembleIntel(
        ZYDIS_MACHINE_MODE_LONG_64,
        (ZyanUPointer) lpAddress,
        lpAddress,
        AMD64_INSTRUCTION_MAX_LENGTH,
        pDecoded
    );
}

SIZE_T GetFunctionSize(
    _In_reads_bytes_(cbMaxSize) LPCVOID lpFunction,
    _In_ SIZE_T cbMaxSize
) {
    SIZE_T cbOffset = 0;

    while (cbOffset < cbMaxSize) {
        ZydisDisassembledInstruction decoded = { 0 };
        ZyanStatus status = ZydisDisassembleIntel(
            ZYDIS_MACHINE_MODE_LONG_64,
            (ZyanUPointer) lpFunction + cbOffset,
            (LPCBYTE) lpFunction + cbOffset,
            cbMaxSize - cbOffset,
            &decoded
        );

        if (!ZYAN_SUCCESS(status)) {
            return 0;
        }

        cbOffset += decoded.info.length;

        if (ZYDIS_MNEMONIC_RET == decoded.info.mnemonic) {
            return cbOffset;
        }
    }

    return 0;
}