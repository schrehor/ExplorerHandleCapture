#ifndef DECODE_H
#define DECODE_H

#include <Windows.h>

#include "Zydis.h"

#define AMD64_INSTRUCTION_MAX_LENGTH 15

ZyanStatus DisassembleInstruction(
    _In_ LPCVOID lpAddress,
    _Out_ ZydisDisassembledInstruction* pDecoded
);

SIZE_T GetFunctionSize(
    _In_reads_bytes_(cbMaxSize) LPCVOID lpFunction,
    _In_ SIZE_T cbMaxSize
);

#endif