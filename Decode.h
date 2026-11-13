#ifndef DECODE_H
#define DECODE_H

#include <Windows.h>

#include "Zydis.h"

#define AMD64_INSTRUCTION_MAX_LENGTH 15

ZyanStatus DisassembleInstruction(LPCVOID address, ZydisDisassembledInstruction* decoded);
SIZE_T GetFunctionSize(LPCVOID function, SIZE_T maxSize);

#endif