#include "Decode.h"

ZyanStatus DisassembleInstruction(LPCVOID address, ZydisDisassembledInstruction* decoded)
{
	if (!decoded)
		return ZYAN_STATUS_INVALID_ARGUMENT;

	ZeroMemory(decoded, sizeof(*decoded));

	return ZydisDisassembleIntel(
		ZYDIS_MACHINE_MODE_LONG_64,
		(ZyanUPointer)address,
		address,
		AMD64_INSTRUCTION_MAX_LENGTH,
		decoded);
}

SIZE_T GetFunctionSize(LPCVOID function, SIZE_T maxSize)
{
	SIZE_T offset = 0;

	while (offset < maxSize)
	{
		ZydisDisassembledInstruction decoded = { 0 };
		ZyanStatus status = ZydisDisassembleIntel(
			ZYDIS_MACHINE_MODE_LONG_64,
			(ZyanUPointer)function + offset,
			(LPCBYTE)function + offset,
			maxSize - offset,
			&decoded);

		if (!ZYAN_SUCCESS(status))
			return 0;

		offset += decoded.info.length;

		if (decoded.info.mnemonic == ZYDIS_MNEMONIC_RET)
			return offset;
	}

	return 0;
}