#include "Capstone.h"

csh Capstone::CpstHandle = { 0 };
cs_opt_mem Capstone::CpstOptMem = { 0 };

void Capstone::Init()
{

	Capstone::CpstOptMem.calloc = calloc;
	Capstone::CpstOptMem.free = free;
	Capstone::CpstOptMem.malloc = malloc;
	Capstone::CpstOptMem.realloc = realloc;
	Capstone::CpstOptMem.vsnprintf = (cs_vsnprintf_t)vsprintf_s;

	cs_option(0, CS_OPT_MEM, (size_t)&Capstone::CpstOptMem);

	cs_open(CS_ARCH_X86, CS_MODE_32, &Capstone::CpstHandle);
}

void Capstone::DisAsm(HANDLE hProcess, LPVOID lpAddr, DWORD dwInsCount)
{
	cs_insn* ins = nullptr;
	char *buf = new char[dwInsCount * 16]();

	SIZE_T size = 0, trueInsCount = 0;


	ReadProcessMemory(hProcess, lpAddr, buf, dwInsCount * 16, &size);
	trueInsCount = cs_disasm(Capstone::CpstHandle, (uint8_t*)buf, dwInsCount * 16,
		(uint64_t)lpAddr, dwInsCount, &ins);
	printf("-------------------------------------------Disasm-------------------------------------------\n");
	for (size_t i = 0; i < trueInsCount; ++i)
	{
		printf("0x%08X:\t\t", (UINT)ins[i].address);
		for (size_t j = 0; j < 16; ++j)
		{
			j < ins[i].size ? printf("%02X", ins[i].bytes[j])
				: printf("  ");
		}
		printf("\t%s\t%s\n", ins[i].mnemonic, ins[i].op_str);
	}
	delete[] buf;
	cs_free(ins, trueInsCount);
}

void  Capstone::getOneIns(HANDLE hProcess, LPVOID lpAddr, uint8_t **pInsByte, uint16_t *pnLen)
{
	cs_insn* ins = nullptr;
	char *buf = new char[16]();

	SIZE_T size = 0, trueInsCount = 0;


	ReadProcessMemory(hProcess, lpAddr, buf, 16, &size);
	trueInsCount = cs_disasm(Capstone::CpstHandle, (uint8_t*)buf, 16,
		(uint64_t)lpAddr, 1, &ins);
	
	*pnLen = ins[0].size;
	if (!(*pInsByte))
	{
		*pInsByte = new uint8_t[CS_MNEMONIC_SIZE]();
	}
	memcpy(*pInsByte, ins[0].mnemonic, CS_MNEMONIC_SIZE);

	delete[] buf;
	cs_free(ins, trueInsCount);

	
}


