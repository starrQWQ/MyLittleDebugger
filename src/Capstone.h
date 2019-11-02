#pragma once

#include <windows.h>
#include "Capstone\include\capstone.h"

#ifdef _64
#pragme comment(lib, "Capstone/capstone_x64".lib)
#else
#pragma comment(lib, "Capstone/capstone_x86.lib")
#endif

#pragma comment(linker, "/NODEFAULTLIB:\"libcmtd.lib\"")

class Capstone
{
private:
	static csh CpstHandle;
	static cs_opt_mem CpstOptMem;
public:
	Capstone() = default;
	~Capstone() = default;

	static void Init();
	static void DisAsm(HANDLE hProcess, LPVOID lpAddr, DWORD dwInsCount);

	static void getOneIns(HANDLE hProcess, LPVOID lpAddr, uint8_t **pInsByte, uint16_t *pnLen);
};