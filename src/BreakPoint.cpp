#include <string.h>
#include "BreakPoint.h"


//
//std::vector<BREAKPOINTINFO> BreakPoint::vBreakPointInfo;
//std::map<LPVOID, BREAKPOINTINFO> BreakPoint::mBreakPointInfo;



/*********************************************
*	Set and Fix CC breakpoint.
*********************************************/
void BreakPoint::SetCCBreakPoint(
	HANDLE hProcess, 
	LPVOID addr, 
	BOOL bStepOver,
	std::map<LPVOID, BREAKPOINTINFO> *pMapBreakPointInfo)
{
	BREAKPOINTINFO bpInfo = { 0 };
	bpInfo.BpAttr.CC.CcOldOpcode = 0;
	bpInfo.bReset = FALSE;
	bpInfo.BpAttr.CC.bStepOver = bStepOver;

	ReadProcessMemory(hProcess, addr, &bpInfo.BpAttr.CC.CcOldOpcode, 1, NULL);
	WriteProcessMemory(hProcess, addr, "\xCC", 1, NULL);

	//vBreakPointInfo.push_back(bpInfo);

	(*pMapBreakPointInfo)[addr] = bpInfo;
}

void BreakPoint::FixCCBreakPoint(
	HANDLE hProcess, 
	HANDLE hThread, 
	LPVOID addr, 
	std::map<LPVOID, BREAKPOINTINFO> *pMapBreakPointInfo)
{
	std::map<LPVOID, BREAKPOINTINFO>::iterator it = pMapBreakPointInfo->find(addr);
	if (it != pMapBreakPointInfo->end())
	{
		CONTEXT context = { CONTEXT_CONTROL };
		GetThreadContext(hThread, &context);
		context.Eip -= 1;
		SetThreadContext(hThread, &context);
		WriteProcessMemory(hProcess, addr, &(it->second.BpAttr.CC.CcOldOpcode), 1, NULL);
		it->second.bReset = TRUE;

		if (it->second.BpAttr.CC.bStepOver)
		{
			pMapBreakPointInfo->erase(it);
		}

	}
}


/*********************************************
*	Set and Fix condition breakpoint.
*********************************************/
BOOL BreakPoint::SetConditionBreakPoing(HANDLE hProcess,
	LPVOID lpAddr,
	char *pReg,
	int nVal,
	std::map<LPVOID, BREAKPOINTINFO> *pMapBreakPointInfo,
	std::map<LPVOID, CONDITIONBP> *pMapConditionBreakPointInfo)
{
	char *regs[] = {
		"eax", "ebx", "ecx", "edx",
		"esi", "edi", "ebp", "esp",
		"eip", "flags"
	};
	CONDITIONBP conditionBp = { 0 };
	
	for (size_t i = 0; i < 10; ++i)
	{
		if (!_stricmp(regs[i], pReg))
		{
			strcpy_s(conditionBp.szReg, REG_NAME_LEN, pReg);
			conditionBp.nVal = nVal;

			BreakPoint::SetCCBreakPoint(hProcess, (LPVOID)lpAddr, FALSE, pMapBreakPointInfo);
			(*pMapConditionBreakPointInfo)[lpAddr] = conditionBp;
			return TRUE;
		}
	}

	return FALSE;
}

BOOL BreakPoint::CheckConditionBreakPoint(HANDLE hThread, CONDITIONBP * pConditionBP)
{
	CONTEXT context = { CONTEXT_CONTROL | CONTEXT_INTEGER };
	GetThreadContext(hThread, &context);

	char *pRegNames[] = {
		"eax", "ebx", "ecx", "edx",
		"esi", "edi", "ebp", "esp",
		"eip", "flags"
	};

	DWORD nRegValues[] = {
		context.Eax, context.Ebx, context.Ecx, context.Edx,
		context.Esi, context.Edi, context.Ebp, context.Esp,
		context.Eip, context.EFlags,
	};

	for (size_t i = 0; i < 10; ++i)
	{
		if (!_stricmp(pRegNames[i], pConditionBP->szReg))
		{
			if (pConditionBP->nVal == nRegValues[i])
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}



/*********************************************
*	TF single step breakpoint.
*********************************************/
void BreakPoint::SetTFBreakPoint(HANDLE hThread, LPVOID lpAddr)
{
	CONTEXT context = { CONTEXT_CONTROL };
	GetThreadContext(hThread, &context);
	context.EFlags |= 0x100;
	SetThreadContext(hThread, &context);
}

/*********************************************
*	Step over breakpoint.
*********************************************/
void BreakPoint::SetStepOverBreakPoint(
	HANDLE hProcess, 
	HANDLE hThread, 
	std::map<LPVOID, BREAKPOINTINFO> *pMapBreakPointInfo)
{
	uint8_t *pInsByte = NULL;
	uint16_t nLen = 0;
	LPVOID lpAddr = NULL;
	CONTEXT context = { CONTEXT_CONTROL };
	GetThreadContext(hThread, &context);
	lpAddr = (LPVOID)context.Eip;

	Capstone::getOneIns(hProcess, lpAddr, &pInsByte, &nLen);
	lpAddr = (LPVOID)((DWORD)lpAddr + nLen);
	if (!strcmp((const char*)"call", (const char*)pInsByte)
		|| strstr((const char*)pInsByte, "rep") == (const char*)pInsByte)
	{
		BreakPoint::SetCCBreakPoint(hProcess, lpAddr, TRUE, pMapBreakPointInfo);
	}
	else
	{
		BreakPoint::SetTFBreakPoint(hThread, lpAddr);
	}
	if (pInsByte)
	{
		delete[] pInsByte;
		pInsByte = NULL;
	}
}

/*********************************************
*	Set and Fix hardware breakpoint.
*********************************************/
BOOL BreakPoint::SetHdBreakPoint(
	HANDLE hThread, 
	LPVOID lpAddr, 
	BYTE type, 
	int len, 
	DWORD *pDr6)
{
	CONTEXT context = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(hThread, &context);

	PDR7 pDr7 = (PDR7)&context.Dr7;

	/********************************
	*	  If it's a r/w breakpoint,
	*	lpAddr need to be aligned.
	********************************/
	if (len == 1)
	{
		lpAddr = (LPVOID)((DWORD)lpAddr - (DWORD)lpAddr % 2);
	}
	else if (len == 3)
	{
		lpAddr = (LPVOID)((DWORD)lpAddr - (DWORD)lpAddr % 4);
	}
	else if(len ==2 || len >3)
	{
		return FALSE;
	}

	if (!pDr7->L0)
	{
		context.Dr0 = (DWORD)lpAddr;
		pDr7->L0 = 1;
		pDr7->RW0 = type;
		pDr7->LEN0 = len;

		context.Dr6 |= 1;
		*pDr6 &= ~1;
	}
	else if (!pDr7->L1)
	{
		context.Dr1 = (DWORD)lpAddr;
		pDr7->L1 = 1;
		pDr7->RW1 = type;
		pDr7->LEN1 = len;

		context.Dr6 |= 2;
		*pDr6 &= ~2;
	}
	else if (!pDr7->L2)
	{
		context.Dr2 = (DWORD)lpAddr;
		pDr7->L2 = 2;
		pDr7->RW2 = type;
		pDr7->LEN2 = len;

		context.Dr6 |= 4;
		*pDr6 &= ~4;
	}
	else if (!pDr7->L3)
	{
		context.Dr3 = (DWORD)lpAddr;
		pDr7->L3 = 3;
		pDr7->RW3 = type;
		pDr7->LEN3 = len;

		context.Dr6 |= 8;
		*pDr6 &= ~8;
	}
	else
	{
		printf("Ooops, there has been 4 hardware breakpoints.\n");
	}
	SetThreadContext(hThread, &context);
	return TRUE;
}

void BreakPoint::FixHdBreakPoint(
	HANDLE hThread, 
	LPVOID addr, 
	DWORD *pDr6)
{
	CONTEXT context = { CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL };
	GetThreadContext(hThread, &context);

	PDR7 pDr7 = (PDR7)&context.Dr7;

	if (context.Dr6 & 1)
	{
		pDr7->L0 = 0;
		*pDr6 |= 1;
	}
	else if (context.Dr6 & 2)
	{
		pDr7->L0 = 0;
		*pDr6 |= 2;
	}
	else if (context.Dr6 & 4)
	{
		pDr7->L0 = 0;
		*pDr6 |= 4;
	}
	else if (context.Dr6 & 8)
	{
		pDr7->L0 = 0;
		*pDr6 |= 8;
	}
	

	SetThreadContext(hThread, &context);

}


/*********************************************
*	Set and Fix memory breakpoint.
*********************************************/
void BreakPoint::SetMemBreakPoint(
	HANDLE hProcess, 
	BREAKPOINTINFO *pMemBreakPointInfo)
{
	
	BOOL bRet = FALSE;

	

	bRet = VirtualProtectEx(hProcess,
		(*pMemBreakPointInfo).BpAttr.MemAttr.lpAddr,
		1,
		(*pMemBreakPointInfo).BpAttr.MemAttr.dwNewProtect,
		&((*pMemBreakPointInfo).BpAttr.MemAttr.dwOldProtect));
	if (!bRet)
	{
		printf("VirtualProtectEx() error.\n");
	}

}

void BreakPoint::FixMemBreakPoint(
	HANDLE hProcess, 
	BREAKPOINTINFO *pMemBreakPointInfo,
	BOOL bReset)
{
	BOOL ret = VirtualProtectEx(hProcess,
		pMemBreakPointInfo->BpAttr.MemAttr.lpAddr,
		1,
		pMemBreakPointInfo->BpAttr.MemAttr.dwOldProtect,
		&(pMemBreakPointInfo->BpAttr.MemAttr.dwNewProtect));
	if (!ret)
	{
		printf("VirtualProtectEx() error.\n");
	}
	pMemBreakPointInfo->bReset = bReset;
	if (!bReset)
	{
		pMemBreakPointInfo->BpAttr.MemAttr.dwOldProtect = 0;
	}

}

void BreakPoint::SetApiBreakPoint(
	HANDLE hProcess,
	char *pAPI,
	std::map<LPVOID, BREAKPOINTINFO> *pMapBreakPointInfo)
{
	wchar_t *wszAPIs[] = {
		L"user32.dll", L"ntdll.dll", L"kernel32.dll"
	};
	LPVOID lpAPI = NULL;
	for (int i = 0; i < 3; ++i)
	{
		lpAPI = GetProcAddress(LoadLibraryW(wszAPIs[i]), pAPI);
		if (lpAPI) break;
	}
	BreakPoint::SetCCBreakPoint(hProcess, lpAPI, FALSE, pMapBreakPointInfo);
}


