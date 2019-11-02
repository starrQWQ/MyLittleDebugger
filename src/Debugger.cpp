#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#include <direct.h>

#include "Debugger.h"



Debugger::Debugger()
	: m_hProcess(nullptr)
	, m_hThread(nullptr)
	, m_bRestart(FALSE)
	, m_Dr6(0)
	, m_bFirstBreakPoint(TRUE)
	, m_bAntiAntiDebug(FALSE)
{
	memset(&m_memBreakPointInfo, 0, sizeof(m_memBreakPointInfo));
	m_memBreakPointInfo.bReset = FALSE;
	m_memBreakPointInfo.BpAttr.MemAttr.dwOldProtect = 0;

	memset(m_szTargetName, 0, MAX_PATH);

	loadPlug();
}

Debugger::~Debugger()
{
	CloseHandles();
	m_mapBreakPointInfo.clear();
	m_mapConditionBreakPointInfo.clear();

}

void Debugger::OpenHandles()
{
	m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_DbgEvent.dwProcessId);
	m_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_DbgEvent.dwThreadId);
}

void Debugger::CloseHandles()
{
	if (m_hProcess)
	{
		CloseHandle(m_hProcess);
		m_hProcess = nullptr;
	}

	if (m_hThread)
	{
		CloseHandle(m_hThread);
		m_hThread = nullptr;
	}
}

/*********************
*	Open a exe.
*********************/
void Debugger::open(LPCSTR filePath)
{
	STARTUPINFOA startup_info = { 0 };
	PROCESS_INFORMATION process_info = { 0 };

	BOOL ret = CreateProcessA(filePath, NULL, NULL, NULL, FALSE,
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE, 
		NULL, NULL,
		&startup_info, &process_info);

	if (ret)
	{
		printf("CreateProcess() successfully\n.\n");
		
		strcpy_s(m_szTargetName, MAX_PATH, filePath);
		CloseHandle(process_info.hProcess);
		CloseHandle(process_info.hThread);
		Capstone::Init();
	}
	else
	{
		printf("CreateProcess() error\n.\n");
		system("pause");
		exit(0);
	}

	
}

/*********************
*	Attach a process
*********************/
void Debugger::attach(DWORD dwPID)
{
	BOOL ret = DebugActiveProcess(dwPID);
	if (ret)
	{
		printf("DebugActiveProcess() successfully\n.\n");
		Capstone::Init();
	}
	else
	{
		printf("DebugActiveProcess() error.\n");
		system("pause");
		exit(0);
	}
}


/************************************************************
*					Layer 1
*	  OpenHandles() to get process and thread handle, and
*	CloseHandles() after ContinueDebugEvent().
*************************************************************/
void Debugger::run()
{
	DWORD dwContinueStatus = DBG_CONTINUE;
	m_bRestart = FALSE;

	printf("run!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	
	while (WaitForDebugEvent(&m_DbgEvent, INFINITE))
	{
		OpenHandles();

		dwContinueStatus = DispatchEvent();
		
		ContinueDebugEvent(m_DbgEvent.dwProcessId, m_DbgEvent.dwThreadId, dwContinueStatus);
		/*******************************************
		*	Anti-AntiDebug(plugin & local function)
		*******************************************/
		if (!m_bAntiAntiDebug && !m_bFirstBreakPoint)
		{
			typedef BOOL (*PFunAntiAntiDebug)(HANDLE hProcess);
			PFunAntiAntiDebug pFunAntiAntiDebug = (PFunAntiAntiDebug)GetProcAddress(LoadLibraryA("..\\Debug\\plugin.dll"), "Anti_AntiDebug");
			if (pFunAntiAntiDebug)
			{
				if (!pFunAntiAntiDebug(m_hProcess))
				{
					printf("Anti_AntiDebug() error!!!!!!!!!!!\n\n\n\n\n");
				}
			}
			else if(!Anti_AntiDebug(m_hProcess))
			{
				printf("Anti_AntiDebug() error!!!!!!!!!!!\n\n\n\n\n");
			}
			m_bAntiAntiDebug = TRUE;
		}

		if (m_bRestart)
		{
			TerminateProcess(m_hProcess, 0);
			return;
		}
		
		/***************************************
		*	  Reset CC breakpoints.
		****************************************/
		for (std::map<LPVOID, BREAKPOINTINFO>::iterator it = m_mapBreakPointInfo.begin();
			it != m_mapBreakPointInfo.end();
			++it)
		{
			if (it->second.bReset)
			{
				BreakPoint::SetCCBreakPoint(m_hProcess,
					it->first,
					FALSE,
					&m_mapBreakPointInfo);
			}
		}

		/***************************************
		*	  Reset hardware breakpoints.
		****************************************/
		CONTEXT context = { CONTEXT_CONTROL };
		GetThreadContext(m_hThread, &context);
		PDR7 pDr7 = (PDR7)&context.Dr7;
		if (context.Dr6 & 1)
		{
			pDr7->L0 = 1;
			m_Dr6 &= ~1;
		}
		else if (context.Dr6 & 2)
		{
			pDr7->L0 = 1;
			m_Dr6 &= ~2;
		}
		else if (context.Dr6 & 4)
		{
			pDr7->L0 = 1;
			m_Dr6 &= ~4;
		}
		else if (context.Dr6 & 8)
		{
			pDr7->L0 = 1;
			m_Dr6 &= ~8;
		}

		CloseHandles();
	}
}



/**************************************
*			Layer 2
**************************************/
DWORD Debugger::DispatchEvent()
{
	DWORD dwContinueStatus = DBG_CONTINUE;
	switch (m_DbgEvent.dwDebugEventCode)
	{
	case EXCEPTION_DEBUG_EVENT:
		dwContinueStatus = OnExceptionEvent();
		break;
	case CREATE_THREAD_DEBUG_EVENT:
		printf("Create a thread\n");
		break;
	case CREATE_PROCESS_DEBUG_EVENT:
		printf("Create process successfully!\n");
		/*****************************************
		*	Set CC on OEP
		******************************************/
		BreakPoint::SetCCBreakPoint(m_hProcess,
			m_DbgEvent.u.CreateProcessInfo.lpStartAddress,
			FALSE, &m_mapBreakPointInfo);
		break;

	case EXIT_THREAD_DEBUG_EVENT:
		printf("Thread exits.\n");
		break;

	case EXIT_PROCESS_DEBUG_EVENT:
		printf("Process exits.\n");
		break;

	case LOAD_DLL_DEBUG_EVENT:
		printf("Load a dll.\n");
		break;

	case UNLOAD_DLL_DEBUG_EVENT:
		printf("Unload a dll.\n");
		break;

	case OUTPUT_DEBUG_STRING_EVENT:
		printf("OutputDebugString():\n\t%s\n",
			m_DbgEvent.u.DebugString.lpDebugStringData);
		break;

	default:
		break;
	}
	return dwContinueStatus;
}


/**************************************
*			Layer 3
**************************************/
DWORD Debugger::OnExceptionEvent()
{
	DWORD dwRet = DBG_CONTINUE;
	DWORD dwExceptionCode = m_DbgEvent.u.Exception.ExceptionRecord.ExceptionCode;
	PVOID pExceptionAddr = m_DbgEvent.u.Exception.ExceptionRecord.ExceptionAddress;
	printf("ExceptionCode(%08X): %p\n", dwExceptionCode, pExceptionAddr);

	

	switch (dwExceptionCode)
	{
	case EXCEPTION_ACCESS_VIOLATION:
	{
		/********************************************
		*	  If ExceptionAddr == MemBreakpoint addr, and RW type is matched, 
		*	remove it and break;
		*	  else, remove it, set TF breakpoint and return.
		*	In this way, it can stop not until the breakpoint.
		*********************************************/
		switch (m_DbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[0])
		{
		case 0:
			/*******************
			*	  Read exception
			********************/
			if (m_DbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]
				== (ULONG_PTR)(m_memBreakPointInfo.BpAttr.MemAttr.lpAddr))
			{
				BreakPoint::FixMemBreakPoint(m_hProcess, &m_memBreakPointInfo, FALSE);
			}
			break;
		case 1:
			/***********************************
			*	Write exception
			************************************/
			if (m_DbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]
				== (ULONG_PTR)(m_memBreakPointInfo.BpAttr.MemAttr.lpAddr))
			{
				BreakPoint::FixMemBreakPoint(m_hProcess, &m_memBreakPointInfo, FALSE);
			}
			break;
		case 8:
			/***********************
			*	Execution exception
			************************/
			if (pExceptionAddr == m_memBreakPointInfo.BpAttr.MemAttr.lpAddr)
			{
				/*******************************
				*	  Trigger the mem breakpoint.
				*	It can't be erased now.
				********************************/
				BreakPoint::FixMemBreakPoint(m_hProcess, &m_memBreakPointInfo, FALSE);
				break;
			}
			
		}
		if(m_memBreakPointInfo.bReset)
		{
			/************************************
			*	  Disable the mem breakpoint
			*	temporarily. Then Set TF.
			**********************************/
			BreakPoint::FixMemBreakPoint(m_hProcess, &m_memBreakPointInfo, TRUE);
			BreakPoint::SetTFBreakPoint(m_hThread, pExceptionAddr);
			return DBG_CONTINUE;
		}
		break;
	}
	case EXCEPTION_BREAKPOINT:
	{
		if (m_bFirstBreakPoint)
		{
			m_bFirstBreakPoint = FALSE;
			return DBG_CONTINUE;
		}

		BreakPoint::FixCCBreakPoint(m_hProcess, m_hThread, pExceptionAddr, &m_mapBreakPointInfo);
		
		/**********************************************
		*	  Check whether it's a condition breakpoint
		*	If not, return.
		***********************************************/
		std::map<LPVOID, CONDITIONBP>::iterator it = m_mapConditionBreakPointInfo.find(pExceptionAddr);
		if (it != m_mapConditionBreakPointInfo.end())
		{
			if (!BreakPoint::CheckConditionBreakPoint(m_hThread, &(it->second)))
			{
				return DBG_CONTINUE;
			}
		}

	}

	case EXCEPTION_SINGLE_STEP:
	{
		/***************************************
		*	Fix hardware breakpoints.
		****************************************/
		BreakPoint::FixHdBreakPoint(m_hThread, pExceptionAddr, &m_Dr6);

		/***************************************
		*	  Compare the address to ensure
		*	whether it's a memory breakpoint.
		****************************************/
		if (m_memBreakPointInfo.bReset)
		{
			BreakPoint::SetMemBreakPoint(m_hProcess,&m_memBreakPointInfo);
			return DBG_CONTINUE;
		}
		break;
	}
	default:
		return DBG_CONTINUE;
	}


	HANDLE hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo(hOutput, &csbi);

	SetConsoleTextAttribute(hOutput, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	showRegisters();
	SetConsoleTextAttribute(hOutput, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	Capstone::DisAsm(m_hProcess, pExceptionAddr, 10);
	SetConsoleTextAttribute(hOutput, FOREGROUND_RED | FOREGROUND_INTENSITY);
	showStack(3);
	SetConsoleTextAttribute(hOutput, csbi.wAttributes);

	help();
	
	GetCmd();
	return DBG_CONTINUE;
}

void Debugger::GetCmd()
{
	char input[0x100] = { 0 };
	void* pAddr = 0;
	int nLines = 0;
	BOOL bTmp = FALSE;
	char szReg[REG_NAME_LEN] = { 0 };
	DWORD dwVal = 0;
	while (1)
	{
		printf(">>");
		fflush(stdin);
		memset(input, 0, 0x100);
		pAddr = NULL;
		scanf_s("%s", input, 0x100);

		if (!strcmp("g", input))
		{
			break;
		}
		/***************************
		*	Disasm.
		****************************/
		else if (!strcmp("u", input))
		{
			scanf_s("%x %d", &pAddr, &nLines);
			Capstone::DisAsm(m_hProcess, (LPVOID)pAddr, nLines);
		}
		/***************************
		*	int 3
		***************************/
		else if (!strcmp("bp", input) || !strcmp("b", input))
		{
			scanf_s("%p", &pAddr);
			BreakPoint::SetCCBreakPoint(m_hProcess, (LPVOID)pAddr, FALSE, &m_mapBreakPointInfo);
		}
		/*********************************
		*	Condition breakpoint
		**********************************/
		else if (!strcmp("bcond", input))
		{
			memset(szReg, 0, REG_NAME_LEN);

			scanf_s("%p %s %d", &pAddr, szReg, REG_NAME_LEN, &dwVal);
			getchar();

			if (!BreakPoint::SetConditionBreakPoing(m_hProcess,
				pAddr,
				szReg,
				dwVal,
				&m_mapBreakPointInfo,
				&m_mapConditionBreakPointInfo))
			{
				printf("BreakPoint::SetConditionBreakPoing() error.\n");
			}

		}
		/*********************************
		*	Hardware breakpoint
		**********************************/
		else if (!strcmp("be", input) || !strcmp("bw", input) || !strcmp("ba", input))
		{
			scanf_s("%p", &pAddr);
			bTmp = FALSE;
			switch (input[1])
			{
			case 'e':
				bTmp = BreakPoint::SetHdBreakPoint(m_hThread, (LPVOID)pAddr, 0, 0, &m_Dr6);
				break;
			case 'w':
				bTmp = BreakPoint::SetHdBreakPoint(m_hThread, (LPVOID)pAddr, 1, 3, &m_Dr6);
				break;
			case 'a':
				bTmp = BreakPoint::SetHdBreakPoint(m_hThread, (LPVOID)pAddr, 3, 3, &m_Dr6);
				break;
			default:
				break;
			}
			if (!bTmp)
			{
				printf("SetHdBreakPoint() error.\n");
			}
		}
		/*********************************
		*	Memory breakpoint
		**********************************/
		else if (!strcmp("bme", input) || !strcmp("bmw", input) || !strcmp("bma", input))
		{
			if (m_memBreakPointInfo.BpAttr.MemAttr.dwOldProtect)
			{
				VirtualProtectEx(m_hProcess,
					m_memBreakPointInfo.BpAttr.MemAttr.lpAddr,
					1,
					m_memBreakPointInfo.BpAttr.MemAttr.dwOldProtect,
					&(m_memBreakPointInfo.BpAttr.MemAttr.dwNewProtect));
			}
			scanf_s("%p", &m_memBreakPointInfo.BpAttr.MemAttr.lpAddr);
			m_memBreakPointInfo.bReset = TRUE;
			switch (input[2])
			{
			case 'e':
				m_memBreakPointInfo.BpAttr.MemAttr.dwNewProtect = PAGE_READWRITE;
				BreakPoint::SetMemBreakPoint(m_hProcess, &m_memBreakPointInfo);
				break;
			case 'w':
				m_memBreakPointInfo.BpAttr.MemAttr.dwNewProtect = PAGE_EXECUTE_READ;
				BreakPoint::SetMemBreakPoint(m_hProcess, &m_memBreakPointInfo);
				break;
			case 'a':
				m_memBreakPointInfo.BpAttr.MemAttr.dwNewProtect = PAGE_NOACCESS;

				BreakPoint::SetMemBreakPoint(m_hProcess, &m_memBreakPointInfo);
				break;
			default:
				break;
			}
		}
		/*******************************
		*	API breakpoint
		********************************/
		else if (!strcmp("bapi", input))
		{
			char *pAPI = new char[0x100]();
			scanf_s("%s", pAPI, 0x100);
			getchar();

			BreakPoint::SetApiBreakPoint(m_hProcess, pAPI, &m_mapBreakPointInfo);
			if (pAPI)
			{
				delete[] pAPI;
				pAPI = NULL;
			}
		}


		/***************************
		*	Dump
		****************************/
		else if (!strcmp("dump", input))
		{
			Dump(m_hProcess);
		}
		/******************************
		*	Export table
		******************************/
		else if (!strcmp("exp", input))
		{
			showExp(m_hProcess);
		}
		/******************************
		*	Import table
		******************************/
		else if (!strcmp("imp", input))
		{
			showImp(m_hProcess);
		}
		else if (!strcmp("mod", input))
		{
			EnumModules96(m_hProcess);
		}
		/***************************
		*	Single step breakpoint
		***************************/
		else if (!strcmp("t", input))
		{
			BreakPoint::SetTFBreakPoint(m_hThread, (LPVOID)pAddr);
			break;
		}
		/***************************
		*	Step over breakpoint
		***************************/
		else if (!strcmp("p", input))
		{
			BreakPoint::SetStepOverBreakPoint(
				m_hProcess, 
				m_hThread, 
				&m_mapBreakPointInfo);
			break;
		}
		/***************************
		*	Show stack.
		****************************/
		else if (!strcmp("ds", input))
		{
			scanf_s("%d", &nLines);
			showStack(nLines);
		}
		/***************************
		*	Show memory.
		****************************/
		else if (!strcmp("dd", input))
		{
			scanf_s("%x %d", &pAddr, &nLines);
			showMem(pAddr, nLines);
		}
		/***************************
		*	Restart.
		****************************/
		else if (!strcmp("re", input))
		{
			m_bRestart = TRUE;
			break;
		}
		/***************************
		*	Show registers.
		****************************/
		else if (!strcmp("r", input) || !strcmp("register", input))
		{
			showRegisters();
		}
		/***************************
		*	Modify registers.
		****************************/
		else if (!strcmp("setreg", input))
		{
			memset(szReg, 0, REG_NAME_LEN);
			scanf_s("%s %d", szReg, REG_NAME_LEN, &dwVal);
			getchar();

			if (!setRegister(szReg, dwVal))
			{
				printf("setRegister() error.\n");
			}
		}
		/***************************
		*	Modify memory.
		****************************/
		else if (!strcmp("setmem", input))
		{
			memset(szReg, 0, REG_NAME_LEN);
			BYTE byte = 0;
			scanf_s("%p %d", &pAddr, &byte);
			getchar();

			if (!SetMem(pAddr, &byte))
			{
				printf("SetMem() error.\n");
			}
		}
		else if (!strcmp("q", input) || !strcmp("quit", input) || !strcmp("exit", input))
		{
			CloseHandles();
			exit(0);
		}
		else if (!strcmp("h", input) || !strcmp("help", input))
		{
			help();
		}
		else
		{
			printf("input error\n");
		}

	}
}

BOOL Debugger::Anti_AntiDebug(HANDLE hProcess)
{
	PROCESS_BASIC_INFORMATION stcProcInfo;

	SIZE_T nSize = 0;
	unsigned char cFlag = 1;
	DWORD dwFlag = 0;
	DWORD dwProcessHeapAddress = 0, dwTmpAddress = 0;
	DWORD dwOldProtect = 0;
	BOOL bRet = TRUE;



	/*********************************************************** 
	*	PEB operations
	***********************************************************/
	NtQueryInformationProcess(
		hProcess,
		ProcessBasicInformation,
		&stcProcInfo,
		sizeof(stcProcInfo),
		NULL);

	PPEB pPeb = stcProcInfo.PebBaseAddress;
	BYTE value = 0;
	
	//VirtualProtectEx(hProcess, stcProcInfo.PebBaseAddress + 2, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	if (!WriteProcessMemory(hProcess, (BYTE*)pPeb + 0x02, &value, 1, NULL))
	{
		printf("WriteProcessMemory(PEB.BeingDebugged) to unset BeingDebugged error.\n");
		bRet = FALSE;
	}
	//ReadProcessMemory(hProcess, stcProcInfo.PebBaseAddress + 2, &cFlag, 1, &nSize);
	//VirtualProtectEx(hProcess, stcProcInfo.PebBaseAddress + 2, 1, dwOldProtect, NULL);
	showMem(stcProcInfo.PebBaseAddress, 10);


	/*
	dwTmpAddress = (DWORD)(stcProcInfo.PebBaseAddress + 0x18);

	VirtualProtectEx(hProcess, (LPVOID)dwTmpAddress, 1, PAGE_READWRITE, &dwOldProtect);

	ReadProcessMemory(hProcess, (LPVOID)dwTmpAddress, &dwProcessHeapAddress, 4, &nSize);

	dwFlag = 2;
	dwTmpAddress = (DWORD)(stcProcInfo.PebBaseAddress + 0x0c);
	if (!WriteProcessMemory(hProcess, (LPVOID)dwTmpAddress, &dwFlag, 1, &nSize))
	{
		printf("WriteProcessMemory(ProcessHeap.Flags) to unset BeingDebugged error.\n");
		bRet = FALSE;
	}
	dwFlag = 0;
	dwTmpAddress = (DWORD)(stcProcInfo.PebBaseAddress + 0x10);
	if (!WriteProcessMemory(hProcess, (LPVOID)dwTmpAddress, &dwFlag, 1, &nSize))
	{
		printf("WriteProcessMemory(ProcessHeap.ForceFlags) to unset BeingDebugged error.\n");
		bRet = FALSE;
	}

	VirtualProtectEx(hProcess, (LPVOID)dwTmpAddress, 1, dwOldProtect, NULL);*/



	/*************************************
	*	Hook NtQueryInformationProcess()
	**************************************/
	char *pDllPath = new char[MAX_PATH]();
	LPVOID lpSzDllPath = NULL;
	_getcwd(pDllPath, MAX_PATH);
	PathRemoveFileSpecA(pDllPath);
	strcat_s(pDllPath, MAX_PATH, "..\\Debug\\hook.dll");

	lpSzDllPath = VirtualAllocEx(hProcess, NULL, strlen(pDllPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, lpSzDllPath, pDllPath, strlen(pDllPath) + 1, &nSize);
	HANDLE hThread = CreateRemoteThread(hProcess,
		NULL, NULL,
		(LPTHREAD_START_ROUTINE)LoadLibraryA,
		lpSzDllPath,
		0, 0);


	VirtualFreeEx(hProcess, lpSzDllPath, 0, MEM_FREE);
	CloseHandle(hThread);

	if (pDllPath)
	{
		delete[] pDllPath;
		pDllPath = NULL;
	}

	return bRet;
}

/****************************************
*	Show help info.
****************************************/
void Debugger::help()
{
	printf("-------------------------------------------commands-------------------------------------------\n");
	printf("[b/bp]: Set CC breakpoint.\n");
	printf("[be/bw/ba addr]: Set hardware execute/write/access breakpoint.\n");
	printf("[bme/bmw/bma addr]: Set memory execute/write/access breakpoint.\n");
	printf("[bcond addr Reg value]: Set memory execute/write/access breakpoint.\t [bapi]: Set API breakpoint.\n");
	printf("");
	printf("[ds nQWORD]: Show stack.\t	[dd addr nQWORD]: Show memory data.\n");

	printf("[dump]: Dump process memory.\t	[g]: Go until breakpoint or end.\n");

	printf("[mod]: Show module info.\t	[p]: Pass\t	[t] : Trace\t	[h/help]: Help info.\n");

	printf("[q/quit/exit]: Exit.\t	[re]: Restart.\n");
	printf("[r/register]: Show registers.\t	[u addr lines]: Disasm\n");
	printf("[setreg reg value]: Set register value.\t [setmem addr value]: Set memory value.\n");

}

/****************************************
*	  Set restarting flag, and restart
*	int run().
****************************************/
BOOL Debugger::restart()
{
	m_bFirstBreakPoint = TRUE;
	return m_bRestart;
}

/****************************************
*	 Show registers.
****************************************/
void Debugger::showRegisters()
{
	CONTEXT context = { CONTEXT_FULL };

	GetThreadContext(m_hThread, &context);
	printf("-------------------------------------------Registers-------------------------------------------\n");
	printf("EAX: %08x\t EBx: %08x\t ECX: %08x\t EDX: %08x\n",
		context.Eax, context.Ebx, context.Ecx, context.Edx);
	printf("ESI: %08x\t EDI: %08x\n",
		context.Esi, context.Edi);
	printf("ESP: %08x\t EBP: %08x, EIP: %08x\n",
		context.Esp, context.Ebp, context.Eip);
	printf("CS: %08x\t DS: %08x\t ES: %08x\t SS: %08x\n"
		"FS: %08x\t GS: %08x\n",
		context.SegCs, context.SegDs, context.SegEs, context.SegSs,
		context.SegFs, context.SegGs);
	printf("EFLAGS: %08x\n", context.EFlags);

}

/**********************************
*	  Set register value.
**********************************/
BOOL Debugger::setRegister(char * pReg, DWORD dwVal)
{
	char *regs[] = {
		"eax", "ebx", "ecx", "edx",
		"esi", "edi", "ebp", "esp",
		"eip", "flags"
	};
	CONTEXT context = { CONTEXT_CONTROL | CONTEXT_INTEGER };
	GetThreadContext(m_hThread, &context);
	DWORD *pRegs[] = {
		&context.Eax, &context.Ebx, &context.Ecx, &context.Edx,
		&context.Esi, &context.Edi, &context.Ebp, &context.Esp,
		&context.Eip, &context.EFlags,
	};
	for (size_t i = 0; i < 10; ++i)
	{
		if (!_stricmp(regs[i], pReg))
		{
			*(pRegs[i]) = dwVal;
			return SetThreadContext(m_hThread, &context);
		}
	}
	return FALSE;
}


/**********************************
*	  Show memory data.
*	  Parameter nDQWORD means 
*	nDQWORD * 16 bytes to display.
**********************************/
void Debugger::showMem(LPVOID lpAddr, size_t nDQWORD)
{
	PBYTE pBuf = new BYTE[nDQWORD * 16]();
	SIZE_T size = 0;
	char cTmp = 0;
	ReadProcessMemory(m_hProcess, lpAddr, pBuf, nDQWORD * 16, &size);
	for (size_t i = 0; i < nDQWORD; ++i)
	{
		printf("0x%08X\t", (DWORD)lpAddr + i * 16);
		for (size_t j = 0; j < 16; ++j)
		{
			printf("%02x ", pBuf[i * 16 + j]);
			if (j == 7)
			{
				printf(" ");
			}
		}
		printf("\t");
		for (size_t j = 0; j < 16; ++j)
		{
			(pBuf[i * 16 + j] == '\n') ?
				printf("\\n")
				: printf("%c", pBuf[i * 16 + j]);
		}
		printf("\n");
	}
	delete[] pBuf;
	pBuf = NULL;
}

/*********************************
*	Set memory value.
*********************************/
BOOL Debugger::SetMem(LPVOID lpAddr, PBYTE pByte)
{
	return WriteProcessMemory(m_hProcess, lpAddr, pByte, 1, NULL);
}

/****************************************
*	  Show stack data via esp
*	  Parameter nDQWORD means
*	nDQWORD * 16 bytes to display.
(****************************************/
void Debugger::showStack(size_t nDQWORD)
{
	CONTEXT context = { CONTEXT_CONTROL };
	GetThreadContext(m_hThread, &context);
	printf("-------------------------------------------Stack-------------------------------------------\n");
	showMem((LPVOID)context.Esp, nDQWORD);
}


/**************************************
*	Show module info.
***************************************/
void Debugger::EnumModules96(HANDLE hProcess)
{
	//HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID);
	HMODULE *hModules = new HMODULE[0x2000]();
	DWORD dwSize = 0, dwModuleCount = 0;
	MODULEINFO mod = { 0 };
	wchar_t *wpFileName = new wchar_t[0x1000]();

	if (!hProcess)
	{
		printf("Invalid hProcess.\n");
		return;
	}

	
	
	EnumProcessModulesEx(hProcess, hModules, sizeof(HMODULE) * 0x2000,
		&dwSize, LIST_MODULES_ALL);

	dwModuleCount = dwSize / sizeof(HMODULE);

	
	for(size_t i = 0; i < dwModuleCount ; ++i)
	{
		
		GetModuleFileNameEx(hProcess, hModules[i],
			wpFileName,0x1000);
		GetModuleInformation(hProcess, hModules[i],
			&mod, sizeof(MODULEINFO));
		wprintf(L"%ls\n", wpFileName);
		wprintf(L"	EP:			%p\n", (WCHAR*)mod.EntryPoint);
		wprintf(L"	BaseOfModule:	%p\n", (WCHAR*)mod.lpBaseOfDll);
		wprintf(L"	SizeOfImage:0x%x\n", mod.SizeOfImage);
	}

	delete[] hModules;
	delete wpFileName;
}


BOOL Debugger::Dump(HANDLE hProcess)
{
	HMODULE hModule = NULL;
	DWORD dwSize = 0;
	MODULEINFO mod = { 0 };
	PIMAGE_DOS_HEADER pDos = NULL;
	DWORD dwImageSize = 0;
	LPVOID lpBuf = NULL;


	EnumProcessModulesEx(hProcess, &hModule, sizeof(HMODULE), &dwSize, LIST_MODULES_ALL);
	GetModuleInformation(hProcess, hModule, &mod, sizeof(MODULEINFO));

	pDos = (PIMAGE_DOS_HEADER)mod.lpBaseOfDll;
	dwImageSize = mod.SizeOfImage;
	lpBuf = new BYTE[dwImageSize]();
	ReadProcessMemory(hProcess, pDos, lpBuf, dwImageSize, &dwImageSize);

	HANDLE hDumpFile = CreateFileA("dump",
		GENERIC_WRITE,
		FILE_SHARE_WRITE,
		NULL,
		CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (WriteFile(hDumpFile, lpBuf, dwImageSize, &dwSize, NULL))
	{
		printf("Dump to file(dump) successfully!\n");
	}
	if (lpBuf)
	{
		delete lpBuf;
		lpBuf = NULL;
	}
	return TRUE;
}

void Debugger::showExp(HANDLE hProcess)
{
	HMODULE *pHModules = new HMODULE[0x2000]();
	MODULEINFO mod = { 0 };
	DWORD dwModuleCount = 0;
	char *pFileName = new char[0x1000]();
	DWORD dwSize = 0;

	PIMAGE_DOS_HEADER pDos = NULL;
	DWORD dwImageSize = 0;
	
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_NT_HEADERS32 pNtHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOpt = NULL;
	PIMAGE_EXPORT_DIRECTORY pExp = NULL;

	EnumProcessModulesEx(hProcess, pHModules, sizeof(HMODULE) * 0x2000, &dwSize, LIST_MODULES_ALL);
	dwModuleCount = dwSize / sizeof(HMODULE);
	for (size_t i = 0; i < dwModuleCount; ++i)
	{
		GetModuleBaseNameA(hProcess, pHModules[i], pFileName, 0x1000);
		GetModuleInformation(hProcess, pHModules[i],
			&mod, sizeof(MODULEINFO));
		dwImageSize = (dwImageSize < mod.SizeOfImage) ? mod.SizeOfImage : dwImageSize;
	}
	
	pDos = (PIMAGE_DOS_HEADER)new BYTE[dwImageSize]();

	

	for (size_t i = 0; i < dwModuleCount; ++i)
	{
		memset(pDos, 0, dwImageSize);

		GetModuleBaseNameA(hProcess, pHModules[i], pFileName, 0x1000);
		GetModuleInformation(hProcess, pHModules[i],
			&mod, sizeof(MODULEINFO));
		ReadProcessMemory(hProcess, mod.lpBaseOfDll, pDos, mod.SizeOfImage, &dwSize);


		pNtHeader = (PIMAGE_NT_HEADERS32)(pDos->e_lfanew + (DWORD)pDos);
		pFileHeader = (PIMAGE_FILE_HEADER)&(pNtHeader->FileHeader);
		pOpt = (PIMAGE_OPTIONAL_HEADER32)&(pNtHeader->OptionalHeader);
		if (pFileHeader->Characteristics & IMAGE_FILE_DLL && pFileHeader->SizeOfOptionalHeader == 0x00E0)
		{
			pExp = (PIMAGE_EXPORT_DIRECTORY)(pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (DWORD)pDos);
			DWORD *pFuncAddr = (DWORD *)(pExp->AddressOfFunctions + (DWORD)pDos);
			DWORD *pFuncName = (DWORD *)(pExp->AddressOfNames + (DWORD)pDos);
			WORD *pFuncOrd = (WORD *)(pExp->AddressOfNameOrdinals + (DWORD)pDos);

			DWORD cNames = pExp->NumberOfNames;
			DWORD cFuncs = pExp->NumberOfFunctions;

			printf("Module name: %s\n", pFileName);
			printf("DLL name:	%s\n", pExp->Name + (DWORD)pDos);

			
			for (int nIndexAddr = 0; nIndexAddr < cFuncs; ++nIndexAddr)
			{
				for (int nIndexOrd = 0; nIndexOrd < cNames; ++nIndexOrd)
				{
					if (nIndexAddr == pFuncOrd[nIndexOrd])
					{
						printf("	Ordinal:	%d		FuncNanme:		%s		FuncAddr:	0x%p\n",
							nIndexOrd, pFuncName[nIndexOrd] + (DWORD)pDos, pFuncAddr[nIndexAddr]);
						break;
					}
					else if (nIndexOrd == cNames - 1)
					{
						printf("	FuncAddr:		0x%p\n", pFuncAddr[nIndexAddr]);
					}
				}
			}

		}
	}


}

void Debugger::showImp(HANDLE hProcess)
{
	HMODULE *pHModules = new HMODULE[0x2000]();
	MODULEINFO mod = { 0 };
	DWORD dwModuleCount = 0;
	char *pFileName = new char[0x1000]();
	DWORD dwSize = 0;

	PIMAGE_DOS_HEADER pDos = NULL;
	DWORD dwImageSize = 0;

	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_NT_HEADERS32 pNtHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOpt = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImp = NULL;
	PIMAGE_THUNK_DATA pINT = NULL, pIAT = NULL;

	EnumProcessModulesEx(hProcess, pHModules, sizeof(HMODULE) * 0x2000, &dwSize, LIST_MODULES_ALL);
	dwModuleCount = dwSize / sizeof(HMODULE);
	for (size_t i = 0; i < dwModuleCount; ++i)
	{
		GetModuleBaseNameA(hProcess, pHModules[i], pFileName, 0x1000);
		GetModuleInformation(hProcess, pHModules[i],
			&mod, sizeof(MODULEINFO));
		dwImageSize = (dwImageSize < mod.SizeOfImage) ? mod.SizeOfImage : dwImageSize;
	}

	pDos = (PIMAGE_DOS_HEADER)new BYTE[dwImageSize]();
	for (size_t i = 0; i < dwModuleCount; ++i)
	{
		memset(pDos, 0, dwImageSize);
		GetModuleBaseNameA(hProcess, pHModules[i], pFileName, 0x1000);
		GetModuleInformation(hProcess, pHModules[i],
			&mod, sizeof(MODULEINFO));
		ReadProcessMemory(hProcess, mod.lpBaseOfDll, pDos, mod.SizeOfImage, &dwSize);


		pNtHeader = (PIMAGE_NT_HEADERS32)(pDos->e_lfanew + (DWORD)pDos);
		pFileHeader = (PIMAGE_FILE_HEADER)&(pNtHeader->FileHeader);
		pOpt = (PIMAGE_OPTIONAL_HEADER32)&(pNtHeader->OptionalHeader);

		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
		{
			pImp = (PIMAGE_IMPORT_DESCRIPTOR)(pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (DWORD)pDos);
			printf("Module name: %s\n", pFileName);
			while (pImp->Name)
			{

				printf("dll name:	%s\n", (char*)(pImp->Name + (DWORD)pDos));

				printf("INT:\n");
				pINT = (PIMAGE_THUNK_DATA)(pImp->OriginalFirstThunk + (DWORD)pDos);
				while (pINT->u1.Ordinal)
				{
					if (pINT->u1.Ordinal
						& 1 << (8 * sizeof(pINT->u1.Ordinal) - 1))
					{
						printf("ordinal:	0x%x\n", pINT->u1.Ordinal & ~(1 << (8 * sizeof(pINT->u1.Ordinal) - 1)));
					}
					else
					{
						PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(pINT->u1.AddressOfData + (DWORD)pDos);
						printf("ordinal:	0x%x		func name:		%s\n", pName->Hint, pName->Name);
					}

					++pINT;
				}

				++pImp;
			}

		}
	}

}

void Debugger::loadPlug()
{
	HMODULE hMod = LoadLibraryA("..\\Debug\\plugin.dll");
	if (!hMod) return;

	typedef void (*PPlugFunc)();
	PPlugFunc pPlugFunc = (PPlugFunc)GetProcAddress(hMod, "DBG_hello");
	if (pPlugFunc) 
	{
		pPlugFunc();
	}

}
