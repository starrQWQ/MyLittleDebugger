#pragma once
#include <windows.h>
#include <Psapi.h>
#pragma comment(lib,"psapi.lib")

#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

#include <TlHelp32.h>
#include <map>

#include "BreakPoint.h"



class Debugger
{
private:
	DEBUG_EVENT m_DbgEvent;

	HANDLE m_hProcess;
	HANDLE m_hThread;

	BOOL m_bRestart;

	char m_szTargetName[MAX_PATH];

	/********************************************************
	*	  Hardware breakpoins are stored in DrX registers.
	*	TF can fix itself.
	*	Only one mem breakpoint can be used.
	*	So we only need to store CC breakpoints.
	**********************************************************/
	std::map<LPVOID, BREAKPOINTINFO> m_mapBreakPointInfo;
	std::map<LPVOID, CONDITIONBP> m_mapConditionBreakPointInfo;


	/********************************************************
	*	Store one memory breakpoint info.
	**********************************************************/
	BREAKPOINTINFO m_memBreakPointInfo;

	/*****************************************
	*	  If m_Dr6.Bx(x in {0, 1, 2, 3}), then 
	*	the true Dr6 need to be reset.
	******************************************/
	DWORD m_Dr6;

	BOOL m_bFirstBreakPoint;
	BOOL m_bAntiAntiDebug;

public:

	Debugger();
	~Debugger();

	/************************************************************
	*	open() : Open a EXE file.
	*	attach(): attach a proces via PID.
	*************************************************************/
	void open(LPCSTR filePath);
	void attach(DWORD dwPID);

	/************************************************************
	*					Layer 1
	*	  OpenHandles() to get process and thread handle, and 
	*	CloseHandles() after ContinueDebugEvent().
	*************************************************************/
	void run();

	/************************************************************
	*	  Input h and then show the helping information.
	*************************************************************/
	void help();

	/****************************************
	*	  Set restarting flag, and restart
	*	int run().
	****************************************/
	BOOL restart();

	/****************************************
	*	 Set and Show registers.
	****************************************/
	void showRegisters();
	BOOL setRegister(char *pReg, DWORD dwVal);

	/****************************************
	*	  Show stack data via esp
	*	  Parameter nDQWORD means
	*	nDQWORD * 16 bytes to display.
	(****************************************/
	void showStack(size_t nDQWORD);

private:


	/**********************************
	*	  Set and Show memory data.
	*	  Parameter nDQWORD means
	*	nDQWORD * 16 bytes to display.
	**********************************/
	void showMem(LPVOID lpAddr, size_t nDQWORD);
	BOOL SetMem(LPVOID lpAddr, PBYTE pByte);


	void OpenHandles();
	void CloseHandles();

	/***************************************
	*			Layer  2
	****************************************/
	DWORD DispatchEvent();

	/***************************************
	*			Layer  3
	****************************************/
	DWORD OnExceptionEvent();
	void GetCmd();


	/*****************************************
	*	Anti-Anti Debug
	*****************************************/
	BOOL Anti_AntiDebug(HANDLE hProcess);

	/*******************************************
	*		PE operations
	*	Funcs below are based on EnumModules96().
	*	Dump(): Dump the memory to a file.
	*	showExp():	Show Export table.
	*	showImp():	Show Import table.
	*******************************************/
	void EnumModules96(HANDLE hProcess);
	BOOL Dump(HANDLE hProcess);
	void showExp(HANDLE hProcess);
	void showImp(HANDLE hProcess);

	/************************
	*	Plugin
	**********************/
	void loadPlug();

};
