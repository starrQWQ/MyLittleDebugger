#pragma once
#include <windows.h>
#include <map>
#include "Capstone.h"




typedef struct _DR7 {
	unsigned L0 : 1; unsigned G0 : 1;
	unsigned L1 : 1; unsigned G1 : 1;
	unsigned L2 : 1; unsigned G2 : 1;
	unsigned L3 : 1; unsigned G3 : 1;
	unsigned LE : 1; unsigned GE : 1;

	unsigned : 6;
	unsigned RW0 : 1; unsigned LEN0 : 1;
	unsigned RW1 : 1; unsigned LEN1 : 1;
	unsigned RW2 : 1; unsigned LEN2 : 1;
	unsigned RW3 : 1; unsigned LEN3 : 1;

}DR7, *PDR7;

/*******************************************
*	  CcOldOpcode is used to recover 
*	CC breakpoint.
*	  If it's a memory breakpoint,
*	the struct is used and active 
*	should be set.
*******************************************/
typedef struct _BREAKPOINTINFO
{
	BOOL bReset;
	union {
		struct {
			BOOL bStepOver;
			BYTE CcOldOpcode;
		}CC;
		struct {
			LPVOID lpAddr;
			DWORD dwNewProtect;
			DWORD dwOldProtect;
		}MemAttr;
	}BpAttr;
}BREAKPOINTINFO, *PBREAKPOINTINFO;

#define REG_NAME_LEN	10
typedef struct _CONDITIONBP {
	char szReg[REG_NAME_LEN];
	int nVal;
}CONDITIONBP, *PCONDITIONBP;

class BreakPoint
{
	//private:
	//	static std::vector<BREAKPOINTINFO> vBreakPointInfo;
	//	static std::map<LPVOID, BREAKPOINTINFO> mBreakPointInfo;

public:

	/*********************************************
	*	Set and Fix CC breakpoint.
	*********************************************/
	static void SetCCBreakPoint(
		HANDLE hProcess, 
		LPVOID lpAddr, 
		BOOL bStepOver,
		std::map<LPVOID, BREAKPOINTINFO> *pMapBreakPointInfo);
	static void FixCCBreakPoint(
		HANDLE hProcess, 
		HANDLE hThread, 
		LPVOID addr, 
		std::map<LPVOID, BREAKPOINTINFO> *pMapBreakPointInfo);

	/*********************************************
	*	Set and check condition breakpoint.
	*********************************************/
	static BOOL SetConditionBreakPoing(
		HANDLE hProcess, 
		LPVOID lpAddr, 
		char *pReg,
		int nVal,
		std::map<LPVOID, BREAKPOINTINFO> *pMapBreakPointInfo,
		std::map<LPVOID, CONDITIONBP> *pMapConditionBreakPointInfo);
	static BOOL CheckConditionBreakPoint(HANDLE hThread, CONDITIONBP *pConditionBP);

	/*********************************************
	*	TF single step breakpoint.
	*********************************************/
	static void SetTFBreakPoint(HANDLE hThread, LPVOID lpAddr);

	/*********************************************
	*	Step over breakpoint.
	*********************************************/
	static void SetStepOverBreakPoint(
		HANDLE hProcess, 
		HANDLE hThread, 
		std::map<LPVOID, BREAKPOINTINFO> *pMapBreakPointInfo);

	/*********************************************
	*	Set and Fix hardware breakpoint.
	*********************************************/
	static BOOL SetHdBreakPoint(
		HANDLE hThread, 
		LPVOID lpAddr, 
		BYTE type, 
		int len,
		DWORD *pDr6);
	static void FixHdBreakPoint(
		HANDLE hThread, 
		LPVOID addr,
		DWORD *pDr6);

	/*********************************************
	*	  Set memory breakpoint.
	*	  The address and protect attr is in the 
	*	struct.
	*********************************************/
	static void SetMemBreakPoint(
		HANDLE hProcess, 
		BREAKPOINTINFO *pMemBreakPointInfo);

	/*******************************************************
	*	  Fix memory breakpoint.
	*	  If bActive is TRUE, it means 
	*	a EXCEPTION_ACCESS_VIOLATION is encountered, but
	*	it's not the breakpoint address.
	*	  Else, the memory breakpoint is triggered, and 
	*	it should be disabled.
	*********************************************************/
	static void FixMemBreakPoint(
		HANDLE hProcess, 
		BREAKPOINTINFO *pMemBreakPointInfo,
		BOOL bActive);

	static void SetApiBreakPoint(
		HANDLE hProcess,
		char *pAPI,
		std::map<LPVOID, BREAKPOINTINFO> *pMapBreakPointInfo);
};