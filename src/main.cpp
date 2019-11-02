#include <stdio.h>
#include "Debugger.h"

int main(int argc, char *argv[])
{
	Debugger debugger;
	int nOpt = 0;
	DWORD dwPID = 0, dwSize = MAX_PATH;
	char *pFilePath = new char[MAX_PATH]();


	/**********************
	*	Command line start
	***********************/
	if (argc == 2)
	{
		DWORD dwPID = 0;

		/*******************
		*	Attach process
		******************/
		if (dwPID = atoi(argv[1]))
		{
			QueryFullProcessImageNameA(OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID), 0, pFilePath, &dwSize);
			debugger.attach(dwPID);
			while (1)
			{
				debugger.open(pFilePath);
				getchar();
				debugger.run();
				if (!debugger.restart()) break;
			}
		}
		/*******************
		*	Open exe
		******************/
		else
		{
			while (1)
			{
				debugger.open(argv[1]);
				getchar();
				debugger.run();
				if (!debugger.restart()) break;
			}
		}
	}
	/*****************************
	*	Input target path or PID
	*******************************/
	else
	{
		while (1)
		{
			printf("1. Open exe\n");
			printf("2. Attach process\n");

			printf("Your choice:");
			scanf_s("%d", &nOpt);
			getchar();
			/*******************
			*	Open exe
			******************/
			if (nOpt == 1)
			{
				printf("EXE path:");
				scanf_s("%s", pFilePath, MAX_PATH);
				getchar();
				
				while (1)
				{
					debugger.open(pFilePath);
					getchar();
					debugger.run();
					if (!debugger.restart()) break;
				}

				break;
			}
			/*******************
			*	Attach process
			******************/
			else if (nOpt == 2)
			{
				printf("PID:");
				scanf_s("%d", &dwPID);
				getchar();
				QueryFullProcessImageNameA(OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID), 0, pFilePath, &dwSize);
				debugger.attach(dwPID);
				while (1)
				{
					debugger.open(pFilePath);
					getchar();
					debugger.run();
					if (!debugger.restart()) break;
				}
				break;
			}
			else
			{
				continue;
			}
		}
	}

	/*while (1)
	{
		debugger.open("demo.exe");
		getchar();
		debugger.run();
		if (!debugger.restart()) break;
	}*/

	if (pFilePath)
	{
		delete[] pFilePath;
		pFilePath = NULL;
	}

	return 0;
}