#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>

void PrintLoader(FLOAT fTime) {

	char LoadingSymbol[8] = { '|', '/', '-', '\\', '|', '/', '-', '\\' };
	int count = 0;
	int arraycount = 0;
	int iTime;
	int iTimePerCharacter = 60;
	int iTimePassed = 0;
	int percentage = 32;
	int bBuffer = 0;
	int Add = 0;

#define FLOAT_TO_INT(x) ((x)>=0?(int)((x)+0.5):(int)((x)-0.5))
	iTime = FLOAT_TO_INT(fTime);

	for (int i = iTime; i > 0; i = i - iTimePerCharacter) {
		Sleep((DWORD)(iTimePerCharacter));
		iTimePassed = iTimePassed + iTimePerCharacter;

		percentage = (int)(iTimePassed * 100 / iTime);

		if (arraycount != 7) {
			if (bBuffer == 1) {
				if (percentage < 10 && percentage > -1) {
					printf("\b\b\b\b\b\b\b [%d%%]  \b%c", percentage, LoadingSymbol[arraycount]);
				}
				else if (percentage < 100 && percentage > 9) {
					printf("\b\b\b\b\b\b\b\b [%d%%]  \b%c", percentage, LoadingSymbol[arraycount]);
				}
				else if (percentage < 1000 && percentage > 99) {
					printf("\b\b\b\b\b\b\b\b\b [%d%%]  \b%c", percentage, LoadingSymbol[arraycount]);
				}
			}
			else if (bBuffer == 0) {
				if (percentage < 10 && percentage > -1) {
					printf("       ");
					printf("\b\b\b\b\b\b\b [%d%%]  \b%c", percentage, LoadingSymbol[arraycount]);
					bBuffer = 1;
				}
				else if (percentage < 100 && percentage > 9) {
					printf("        ");
					printf("\b\b\b\b\b\b\b\b [%d%%]  \b%c", percentage, LoadingSymbol[arraycount]);
					bBuffer = 1;
				}
				else if (percentage < 1000 && percentage > 99) {
					printf("         ");
					printf("\b\b\b\b\b\b\b\b\b [%d%%]  \b%c", percentage, LoadingSymbol[arraycount]);
					bBuffer = 1;
				}
			}
		}
		else if (arraycount == 7) {
			count++;
			if (bBuffer == 1) {
				if (percentage < 10 && percentage > -1) {
					printf("\b\b\b\b\b\b\b [%d%%]  \b%c", percentage, LoadingSymbol[arraycount]);
				}
				else if (percentage < 100 && percentage > 9) {
					printf("\b\b\b\b\b\b\b\b [%d%%]  \b%c", percentage, LoadingSymbol[arraycount]);
				}
				else if (percentage < 1000 && percentage > 99) {
					printf("\b\b\b\b\b\b\b\b\b [%d%%]  \b%c", percentage, LoadingSymbol[arraycount]);
				}
			}
			else if (bBuffer == 0) {
				if (percentage < 10 && percentage > -1) {
					printf("       ");
					printf("\b\b\b\b\b\b\b [%d%%]  \b%c", percentage, LoadingSymbol[arraycount]);
					bBuffer = 1;
				}
				else if (percentage < 100 && percentage > 9) {
					printf("        ");
					printf("\b\b\b\b\b\b\b\b [%d%%]  \b%c", percentage, LoadingSymbol[arraycount]);
					bBuffer = 1;
				}
				else if (percentage < 1000 && percentage > 99) {
					printf("         ");
					printf("\b\b\b\b\b\b\b\b\b [%d%%]  \b%c", percentage, LoadingSymbol[arraycount]);
					bBuffer = 1;
				}
			}
			for (int j = count; j > 0; j--) {
				printf(".");
			}
			for (int j = count; j > 0; j--) {
				printf("\b");
			}
			if (Add == 1) {
				arraycount = 0;
				Add = 0;
			}
			else {
				Add = 1;
			}
		}

		if (Add == 1) {
			arraycount++;
		}
		else {
			Add = 1;
		}
	}

	int k = 100;
	for (int j = count; j > 0; j--) {
		printf(" ");
	}
	while (k > 0) {
		printf("\b \b");
		k--;
	}
}

BOOL InjectDllToRemoteProcess(HANDLE hProcessHandle, LPWSTR dllName) {									//Function that Injects the DLL
																												//Declaring variables
	BOOL	bSTATE					=	TRUE;

	PVOID	pLoadLibraryW			=	NULL;
	PVOID	pAddress				=	NULL;

	DWORD	dwSizeToWrite			=	lstrlenW(dllName) * sizeof(WCHAR);

	SIZE_T	lpNumberOfBytesWritten	=	NULL;

	HANDLE	hThread					=	NULL;
	int		i						=	0;

	

	pLoadLibraryW = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");							//pLoadLibraryW = The address of the LoadLibrary that is loaded by the kernel
	if (pLoadLibraryW == NULL) {
		printf("Getting process address failed. There was an error: %d\n", GetLastError());
		bSTATE = FALSE;  goto _EndOfFunction;
	}

	printf("\n|[X]Finding LoadLibrary function in kernel32.dll:  ");
	PrintLoader(rand() % 3000 + 1);
	printf("\r|[$]Found LoadLibrary function in kernel32.dll: 0x%p\n", pLoadLibraryW);

	pAddress = VirtualAllocEx(hProcessHandle, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);	//Allocating memory within the process to store the dllname
	if (pAddress == NULL) {
		printf("Allocating memory failed. There was an error: 0x%d\n", GetLastError());
		bSTATE = FALSE;  goto _EndOfFunction;
	}

	printf("|[X]Allocating memory within:  ");
	PrintLoader(rand() % 1500 + 1);
	printf("\r|[X]Allocating memory within: 0x%p  |  at:  ", hProcessHandle);
	PrintLoader(rand() % 1500 + 1);
	printf("\r|[$]Allocated memory within: 0x%p  |  at: 0x%p\n", hProcessHandle, pAddress);

	if (!WriteProcessMemory(hProcessHandle, pAddress, dllName, dwSizeToWrite, &lpNumberOfBytesWritten)) {		//Writing the dll name into the allocated memory
		printf("Write process memory failed. There was an error: %d\n", GetLastError());
		bSTATE = FALSE;  goto _EndOfFunction;
	}


	wprintf(L"|[X] Writing  ");
	PrintLoader(rand() % 750 + 1);
	wprintf(L"|[X]Writing %s into ", dllName);
	PrintLoader(rand() % 750 + 1);
	wprintf(L"|[X]Writing %s into 0x%p of process ", dllName, pAddress);
	PrintLoader(rand() % 750 + 1);
	wprintf(L"|[$]Writing %s into 0x%p of process 0x%p  ", dllName, pAddress, hProcessHandle);
	PrintLoader(rand() % 5000 + 1);

	printf("|[i] Press enter to create a remote thread and run the injected dll...");
	getchar();

	hThread = CreateRemoteThread(hProcessHandle, NULL, NULL, pLoadLibraryW, pAddress, NULL, NULL);				//Creating the remote thread that executes the dll
	PrintLoader(rand() % 4000 + 1);

	wprintf(L"|--------------------\n\n     \ /------| DLL successfully injected |------\/\n");
	PrintLoader(rand() % 2000 + 1);
	printf("    [Hdl] Handle to Process ===> 0x%p\n", hProcessHandle);
	wprintf(L"    [DLL] DLL injected      ===> %s\n\n", dllName);
	

_EndOfFunction:																									//Closes the open handle and returns the bSTATE value
	if (hThread)
		CloseHandle(hThread);
	return bSTATE;
	getchar();
}

BOOL GetRemoteProcess(IN LPWSTR szProcessName, OUT DWORD* dwProcessID, OUT HANDLE* hProcessHandle) {	//The function that finds and provides the handle and ID of the process

	HANDLE hSnapHandle	= NULL;																					//Declaring Handle

	PROCESSENTRY32 Proc = {																						//Initalising PROCESSENTRY32 struct
		.dwSize			= sizeof(PROCESSENTRY32)
	};

	hSnapHandle	= CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);											//Taking snapshot off processes runing

	if (hSnapHandle == INVALID_HANDLE_VALUE) {																	//Checking there are no errors with the handle
		printf("There was an error with the handle: %d\n", GetLastError());
		goto _EndOfFunction;
	}
	
	if (!Process32First(hSnapHandle, &Proc)) {
		printf("There was an error the first process: %d\n", GetLastError());
		goto _EndOfFunction;
	}

	printf("\n|[X]Taking Snapshot:  ");
	PrintLoader(rand() % 2000 + 1);
	printf("\r|[$]Took Snapshot at: %p\n", hSnapHandle);

	printf("|[X]Looking for specified process:\n|   #################\n");

	do {																										//Do while loop that scans all processes in snapshot
		
		WCHAR LowerCase[MAX_PATH * 2];																			//The LowerCase WChar array that'll hold Proc.szExeFile

		if (Proc.szExeFile) {
			DWORD i			= 0;
			DWORD dwStrSize = lstrlenW(Proc.szExeFile);

			RtlSecureZeroMemory(LowerCase, sizeof(LowerCase));													//Zeroing memory in LowerCase's block

			if (dwStrSize < MAX_PATH * 2) {
				for (; i < dwStrSize; i++) {																	//Setting every character in Proc.szExeFile to the lowercase equivilent in LowerCase
					LowerCase[i] = (WCHAR)tolower(Proc.szExeFile[i]);
				}
				LowerCase[i++] = '\0';
			}
			if (wcscmp(LowerCase, szProcessName) == 0) {														//Comparing the process names to the name inputted
																												//Setting the values of the function's OUT parameters 
				*dwProcessID	= Proc.th32ProcessID;															
				*hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *dwProcessID);
				
				printf("\r");
				for (i = 0; i < (dwStrSize * 2 + 20); i++) {
					printf(" ");
				}
				Sleep(5);
				printf("\r|[Found a match] >>> |");
				wprintf(L"%s == %s", LowerCase, szProcessName);
				printf("| <<<");
				printf("\n|   #################\n\r");
				
				Sleep(5);
				for (i = 0; i < (dwStrSize * 2 + 20); i++) {
					printf(" ");
				}
				printf("\r");
			}
			else {
				printf("\r|   ##| ");																			//Prints the comparison and overwrites itself
				wprintf(L"%s != %s", LowerCase, szProcessName);
				printf(" |##\r");
				Sleep(5);
				for (i = 0; i < (dwStrSize * 2 + 20); i++) {
					printf(" ");
				}
				printf("\r");
			}
		}
	} while (Process32Next(hSnapHandle, &Proc));

	wprintf("\r\n|   #################\n");

	_EndOfFunction:																								//Returns TRUE or FALSE for the function and closes handle
		if (hSnapHandle != NULL) {
			CloseHandle(hSnapHandle);
		}

		if (*dwProcessID == NULL || *hProcessHandle == NULL) {
			return FALSE;
		}
		else {
			return TRUE;
		}
		getchar();
}

int main() {
	//Initalising variables
	DWORD	dwProcessID			= NULL;

	HANDLE	hProcessHandle		= NULL;

	
	int		i					= 0;

	wchar_t userInputProcess[MAX_PATH];
	wchar_t userInputDll[MAX_PATH];


	srand(time(NULL));


	

	printf(">>>--------------| Process finder |--------------<<<\n");


	printf("---[i] Enter the name of the process you'd like to inject: \n>>>");
	_getws_s(userInputProcess, sizeof(userInputProcess) / sizeof(wchar_t));

	PrintLoader(rand() % 2000 + 1);

	wprintf(L"\n---[i] Searching for the '%s' process  ", userInputProcess);
	printf("\n\n|--------------------");

	
	if (GetRemoteProcess(&userInputProcess, &dwProcessID, &hProcessHandle)) {
	  wprintf(L"|--------------------\n\n     \ /------| %s |------\/\n", userInputProcess);

		PrintLoader(rand() % 2000 + 1);
		printf("    [PID] Process ID        ===> %d\n", dwProcessID);
		printf("    [Hdl] Handle to Process ===> 0x%p\n\n", hProcessHandle);

		printf(">>>--------------| Process Injector |--------------<<<\n");
		printf("---[i] Enter the path to the DLL you'd like to be injected: \n>>>  ");
		_getws_s(userInputDll, sizeof(userInputDll) / sizeof(wchar_t));

		PrintLoader(rand() % 2000 + 1);

		wprintf(L"\n---[i] Injecting the '%s' DLL into '%s' process... \n\n|--------------------", userInputDll, userInputProcess);

		if (InjectDllToRemoteProcess(hProcessHandle, &userInputDll)) {
			printf("\n   ...Press enter to exit...");
			getchar();
		}
		else {
			printf("There was an error: %d", GetLastError());
		}

		
	}
	else {
		printf("There was an error: %d\n", GetLastError());
		return -1;
	}
	

	return 0;
}