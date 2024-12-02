#include <stdio.h>
#include <windows.h>
#include <string.h>


int WriteMemWithMalloc(char* cMallocString){
	int iMallocStrlen = strlen(cMallocString);
	char sMallocString[50];
	char sMemory[100];
	int i;

	if (iMallocStrlen != 0) {
		PVOID pMallocAddress = malloc(strlen(cMallocString));

		char* cMemory = pMallocAddress;

		printf("[i] Allocating memory using Malloc\n  | Length: %i\n  | Location: %p\n", iMallocStrlen, pMallocAddress);

		printf("[i] Reading 30 bytes from '%p' -> <|", pMallocAddress);				//Printing memory before writing
		for (i = 0; i < 30; i++) {	printf("%c", cMemory[i]);}
		printf("|> \n");


		snprintf(sMallocString, strlen(cMallocString) + 1, "%s\n", cMallocString);	//Printing string from char pointer
		printf("[i] Writing: '%s' -> %p\n", sMallocString, pMallocAddress);

		memcpy(pMallocAddress, cMallocString, strlen(cMallocString));
		snprintf(sMemory, strlen(sMemory) + 1, "%s\n", pMallocAddress);

		printf("[i] Reading 30 bytes from '%p' -> <|", pMallocAddress);				//Printing memory after writing
		for (i = 0; i < 30; i++) { printf("%c", cMemory[i]); }
		printf("|> \n");
		
		printf("[i] Freeing memory at %p\n", pMallocAddress);
		free(pMallocAddress);														//Freeing up memory

		getchar();

		return 0;
	}
}
	
int main() {
	printf("-----Writing Input To Memory-----\n  | What would you like to write to memory (1 word)? ");

	char sInput[100];
	scanf_s("%s", &sInput, 100);
	printf("[i] You inputted: '%s '\n", sInput);
	
	char* cMallocString = { sInput };

	if (WriteMemWithMalloc(cMallocString) == 0) {
		printf(">>>Press enter to close<<<\n");
		getchar();
		return 0;
	}
	
	
}