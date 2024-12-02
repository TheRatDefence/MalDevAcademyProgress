# Local Shell Code Injector
This is a local shellcode injector that runs the **MsfVenom "Calc.exe"** payload after decrypting it. The shellcode is encrypted and decrypted using a simple XOR cypher.
___

On (Virus Total)[https://www.virustotal.com/gui/file/3a3ef38f2f866a7bd5d6ae3254b3506c1888480813a711291f1013f5639c02ce/detection] it scores 20/72. 

Compile using *Visual Studio* or *download* and **run at your own risk.**
___
### Detailed explanation:
1) XOR encrypted payload is decrypted after program starts.
2) Program allocates memory the same size as the payload using VirtualAlloc with the parameters: `"MEM COMMIT | MEM RESERVE", "PAGE_READWRITE"`.
3) Program writes the decrypted payload into the newly allocated memory using `memcpy()`.
4) Old memory used to store the payload is zeroed to make it harder for security solutions using `memset()`.
5) Program changes the page protection where the decrypted payload is stored from `"PAGE_READWRITE"` -> `"PAGE_EXECUTE_READWRITE"`.
6) A new thread is created using `CreateThread()` pointing to the decrypted payload.
7) Program waits using `getchar()` to give the thread time to execute.