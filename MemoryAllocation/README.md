### Memory Allocation
This is my first very basic C project that just uses a custom `int WriteMemWithMalloc(char* cMallocString)` function to allocate memory, write to it and read from it. 
1. First the function takes in a char pointer array from the user. 
2. Allocates memory using `malloc()`.
3. Reads off what's at that location (malloc doesn't zero the allocated memory). 
4. Uses `memcpy()` to write to the memory.
5. Reads off the allocated memory (which now contains the user inputted string).
6. Finally uses `free()` to free the allocated memory.