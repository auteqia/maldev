#include <Windows.h>
#include <stdio.h>


int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("missing argument - need the relative or absolute path\n");
		return -1;
	}

	printf("Injecting the DLL \"%s\" to the local process: %d \n", argv[1], GetCurrentProcessId());

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);



	if (LoadLibraryA(argv[1]) == NULL) {
		printf("LoadLibraryA failed -- error: %d \n", GetLastError());
		return -1;
	}
	printf("loaded\n");


	printf("Press <Enter> to quit");
	getchar();

	return 0;
}

