// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"


VOID MessageBoxDLL() {
    MessageBoxA(NULL, "i told you i do", "i <3 DFIR-ORC", MB_OK | MB_ICONINFORMATION);
}


// MAIN GOAL: messagebox whenever the DLL is loaded
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {

    switch (dwReason) {
    case DLL_PROCESS_ATTACH: {
        MessageBoxDLL();
        break;
    };
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}