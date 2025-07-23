#include <windows.h>

extern "C" __declspec(dllexport)
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        MessageBoxA(NULL, "DLL Injected Successfully!", "RDI Payload", MB_OK | MB_ICONINFORMATION);
    }
    return TRUE;
}

// Stub ReflectiveLoader just returns DllMain address (for testing)
extern "C" __declspec(dllexport)
void* ReflectiveLoader() {
    return (void*)DllMain;
}
