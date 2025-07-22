// loader.cpp
#include "loader.h"
#include <windows.h>
#include <winnt.h>
#include <string>

DWORD GetReflectiveLoaderOffset(BYTE* dllBuffer) {
    if (!dllBuffer) return 0;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dllBuffer;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dllBuffer + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    IMAGE_DATA_DIRECTORY exportDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exportDir.VirtualAddress || !exportDir.Size)
        return 0;

    IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)(dllBuffer + exportDir.VirtualAddress);
    DWORD* nameRVAs = (DWORD*)(dllBuffer + exports->AddressOfNames);
    WORD* ordinals = (WORD*)(dllBuffer + exports->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)(dllBuffer + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* funcName = (char*)(dllBuffer + nameRVAs[i]);
        if (strcmp(funcName, "ReflectiveLoader") == 0) {
            WORD ordinal = ordinals[i];
            DWORD funcRVA = functions[ordinal];
            return funcRVA;
        }
    }

    return 0; // not found
}
