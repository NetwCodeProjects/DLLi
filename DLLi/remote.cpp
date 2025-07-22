// remote.cpp
#include "remote.h"
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>

HANDLE OpenTargetProcess(const std::wstring& procName) {
    DWORD pid = FindProcessId(procName);
    if (!pid) {
        std::wcerr << L"[-] Could not find process: " << procName << std::endl;
        return NULL;
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        std::wcerr << L"[-] OpenProcess failed: " << GetLastError() << std::endl;
        return NULL;
    }

    std::wcout << L"[+] Attached to PID " << pid << std::endl;
    return hProc;
}

HANDLE SpawnSuspendedProcess(const std::wstring& exePath, PROCESS_INFORMATION& piOut) {
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    ZeroMemory(&piOut, sizeof(PROCESS_INFORMATION));

    std::wstring cmdline = exePath;

    BOOL success = CreateProcessW(
        NULL,
        &cmdline[0], // mutable buffer
        NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &si, &piOut
    );

    if (!success) {
        std::wcerr << L"[-] Failed to create suspended process: " << exePath << std::endl;
        return NULL;
    }

    std::wcout << L"[+] Spawned suspended process PID: " << piOut.dwProcessId << std::endl;
    return piOut.hProcess;
}

DWORD FindProcessId(const std::wstring& procName) {
    PROCESSENTRY32W pe32 = { sizeof(PROCESSENTRY32W) };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    DWORD pid = 0;
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, procName.c_str()) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return pid;
}
