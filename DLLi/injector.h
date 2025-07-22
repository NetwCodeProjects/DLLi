// injector.h
#pragma once
#include <windows.h>

namespace EXEC_METHOD {
    enum {
        CreateRemoteThreadExec = 1,
        ApcExec = 2
    };
}

bool InjectReflectiveDLL(HANDLE hProc, BYTE* dllBuf, SIZE_T dllSize, DWORD execMode);
DWORD FindSuitableThread(DWORD pid);
