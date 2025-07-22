// remote.h
#pragma once
#include <windows.h>
#include <string>

HANDLE OpenTargetProcess(const std::wstring& procName);
HANDLE SpawnSuspendedProcess(const std::wstring& exePath, PROCESS_INFORMATION& piOut);
DWORD FindProcessId(const std::wstring& procName);
