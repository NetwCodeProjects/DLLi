// crypto.h
#pragma once
#include <Windows.h>     // <-- Required for BYTE, DWORD, etc.
#include <vector>
#include <string>

bool XORDecode(std::vector<BYTE>& data, const std::string& key);
bool AESDecrypt(std::vector<BYTE>& data, const std::string& key, const std::string& iv);
