// http.h
#pragma once
#include <string>
#include <vector>
#include <Windows.h>

bool DownloadRemotePayload(const std::string& url, std::vector<BYTE>& outBuffer);
