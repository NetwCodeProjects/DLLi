// crypto.cpp
#include "crypto.h"
#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <iostream>

#pragma comment(lib, "advapi32.lib")

bool XORDecode(std::vector<BYTE>& data, const std::string& key) {
    if (key.empty()) return false;
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= key[i % key.length()];
    }
    return true;
}

bool AESDecrypt(std::vector<BYTE>& data, const std::string& keyStr, const std::string& ivStr) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "[-] CryptAcquireContext failed.\n";
        return false;
    }

    // Hash the key
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "[-] CryptCreateHash failed.\n";
        CryptReleaseContext(hProv, 0);
        return false;
    }

    CryptHashData(hHash, (BYTE*)keyStr.c_str(), keyStr.size(), 0);
    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) {
        std::cerr << "[-] CryptDeriveKey failed.\n";
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    // Set the IV
    if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)ivStr.c_str(), 0)) {
        std::cerr << "[-] CryptSetKeyParam failed.\n";
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    DWORD len = (DWORD)data.size();
    if (!CryptDecrypt(hKey, 0, TRUE, 0, data.data(), &len)) {
        std::cerr << "[-] CryptDecrypt failed.\n";
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    // Resize to actual length (some padding may be removed)
    data.resize(len);

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return true;
}
