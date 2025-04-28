/*
DeathWize v1.0.1
A LineWize Killer, developed by Jason Wu

WHAT'S NEW:
  - Bug Fixes for the original DeathWize, where the program refuses
    to run due to some files missing
*/

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <string>
#include <tchar.h>
#include <algorithm>

#pragma comment(lib, "ntdll.lib")

// NT structures for internal access
typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

bool ProcessHasExtensionFlag(DWORD pid) {
    bool isExtension = false;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;

    HMODULE hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
    if (!hNtdll) {
        CloseHandle(hProcess);
        return false;
    }

    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        CloseHandle(hProcess);
        return false;
    }

    PROCESS_BASIC_INFORMATION pbi;
    ZeroMemory(&pbi, sizeof(pbi));

    if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0) {
        CloseHandle(hProcess);
        return false;
    }

    PEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        CloseHandle(hProcess);
        return false;
    }

    RTL_USER_PROCESS_PARAMETERS params;
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(params), NULL)) {
        CloseHandle(hProcess);
        return false;
    }

    WCHAR commandLine[4096];
    ZeroMemory(commandLine, sizeof(commandLine));
    if (!ReadProcessMemory(hProcess, params.CommandLine.Buffer, &commandLine, params.CommandLine.Length, NULL)) {
        CloseHandle(hProcess);
        return false;
    }

    std::wstring cmd(commandLine);
    if (cmd.find(L"--extension-process") != std::wstring::npos) {
        isExtension = true;
    }

    CloseHandle(hProcess);
    return isExtension;
}

// Function to kill a process by its PID
bool KillProcessByID(DWORD processID) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processID);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process with ID " << processID << ". Error: " << GetLastError() << std::endl;
        return false;
    }

    if (!TerminateProcess(hProcess, 0)) {
        std::cerr << "Failed to terminate process with ID " << processID << ". Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(hProcess);
    return true;
}

std::vector<DWORD> FindChromeExtensionProcesses() {
    std::vector<DWORD> chromePIDs;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return chromePIDs;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_tcsicmp(pe.szExeFile, TEXT("chrome.exe")) == 0) {
                if (ProcessHasExtensionFlag(pe.th32ProcessID)) {
                    chromePIDs.push_back(pe.th32ProcessID);
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return chromePIDs;
}

int main() {
    // same message from the original version
    std::string msg = "\n"
                    "DeathWize v1.0.1\n"
                    "A LineWize Killer, developed by Jason Wu\n"
                    "\n"
                    "WHAT'S NEW: \n"
                    "  - Bug Fixes for the original DeathWize, where the program refuses\n"
                    "    to run due to some files missing\n"
                    "\n"
                    "Before you continue:\n"
                    "\n"
                    "Due to the limitations of the Task Manager and the nature of this\n"
                    "program, you will not be able to access other Chrome Extensions  \n"
                    "while DeathWize is running. Please read the terms in the README  \n"
                    "file, ensure you have opened the Chrome profile with the LineWize\n"
                    "extension installed and save any unsaved work before proceeding. \n"
                    "\n"
                    "Continue? (Y/n) ";
    std::cout << msg;
    char reply;
    std::cin >> reply;
    if (reply == 'Y' || reply == 'y') {

        msg = "\n"
            "All Chrome Extensions are now being killed. You have broken free \n"
            "from the constraints of web filtering and you should be able to  \n"
            "access any website while this window is open (can be minimized). \n"
            "Press [Ctrl]+[C] to exit.\n"
            "\n"
            "Debug statements will be shown below:";
        std::cout << msg << std::endl;
    }

    while (true) {
        std::vector<DWORD> chromePIDs = FindChromeExtensionProcesses();

        for (DWORD pid : chromePIDs) {
            KillProcessByID(pid);
        }
    }

    return 0;
}

// If you want to compile from source:
// compile with: g++ deathwize.cpp -o deathwize.exe -static
// run with: ./deathwize

// I recommend that you save the run command in a batch file for easy access.
