/*
DeathWize v1.1
A Linewize Killer, developed by Jason Wu

WHAT'S NEW:
  - Allowlisting now prevents what could most likely be system and 
    other unkillable processes from being killed too many times
  - Added delay between process scans: Slightly weaker performance,
    but DeathWize is now 10x more Energy Efficient!
*/

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <string>
#include <tchar.h>
#include <algorithm>
#include <map>

#pragma comment(lib, "ntdll.lib")

// NT structures for internal access
typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

// initialize Process Allowlist variables (globally)
std::map<DWORD, int> ProcessKillFailCounter;
std::vector<DWORD> ProcessAllowlist; // unkillable processes (usually System ones) will end up here

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

    // check if the process is on the allowlist
    if (std::find(ProcessAllowlist.begin(), ProcessAllowlist.end(), processID) == ProcessAllowlist.end()) {
        if (!TerminateProcess(hProcess, 0)) {
            std::cerr << "Failed to terminate process with ID " << processID << ". Error: " << GetLastError() << std::endl;
            CloseHandle(hProcess);
            // if an attempt to kill the process fails, log it in the kill fail counter
            if (ProcessKillFailCounter.find(processID) != ProcessKillFailCounter.end() && GetLastError() == 5) {
                int a = ProcessKillFailCounter[processID];
                ProcessKillFailCounter.erase(processID);
                ProcessKillFailCounter.insert(std::make_pair(processID, a+1));
                // if 10 attempts to kill process reached, add it to the allowlist
                if (ProcessKillFailCounter[processID] >= 10) {
                    ProcessAllowlist.push_back(processID);
                    ProcessKillFailCounter.erase(processID);
                    std::cerr << "Process with ID " << processID << " added to Allowlist.";
                }
            } else if (GetLastError() == 5) {
                ProcessKillFailCounter.insert(std::make_pair(processID, 1));
            }
            return false;
        }
    } else {
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
                    "DeathWize v1.1\n"
                    "A Linewize Killer, developed by Jason Wu\n"
                    "\n"
                    "WHAT'S NEW:\n"
                    "  - Allowlisting now prevents what could most likely be system and\n"
                    "    other unkillable processes from being killed too many times   \n"
                    "  - Added delay between process scans: Slightly weaker performance,\n"
                    "    but DeathWize is now 10x more Energy Efficient!               \n"
                    "\n"
                    "Before you continue:\n"
                    "\n"
                    "Due to the limitations of the Task Manager and the nature of this\n"
                    "program, you will not be able to access other Chrome Extensions  \n"
                    "while DeathWize is running. Please read the terms in the README  \n"
                    "file, ensure you have opened the Chrome profile with the Linewize\n"
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
    

        while (true) {
            std::vector<DWORD> chromePIDs = FindChromeExtensionProcesses();

            for (DWORD pid : chromePIDs) {
                KillProcessByID(pid);
            }

            // Delay before next scan
            Sleep(1000);
        }
    }
    return 0;
}

// If you want to compile from source:
// compile with: g++ deathwize.cpp -o deathwize.exe -static
// run with: ./deathwize

// I recommend that you save the run command in a batch file for easy access.
