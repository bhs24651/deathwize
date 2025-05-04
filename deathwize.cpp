/*
========================================================
DeathWize – Chrome Extension Process Controller
Version 1.2
Developed by Jason Wu
========================================================

WHAT'S NEW:
  - Delay between process scans is now customizable, thanks to the
    new "-i/--interval <delay_ms>" flag. Try it out for yourself!
  - Next-Gen Adaptive Allowlisting means Processes that repeatedly
    fail to terminate are now handled dynamically based on failure
    count, and allowlist now removes processes that have already 
    been successfully terminated
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
#include <chrono>
#include <iomanip>

#pragma comment(lib, "ntdll.lib")

// NT structures for internal access
typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

// Allowlist entry with backoff
struct AllowlistEntry {
    int failCount = 0;
    std::chrono::steady_clock::time_point lastAttempt;
    bool shouldBackoff() {
        using namespace std::chrono;
        int waitTime = std::min(failCount * 1000, 10000); // linear backoff up to 10s
        return duration_cast<milliseconds>(steady_clock::now() - lastAttempt).count() < waitTime;
    }
};

std::map<DWORD, AllowlistEntry> ProcessAllowlist;
int scanIntervalMs = 1000; // default interval

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

bool KillProcessByID(DWORD processID) {
    auto& entry = ProcessAllowlist[processID];
    if (entry.failCount > 0 && entry.shouldBackoff()) {
        std::cout << "Skipping PID " << processID << " due to backoff (failCount=" << entry.failCount << ")\n";
        return false;
    }
    entry.lastAttempt = std::chrono::steady_clock::now();

    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processID);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process with ID " << processID << ". Error: " << GetLastError() << std::endl;
        entry.failCount++;
        return false;
    }

    if (!TerminateProcess(hProcess, 0)) {
        DWORD err = GetLastError();
        std::cerr << "Failed to terminate process with ID " << processID << ". Error: " << err << std::endl;
        CloseHandle(hProcess);
        if (err == 5) {
            entry.failCount++;
        }
        return false;
    }

    CloseHandle(hProcess);
    // std::cout << "Terminated extension process with PID " << processID << "." << std::endl;
    ProcessAllowlist.erase(processID); // success, remove from list
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

void ParseArguments(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "--interval" || arg == "-i") && i + 1 < argc) {
            int value = atoi(argv[i + 1]);
            if (value >= 40 && value <= 2000) {
                scanIntervalMs = value;
                std::cout << "[CONFIG] Set scan interval to " << scanIntervalMs << " ms." << std::endl;
            } else {
                std::cerr << "[WARNING] Invalid interval. Must be between 40 and 2000 ms. Using default 1000 ms." << std::endl;
            }
            i++; // skip next
        }
    }
}

int main(int argc, char* argv[]) {
    // parse flags, such as --interval before program starts
    ParseArguments(argc, argv);
    // output a brief description about this program
    std::string msg = 
                    "========================================================\n"
                    "DeathWize - Chrome Extension Process Controller\n"
                    "Version 1.2\n"
                    "Developed by Jason Wu\n"
                    "========================================================\n"
                    "\n"
                    "WHAT'S NEW:\n"
                    "  - Delay between process scans is now customizable, thanks to the\n"
                    "    new \"-i/--interval <delay_ms>\" flag. Try it out for yourself! \n"
                    "  - Next-Gen Adaptive Allowlisting means Processes that repeatedly\n"
                    "    fail to terminate are now handled dynamically based on failure\n"
                    "    count, and allowlist now removes processes that have already  \n"
                    "    been successfully terminated\n"
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

            Sleep(scanIntervalMs);
        }
    }
    return 0;
}

// If you want to compile from source:
// compile with: g++ deathwize.cpp -o deathwize.exe -static
// run with: ./deathwize [-i/--interval <delay_ms>]

// I recommend that you save the run command in a batch file for easy access.
