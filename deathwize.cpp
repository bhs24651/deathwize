/*
========================================================
DeathWize – Chrome Extension Process Controller
Version 1.4
Developed by Jason Wu
========================================================

WHAT'S NEW:
  - Pressing [Esc] now exits the program and shows the summary report
    (used to be [Ctrl]+[C]).
  - Fixed: Program interruption no longer interferes with the run 
    duration feature.
  - Improved reliability and user experience for exiting and reporting.
  - Re-worded Confirmation Message since the old one was in dire need
    of replacement.
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
#include <csignal>
#include <conio.h>

#ifdef min
#undef min
#endif

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
int runDurationSec = -1; // -1 means run forever

// Global counters for process statistics
int totalFound = 0;
int totalTerminated = 0;
int totalFailed = 0;
int totalSkipped = 0;
bool interrupted = false;

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
        // New flag: --duration or -d <seconds>
        if ((arg == "--duration" || arg == "-d") && i + 1 < argc) {
            int value = atoi(argv[i + 1]);
            if (value > 0) {
                runDurationSec = value;
                std::cout << "[CONFIG] Set run duration to " << runDurationSec << " seconds." << std::endl;
            } else {
                std::cerr << "[WARNING] Invalid duration. Must be a positive integer. Running indefinitely." << std::endl;
            }
            i++;
        }
        // New flag: --help or -h
        if (arg == "--help" || arg == "-h") {
            std::cout << "USAGE: deathwize [-i/--interval <delay_ms>] [-d/--duration <seconds>] [-h/--help]\n";
            std::cout << "  -i/--interval <delay_ms>   Set the delay between scans (default: 1000 ms)\n";
            std::cout << "  -d/--duration <seconds>    Set the duration to run the program (default: run indefinitely)\n";
            std::cout << "  -h/--help                  Show this help message\n";
            exit(0);
        }
    }
}

void PrintSummaryReport() {
    if (interrupted) {
        std::cout << "[INFO] Program interrupted by user (Ctrl+C)." << std::endl;
    }
    std::cout << "\n==================== SUMMARY ====================\n";
    std::cout << "Total Chrome extension processes found: " << totalFound << std::endl;
    std::cout << "Total processes terminated: " << totalTerminated << std::endl;
    std::cout << "Total failures: " << totalFailed << std::endl;
    std::cout << "Total skipped due to backoff: " << totalSkipped << std::endl;
    std::cout <<  "================================================\n";
    std::cout << "If you enjoyed the program, why not spread the word about it?" << std::endl;
    std::cout << std::endl;
    system("pause");
}

void signalHandler(int signum) {
    interrupted = true;
    PrintSummaryReport();
    exit(signum);
}

int main(int argc, char* argv[]) {
    // parse flags, such as --interval and --duration before program starts
    ParseArguments(argc, argv);
    // output a brief description about this program
    std::string msg = 
                    "========================================================\n"
                    "DeathWize - Chrome Extension Process Controller\n"
                    "Version 1.4\n"
                    "Developed by Jason Wu\n"
                    "========================================================\n"
                    "\n"
                    "WHAT'S NEW: \n"
                    "  - Pressing [Esc] now exits the program and shows the summary report\n"
                    "    (used to be [Ctrl]+[C]).\n"
                    "  - Fixed: Program interruption no longer interferes with the run \n"
                    "    duration feature.\n"
                    "  - Improved reliability and user experience for exiting and reporting.\n"
                    "  - Re-worded Confirmation Message since the old one was in dire need\n"
                    "    of replacement.\n"
                    "\n"
                    "Before you continue:\n"
                    "\n"
                    "Please ensure you have opened the Chrome profile with the extensions\n"
                    "to be killed installed and save any unsaved work before proceeding. \n"
                    "\n"
                    "YOUR USAGE OF DEATHWIZE IS CONDUCTED AT YOUR OWN RISK. I DO NOT \n"
                    "ACCEPT ANY RESPONSIBILITY FOR ANY LIABILITY OR DAMAGES THAT ARISE\n"
                    "OUT OF THE USE OF THIS SOFTWARE. \n" 
                    "Full terms are outlined in the README.txt file. By replying Y in\n"
                    "the prompt below, I assume that you accept those terms.\n"
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
            "TIP: For best results, please use a VPN with this program. \n"
            "\n"
            "Press [Esc] to exit and show summary report.\n"
            "\n"
            "Debug statements will be shown below:";
        std::cout << msg << std::endl;

        auto start = std::chrono::steady_clock::now();
        while (true) {
            // Check for Esc key press
            if (_kbhit()) {
                int ch = _getch();
                if (ch == 27) { // 27 is ASCII for Esc
                    std::cout << "[INFO] Escape key pressed. Exiting and showing summary report." << std::endl;
                    break;
                }
            }
            // If runDurationSec is set, check if time is up
            if (runDurationSec > 0) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
                if (elapsed >= runDurationSec) {
                    std::cout << "[INFO] Run duration reached (" << runDurationSec << " seconds). Exiting." << std::endl;
                    break;
                }
            }
            std::vector<DWORD> chromePIDs = FindChromeExtensionProcesses();
            totalFound += chromePIDs.size();
            for (DWORD pid : chromePIDs) {
                // Check if process will be skipped due to backoff
                auto it = ProcessAllowlist.find(pid);
                if (it != ProcessAllowlist.end() && it->second.failCount > 0 && it->second.shouldBackoff()) {
                    totalSkipped++;
                    KillProcessByID(pid); // still prints skip message
                } else {
                    bool result = KillProcessByID(pid);
                    if (result) totalTerminated++;
                    else totalFailed++;
                }
            }
            Sleep(scanIntervalMs);
        }
        PrintSummaryReport();
    }
    return 0;
}

// If you want to compile from source:
// compile with: g++ deathwize.cpp -o deathwize.exe -static
// run with: ./deathwize [-i/--interval <delay_ms>] [-d/--duration <seconds>]

// I recommend that you save the run command in a batch file for easy access.
