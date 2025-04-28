/*
DeathWize v1.0
A LineWize Killer, developed by Jason Wu
*/

#include <windows.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

#pragma comment(lib, "wbemuuid.lib")

// global vector to store extension process PIDs
std::vector<int> extension_PIDs;

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

    // std::cout << "Process with ID " << processID << " terminated." << std::endl;
    CloseHandle(hProcess);
    return true;
}

int processCheck() {
    HRESULT hres;

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize COM library. Error code = 0x"
                  << std::hex << hres << std::endl;
        return 1;
    }

    // Set general COM security levels
    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
    );

    if (FAILED(hres)) {
        std::cerr << "Failed to initialize security. Error code = 0x"
                  << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;
    }

    // Obtain the initial locator to WMI 
    IWbemLocator *pLoc = NULL;

    hres = CoCreateInstance(
        CLSID_WbemLocator,             
        0, 
        CLSCTX_INPROC_SERVER, 
        IID_IWbemLocator, (LPVOID *)&pLoc);

    if (FAILED(hres)) {
        std::cerr << "Failed to create IWbemLocator object. Error code = 0x"
                  << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;
    }

    IWbemServices *pSvc = NULL;

    // Use SysAllocString instead of _bstr_t
    BSTR namespaceStr = SysAllocString(L"ROOT\\CIMV2");

    // Connect to WMI namespace
    hres = pLoc->ConnectServer(
        namespaceStr,            // WMI namespace
        NULL,                    // User name
        NULL,                    // User password
        NULL,                    // Locale
        0,                       // Security flags (changed from NULL to 0)
        NULL,                    // Authority
        NULL,                    // Context object
        &pSvc                    // IWbemServices proxy
    );

    SysFreeString(namespaceStr);

    if (FAILED(hres)) {
        std::cerr << "Could not connect to WMI namespace. Error code = 0x"
                  << std::hex << hres << std::endl;
        pLoc->Release();     
        CoUninitialize();
        return 1;
    }

    // Set security levels on the proxy
    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hres)) {
        std::cerr << "Could not set proxy blanket. Error code = 0x"
                  << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();     
        CoUninitialize();
        return 1;
    }

    // Use WQL to query all chrome.exe processes
    IEnumWbemClassObject* pEnumerator = NULL;
    BSTR query = SysAllocString(L"SELECT ProcessId, CommandLine FROM Win32_Process WHERE Name = 'chrome.exe'");
    BSTR queryLanguage = SysAllocString(L"WQL");

    hres = pSvc->ExecQuery(
        queryLanguage, 
        query,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
        NULL,
        &pEnumerator);

    SysFreeString(query);
    SysFreeString(queryLanguage);

    if (FAILED(hres)) {
        std::cerr << "WMI query failed. Error code = 0x"
                  << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) break;

        VARIANT vtProcessId;
        VARIANT vtCommandLine;

        hr = pclsObj->Get(L"ProcessId", 0, &vtProcessId, 0, 0);
        hr = pclsObj->Get(L"CommandLine", 0, &vtCommandLine, 0, 0);

        if (vtCommandLine.vt == VT_BSTR && vtCommandLine.bstrVal != NULL) {
            // check if the process is a chrome extension process
            std::wstring commandline_wstr = vtCommandLine.bstrVal;
            std::string commandline_str(commandline_wstr.begin(), commandline_wstr.end());
            if (commandline_str.find("--extension-process") != std::string::npos) {
                extension_PIDs.push_back(vtProcessId.uintVal); // if it is, append PID
            }
        }

        VariantClear(&vtProcessId);
        VariantClear(&vtCommandLine);
        pclsObj->Release();
    }

    // Cleanup
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return 0;
}

int main() {

    // foreword
    std::string msg = "\n"
                    "DeathWize v1.0\n"
                    "A LineWize Killer, developed by Jason Wu\n"
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

        // loop to check for and kill Chrome Extension Processes 
        while (1==1) {
            processCheck();

            // std::cout << "Found Chrome Extension Processes: ";
            // for (int id : extension_PIDs) {
            //     std::cout << id << ", ";
            // }
            // std::cout << std::endl;

            // Kill all processes with "--extension-process" in CommandLine
            for (int id : extension_PIDs) {
                KillProcessByID(id);
            }

            extension_PIDs = {};
        }
    }
    return 0;
}

// If you want to compile from source:
// compile with: g++ deathwize.cpp -o deathwize.exe -lole32 -loleaut32 -luuid -lwbemuuid
// run with: ./deathwize

// I recommend that you save the run command in a batch file for easy access.