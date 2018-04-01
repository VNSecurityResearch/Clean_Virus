#include <windows.h>
#include <stdio.h>
#include <process.h>
#include<TlHelp32.h>
#include <iostream>
#include <strsafe.h>
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Advapi32.lib")
using namespace std;
#include <comdef.h>
#define MAX_NAME 256
/*
bool suspend(DWORD processId)
{
HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
cout << "Process ID: " << processId << endl;
THREADENTRY32 threadEntry;
threadEntry.dwSize = sizeof(THREADENTRY32);
Thread32First(hThreadSnapshot, &threadEntry);
do
{
if (threadEntry.th32OwnerProcessID == processId)
{
HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,
threadEntry.th32ThreadID);
if (SuspendThread(hThread) == -1) {
return FALSE;
}
else {
return TRUE;
}
CloseHandle(hThread);
}
} while (Thread32Next(hThreadSnapshot, &threadEntry));
CloseHandle(hThreadSnapshot);
}
*/
typedef LONG(NTAPI *NtSuspendProcess)(IN HANDLE ProcessHandle);
bool suspend(DWORD processId)
{
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(GetModuleHandle("ntdll"), "NtSuspendProcess");

	if (pfnNtSuspendProcess(processHandle) == TRUE) {
		return TRUE;
	}
	else {
		return FALSE;
	}
	CloseHandle(processHandle);
}

int len(char *s) {
	int len = 0;
	while (s[len] != '\0')
		len++;
	return len;
}

int compare(char *s, char* search) {
	int len_search = len(search);
	int len_s = len(s);
	int i;
	if (len_s != len_search)
		return 1;
	else {
		for (i = 0; i < len_s; i++) {
			if (s[i] != search[i])
				return 1;
		}
		return 0;
	}
}
HANDLE fopenProcess(DWORD id) {
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	HANDLE hToken = INVALID_HANDLE_VALUE;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);
	HANDLE hCurrent = GetCurrentThread();
	//cout << GetLastError();
	OpenThreadToken(hCurrent, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken);
	if (GetLastError() == ERROR_NO_TOKEN) {
		ImpersonateSelf(SecurityImpersonation);
		OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) return false;
	// 
	// first pass.  get current privilege setting
	//
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		&tpPrevious,
		&cbPrevious
	);
	if (GetLastError() != ERROR_SUCCESS) return false;
	// 
	// second pass.  set privilege based on previous setting
	// 
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);
	if (hProcess != INVALID_HANDLE_VALUE) {
		//printf("%s %x\n", "Success", hProcess);
		return hProcess;
	}
	else return false;
	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tpPrevious,
		cbPrevious,
		NULL,
		NULL
	);
	CloseHandle(hToken);
	return hProcess;
}

int suspendProcess()
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hProcessSnap;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	HANDLE hToken = NULL;
	const char *Nam = NULL;
	if (Process32First(hProcessSnap, &pe32) == TRUE) {
		while (Process32Next(hProcessSnap, &pe32) == TRUE)
		{
			cout << pe32.szExeFile << ": ID " << pe32.th32ProcessID << " | PID: " << pe32.th32ParentProcessID << endl;
			//if (strncmp(pe32.szExeFile, "Calculator.exe", 14) == 0) {
			//if(strncmp(pe32.szExeFile, "calc.exe", 8) == 0) {
			if (strncmp(pe32.szExeFile, "svchost.exe", 11) == 0 || strncmp(pe32.szExeFile, "SVCHOST.EXE", 11) == 0) {
				DWORD i, dwSize = 0, dwResult = 0;
				HANDLE hToken;
				PTOKEN_OWNER pOwner;
				SID_NAME_USE SidType;
				char lpName[MAX_NAME];
				char lpDomain[MAX_NAME];
				PSID pSID = NULL;
				SID_IDENTIFIER_AUTHORITY SIDAuth = SECURITY_NT_AUTHORITY;
				HANDLE hProcess = fopenProcess(pe32.th32ProcessID);
				OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
				GetTokenInformation(hToken, TokenOwner, NULL, dwSize, &dwSize);
				pOwner = (PTOKEN_OWNER)GlobalAlloc(GPTR, dwSize);
				GetTokenInformation(hToken, TokenOwner, pOwner, dwSize, &dwSize);
				AllocateAndInitializeSid(&SIDAuth, 2,
					SECURITY_BUILTIN_DOMAIN_RID,
					DOMAIN_ALIAS_RID_ADMINS,
					0, 0, 0, 0, 0, 0,
					&pSID);
				LookupAccountSid(NULL, pOwner->Owner, lpName, &dwSize, lpDomain, &dwSize, &SidType);
				cout << endl << pe32.szExeFile << lpName << pe32.th32ProcessID <<  endl;
				if (compare(lpName, "Admin") == 0) {
					if (suspend(pe32.th32ProcessID) == TRUE) {
						cout << "Suspend success: " << pe32.szExeFile << " user: " << lpName << endl; return TRUE;
					}
				}
			}
		}
	}
	CloseHandle(hProcessSnap);
}
void Search_file(char* startDir, int key) {
	HANDLE hFind;
	WIN32_FIND_DATA wfd;
	char path[MAX_PATH];
	char path_exe[MAX_PATH];
	int temp = 0;
	sprintf_s(path, "%s\\*", startDir);
	if ((hFind = FindFirstFile(path, &wfd)) == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "FindFirstFIle failed on path = \"%s\"\n", path);
		return;
	}
	do {
		if ((strncmp(".", wfd.cFileName, 1) != 0) && (strncmp("..", wfd.cFileName, 2) != 0))
		{
			if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				sprintf_s(path, "%s\\%s", startDir, wfd.cFileName);
				if (len(wfd.cFileName) == 38) {
					cout << "Found directory contain virus noname: " << wfd.cFileName << endl;
					Search_file(path, 1);
					if (RemoveDirectoryA(path)) {
						cout << "Remove success" << endl;
					}
					else { cout << "Directory remove before"; }
				}
			}
			else {
				sprintf_s(path_exe, "%s\\%s", startDir, wfd.cFileName);
				if (key == 1) {
					DeleteFileA(path_exe);
				}
			}
		}
	} while (FindNextFile(hFind, &wfd) != 0);
	FindClose(hFind);
	return;
}
BOOL RegDelnodeRecurse(HKEY hKeyRoot, LPTSTR lpSubKey)
{
	LPTSTR lpEnd;
	LONG lResult;
	DWORD dwSize;
	TCHAR szName[MAX_PATH];
	HKEY hKey;
	FILETIME ftWrite;

	// First, see if we can delete the key without having
	// to recurse.

	lResult = RegDeleteKey(hKeyRoot, lpSubKey);

	if (lResult == ERROR_SUCCESS)
		return TRUE;

	lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);

	if (lResult != ERROR_SUCCESS)
	{
		if (lResult == ERROR_FILE_NOT_FOUND) {
			//printf("Key not found.\n");
			return TRUE;
		}
		else {
			printf("Error opening key.\n");
			return FALSE;
		}
	}

	// Check for an ending slash and add one if it is missing.

	lpEnd = lpSubKey + lstrlen(lpSubKey);

	if (*(lpEnd - 1) != TEXT('\\'))
	{
		*lpEnd = TEXT('\\');
		lpEnd++;
		*lpEnd = TEXT('\0');
	}

	// Enumerate the keys

	dwSize = MAX_PATH;
	lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
		NULL, NULL, &ftWrite);

	if (lResult == ERROR_SUCCESS)
	{
		do {

			*lpEnd = TEXT('\0');
			StringCchCat(lpSubKey, MAX_PATH * 2, szName);

			if (!RegDelnodeRecurse(hKeyRoot, lpSubKey)) {
				break;
			}

			dwSize = MAX_PATH;

			lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
				NULL, NULL, &ftWrite);

		} while (lResult == ERROR_SUCCESS);
	}

	lpEnd--;
	*lpEnd = TEXT('\0');

	RegCloseKey(hKey);

	// Try again to delete the key.

	lResult = RegDeleteKey(hKeyRoot, lpSubKey);

	if (lResult == ERROR_SUCCESS)
		return TRUE;

	return FALSE;
}

BOOL RegDelnode(HKEY hKeyRoot, LPCTSTR lpSubKey)
{
	TCHAR szDelKey[MAX_PATH * 2];

	StringCchCopy(szDelKey, MAX_PATH * 2, lpSubKey);
	return RegDelnodeRecurse(hKeyRoot, szDelKey);

}

int main()
{
	suspendProcess();
	BOOL bSuccess;
	bSuccess = RegDelnode(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
	RegDelnode(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
	RegDelnode(HKEY_LOCAL_MACHINE, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
	RegDelnode(HKEY_LOCAL_MACHINE, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
	RegDelnode(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
	RegDelnode(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
	RegDelnode(HKEY_LOCAL_MACHINE, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
	RegDelnode(HKEY_LOCAL_MACHINE, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
	if (bSuccess)
		printf("Delete hkey success!\n");
	else printf("Failure.\n");
	// xoa thu muc
	Search_file("C:\\Documents and Settings\\All Users\\Application Data\\", 0);
	system("pause");
	return 0;
}
