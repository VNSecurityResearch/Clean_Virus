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

void suspend(DWORD pid) {
HANDLE hProcess = INVALID_HANDLE_VALUE;
HANDLE hToken = INVALID_HANDLE_VALUE;
TOKEN_PRIVILEGES tp;
LUID luid;
TOKEN_PRIVILEGES tpPrevious;
DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);
OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken);
if (GetLastError() == ERROR_NO_TOKEN) {
ImpersonateSelf(SecurityImpersonation);
OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
}
if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) return;
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
if (GetLastError() != ERROR_SUCCESS) return;
//
// second pass.  set privilege based on previous setting
//
hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
if (hProcess != INVALID_HANDLE_VALUE) {
printf("%s %x\n", "Success", hProcess);
TerminateProcess(hProcess, (UINT)-1);
}
AdjustTokenPrivileges(
hToken,
FALSE,
&tpPrevious,
cbPrevious,
NULL,
NULL
);
CloseHandle(hToken);
return;
}

/*
void suspend(DWORD processId)
{
HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

THREADENTRY32 threadEntry;
threadEntry.dwSize = sizeof(THREADENTRY32);

Thread32First(hThreadSnapshot, &threadEntry);

do
{
if (threadEntry.th32OwnerProcessID == processId)
{
HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,
threadEntry.th32ThreadID);
SuspendThread(hThread);
CloseHandle(hThread);
}
} while (Thread32Next(hThreadSnapshot, &threadEntry));

CloseHandle(hThreadSnapshot);
}
*/


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
	cout << GetLastError();
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
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	HANDLE hToken = NULL;
	const char *Nam = NULL;
	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);
	// Retrieve information about the first process,
	// and exit if unsuccessful
	Process32First(hProcessSnap, &pe32);
	// Now walk the snapshot of processes, and
	// display information about each process in turn
	//OpenProcess
	do {
		if (strncmp(pe32.szExeFile, "Calculator.exe", 8) == 0) {
		//if(strncmp(pe32.szExeFile, "calc.exe", 8) == 0) {
		//if (strncmp(pe32.szExeFile, "svchost.exe", 11) == 0 || strncmp(pe32.szExeFile, "SVCHOST.EXE", 11) == 0) {
			DWORD i, dwSize = 0, dwResult = 0;
			HANDLE hToken;
			PTOKEN_OWNER pOwner;
			SID_NAME_USE SidType;
			char lpName[MAX_NAME];
			char lpDomain[MAX_NAME];
			PSID pSID = NULL;
			SID_IDENTIFIER_AUTHORITY SIDAuth = SECURITY_NT_AUTHORITY;
			// Open a handle to the access token for the calling process.
			HANDLE hProcess = fopenProcess(pe32.th32ProcessID);
			//cout << endl << hProcess << endl;
			//OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
			cout << GetLastError() << endl;
			if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
			{
				printf("OpenProcessToken Error %u\n", GetLastError());
				system("pause");
				return FALSE;
			}
			//cout << "ok";
			//system("pause");
			// Call GetTokenInformation to get the buffer size.

			if (!GetTokenInformation(hToken, TokenOwner, NULL, dwSize, &dwSize))
			{
				dwResult = GetLastError();
				if (dwResult != ERROR_INSUFFICIENT_BUFFER) {
					printf("GetTokenInformation Error %u\n", dwResult);
					return FALSE;
				}
			}

			// Allocate the buffer.

			pOwner = (PTOKEN_OWNER)GlobalAlloc(GPTR, dwSize);

			// Call GetTokenInformation again to get the group information.

			if (!GetTokenInformation(hToken, TokenOwner, pOwner,
				dwSize, &dwSize))
			{
				printf("GetTokenInformation Error %u\n", GetLastError());
				return FALSE;
			}

			// Create a SID for the BUILTIN\Administrators group.

			if (!AllocateAndInitializeSid(&SIDAuth, 2,
				SECURITY_BUILTIN_DOMAIN_RID,
				DOMAIN_ALIAS_RID_ADMINS,
				0, 0, 0, 0, 0, 0,
				&pSID))
			{
				printf("AllocateAndInitializeSid Error %u\n", GetLastError());
				return FALSE;
			}

			// Loop through the group SIDs looking for the administrator SID.
			LookupAccountSid(NULL, pOwner->Owner, lpName, &dwSize, lpDomain, &dwSize, &SidType);
			//cout << pe32.szExeFile;
			//cout << lpName;
			//system("pause");
			//cout << lpDomain;
			if (compare(lpName, "Admin") == 0) {
				suspend(pe32.th32ProcessID);
				cout << "Suspend success: " << pe32.szExeFile << " user: " << lpName << endl;
			}
			//for (i = 0; i < pGroupInfo->GroupCount; i++)
			//{
			//	if (EqualSid(pSID, pGroupInfo->Groups[i].Sid))
			//	{
			//		// Lookup the account name and print it.
			//		dwSize = MAX_NAME;
			//		LookupAccountSid(NULL, pGroupInfo->Groups[i].Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType);
			//		if (compare(lpName, "Administrators") == 0) {
			//			cout << pe32.th32ProcessID;
			//			cout << lpName;
			//			//suspend(pe32.th32ParentProcessID);
			//			suspend(pe32.th32ProcessID);
			//			system("pause");
			//		}
			//	}
			//}
/*
			if (pSID)
				FreeSid(pSID);
			if (pGroupInfo)
				GlobalFree(pGroupInfo);*/
			//system("pause");
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));
	return TRUE;
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
					cout << GetLastError();
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
// main
/*#include<stdio.h>
#include<Windows.h>
#include <process.h>
#include<TlHelp32.h>
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Advapi32.lib")

void get_path_startup(char *path_file)
{
char name1[65] = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";
char name2[8] = "Startup";
char path[256] = { 0 };
DWORD cbData;
HKEY phkResult;

if (!RegOpenKeyExA(HKEY_CURRENT_USER, name1, 0, 1, &phkResult))
{
cbData = 0;
if (!RegQueryValueExA(phkResult, name2, 0, 0, 0, &cbData))
{
if (!RegQueryValueExA(phkResult, name2, 0, 0, (BYTE*)path, &cbData))
{
strcpy_s(path_file, 256, path);
}
}
}
}
void KillSpecialProc(DWORD pid) {
HANDLE hProcess = INVALID_HANDLE_VALUE;
HANDLE hToken = INVALID_HANDLE_VALUE;
TOKEN_PRIVILEGES tp;
LUID luid;
TOKEN_PRIVILEGES tpPrevious;
DWORD cbPrevious=sizeof(TOKEN_PRIVILEGES);
OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken);
if (GetLastError() == ERROR_NO_TOKEN) {
ImpersonateSelf(SecurityImpersonation);
OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
}
if(!LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &luid )) return;
//
// first pass.  get current privilege setting
//
tp.PrivilegeCount           = 1;
tp.Privileges[0].Luid       = luid;
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
AdjustTokenPrivileges(
hToken,
FALSE,
&tp,
sizeof(TOKEN_PRIVILEGES),
&tpPrevious,
&cbPrevious
);
if (GetLastError() != ERROR_SUCCESS) return;
//
// second pass.  set privilege based on previous setting
//
hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
if(hProcess != INVALID_HANDLE_VALUE) {
printf("%s %x\n", "Success", hProcess);
TerminateProcess(hProcess, (UINT)-1);
}
AdjustTokenPrivileges(
hToken,
FALSE,
&tpPrevious,
cbPrevious,
NULL,
NULL
);
CloseHandle(hToken);
return;
}

void killProcess()
{
// Kill Process
HANDLE hProcessSnap;
PROCESSENTRY32 pe32;
// Take a snapshot of all processes in the system.
hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
// Set the size of the structure before using it.
pe32.dwSize = sizeof( PROCESSENTRY32 );
// Retrieve information about the first process,
// and exit if unsuccessful
Process32First( hProcessSnap, &pe32 );
// Now walk the snapshot of processes, and
// display information about each process in turn
do {
if(strncmp(pe32.szExeFile, "SVCHOST.EXE", 12) == 0 || strncmp(pe32.szExeFile, "svchost.exe", 12) == 0) {
KillSpecialProc(pe32.th32ParentProcessID);
KillSpecialProc(pe32.th32ProcessID);
break;
}
} while(Process32Next( hProcessSnap, &pe32 ) );
CloseHandle( hProcessSnap );
}
int main()
{
killProcess();
return 0;
}
*/

//*************************************************************
//
//  RegDelnodeRecurse()
//
//  Purpose:    Deletes a registry key and all its subkeys / values.
//
//  Parameters: hKeyRoot    -   Root key
//              lpSubKey    -   SubKey to delete
//
//  Return:     TRUE if successful.
//              FALSE if an error occurs.
//
//*************************************************************

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

//*************************************************************
//
//  RegDelnode()
//
//  Purpose:    Deletes a registry key and all its subkeys / values.
//
//  Parameters: hKeyRoot    -   Root key
//              lpSubKey    -   SubKey to delete
//
//  Return:     TRUE if successful.
//              FALSE if an error occurs.
//
//*************************************************************

BOOL RegDelnode(HKEY hKeyRoot, LPCTSTR lpSubKey)
{
	TCHAR szDelKey[MAX_PATH * 2];

	StringCchCopy(szDelKey, MAX_PATH * 2, lpSubKey);
	return RegDelnodeRecurse(hKeyRoot, szDelKey);

}
int main() {
	suspendProcess();
	system("pause");
}
int main1()
{
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
	//Search_file("D:\\Data\\", 0);
	system("pause");
	return 0;
}