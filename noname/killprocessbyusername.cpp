#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "advapi32.lib")
#include<Windows.h>
#include <process.h>
#include<TlHelp32.h>
#include <iostream>
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Advapi32.lib")
using namespace std;
#include <comdef.h>
#define MAX_NAME 256
/*
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
*/

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
		printf("%s %x\n", "Success", hProcess);
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

int main()
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
		//if(strncmp(pe32.szExeFile, "calc.exe", 8) == 0) {
		if (strncmp(pe32.szExeFile, "svchost.exe", 11) == 0 || strncmp(pe32.szExeFile, "SVCHOST.EXE", 11) == 0) {
			DWORD i, dwSize	= 0, dwResult = 0;
			HANDLE hToken;
			PTOKEN_GROUPS pGroupInfo;
			SID_NAME_USE SidType;
			char lpName[MAX_NAME];
			char lpDomain[MAX_NAME];
			PSID pSID = NULL;
			SID_IDENTIFIER_AUTHORITY SIDAuth = SECURITY_NT_AUTHORITY;
			// Open a handle to the access token for the calling process.
			HANDLE hProcess = fopenProcess(pe32.th32ProcessID);
			cout << endl << hProcess << endl;
			 //OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
			cout << GetLastError() << endl;
			if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
			{
				printf("OpenProcessToken Error %u\n", GetLastError());
				system("pause");
				return FALSE;
			}
			cout << "ok";
			system("pause");
			// Call GetTokenInformation to get the buffer size.

			if (!GetTokenInformation(hToken, TokenGroups, NULL, dwSize, &dwSize))
			{
				dwResult = GetLastError();
				if (dwResult != ERROR_INSUFFICIENT_BUFFER) {
					printf("GetTokenInformation Error %u\n", dwResult);
					return FALSE;
				}
			}

			// Allocate the buffer.

			pGroupInfo = (PTOKEN_GROUPS)GlobalAlloc(GPTR, dwSize);

			// Call GetTokenInformation again to get the group information.

			if (!GetTokenInformation(hToken, TokenGroups, pGroupInfo,
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

			for (i = 0; i < pGroupInfo->GroupCount; i++)
			{
				if (EqualSid(pSID, pGroupInfo->Groups[i].Sid))
				{
					// Lookup the account name and print it.
					dwSize = MAX_NAME;
					LookupAccountSid(NULL, pGroupInfo->Groups[i].Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType);
						if (compare(lpName, "Administrators") == 0) {
							cout << pe32.th32ProcessID;
							cout << lpName;
							//suspend(pe32.th32ParentProcessID);
							suspend(pe32.th32ProcessID);
							system("pause");
						}
				}
			}

			if (pSID)
				FreeSid(pSID);
			if (pGroupInfo)
				GlobalFree(pGroupInfo);
		}
	} while (Process32Next(hProcessSnap, &pe32));
	return TRUE;
}
/*
#include <windows.h>
#include <iostream>
#include <stdio.h>
#pragma comment(lib, "advapi32.lib")

#define MAX_NAME 256
using namespace std;
int main()
{
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
	 
	 first pass.  get current privilege setting
	
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
	 
	 second pass.  set privilege based on previous setting
	 
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);
	if (hProcess != INVALID_HANDLE_VALUE) {
		printf("%s %x\n", "Success", hProcess);
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
*/