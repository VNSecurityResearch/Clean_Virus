#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tlhelp32.h>
void TerminateProc(DWORD pid) {
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
void killProcessByName(const char *filename)
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (strcmp(pEntry.szExeFile, filename) == 0)
		{
			//HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
			//(DWORD) pEntry.th32ProcessID);
			//HANDLE hPaProcess = OpenProcess(PROCESS_TERMINATE, 0,
			//(DWORD) pEntry.th32ParentProcessID);
			//if (hProcess != NULL)
			//{
			TerminateProc(pEntry.th32ParentProcessID);
			TerminateProc(pEntry.th32ProcessID);
			//CloseHandle(hProcess);
			//}
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
}
int main()
{
	killProcessByName("Serverx.exe");
	return 0;
}