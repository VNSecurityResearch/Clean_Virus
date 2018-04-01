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

int main()
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	HANDLE hToken = NULL;
	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);
	// Retrieve information about the first process,
	// and exit if unsuccessful
	Process32First(hProcessSnap, &pe32);
	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do {
		if (strncmp(pe32.szExeFile, "Calculator.exe", 14) == 0) {
			DWORD i, dwSize = 0, dwResult = 0;
			HANDLE hToken;
			PTOKEN_GROUPS pGroupInfo;
			SID_NAME_USE SidType;
			char lpName[MAX_NAME];
			char lpDomain[MAX_NAME];
			PSID pSID = NULL;
			SID_IDENTIFIER_AUTHORITY SIDAuth = SECURITY_NT_AUTHORITY;

			// Open a handle to the access token for the calling process.
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
			if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
			{
				printf("OpenProcessToken Error %u\n", GetLastError());
				return FALSE;
			}

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
					if (!LookupAccountSid(NULL, pGroupInfo->Groups[i].Sid,
						lpName, &dwSize, lpDomain,
						&dwSize, &SidType))
					{
						dwResult = GetLastError();
						if (dwResult == ERROR_NONE_MAPPED)
							strcpy_s(lpName, dwSize, "NONE_MAPPED");
						else
						{
							printf("LookupAccountSid Error %u\n", GetLastError());
							return FALSE;
						}
					}
					printf("Current user is a member of the %s\\%s group\n",
						lpDomain, lpName);
					// Find out whether the SID is enabled in the token.
					if (pGroupInfo->Groups[i].Attributes & SE_GROUP_ENABLED)
						printf("The group SID is enabled.\n");
					else if (pGroupInfo->Groups[i].Attributes &
						SE_GROUP_USE_FOR_DENY_ONLY)
						printf("The group SID is a deny-only SID.\n");
					else
						printf("The group SID is not enabled.\n");
				}
			}

			if (pSID)
				FreeSid(pSID);
			if (pGroupInfo)
				GlobalFree(pGroupInfo);
		}
		}while (Process32Next(hProcessSnap, &pe32));
	return TRUE;
}