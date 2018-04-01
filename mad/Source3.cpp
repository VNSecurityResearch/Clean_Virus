#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <tchar.h>
#include <windows.h>
#include <process.h>
#include <Tlhelp32.h>
#include <winbase.h>
#include <string.h>
using namespace std;

int i = 0;
HANDLE hMapObject, hRead;
LPVOID lpBase;
PIMAGE_DOS_HEADER dosHeader;
PIMAGE_NT_HEADERS ntHeader;
IMAGE_FILE_HEADER header;
IMAGE_OPTIONAL_HEADER opHeader;
PIMAGE_SECTION_HEADER pSecHeader;
OPENFILENAME ofn;
char szFile[100];
//typedef std::vector<std::string> stringvec;

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
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
				(DWORD)pEntry.th32ProcessID);
			if (hProcess != NULL)
			{
				TerminateProcess(hProcess, 9);
				CloseHandle(hProcess);
			}
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
}

DWORD RvaToOffset(DWORD rva, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt)
{
	size_t i = 0;
	PIMAGE_SECTION_HEADER pSeh;
	if (rva == 0)
	{
		return (rva);
	}
	pSeh = psh;
	for (i = 0; i < pnt->FileHeader.NumberOfSections; i++)
	{
		if (rva >= pSeh->VirtualAddress && rva < pSeh->VirtualAddress +
			pSeh->Misc.VirtualSize)
		{
			break;
		}
		pSeh++;
	}
	return (rva - pSeh->VirtualAddress + pSeh->PointerToRawData);
}
void cutfile(const string Dirname)
{
	LPCSTR filename = Dirname.c_str();
	LONG lsize = -4495;
	DWORD dwErr;
	HANDLE file = CreateFile(filename, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_NEW | OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	dwErr = GetLastError();
	if (dwErr > 0) {
		cout << "Error Code: " << dwErr << endl;
	}
	SetFilePointer(file, lsize, 0, FILE_END);
	int ok = SetEndOfFile(file);
	CloseHandle(file);
}
void clearShellCode(const string directory) {
	LPCSTR Dirname = directory.c_str();
	hRead = CreateFile(Dirname, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	hMapObject = CreateFileMapping(hRead, NULL, PAGE_READONLY, 0, 0, NULL);
	lpBase = MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);
	dosHeader = (PIMAGE_DOS_HEADER)lpBase;
	ntHeader = (PIMAGE_NT_HEADERS)((DWORD)(dosHeader)+(dosHeader->e_lfanew));
	opHeader = ntHeader->OptionalHeader;
	WORD numsec = ntHeader->FileHeader.NumberOfSections - 1;
	PIMAGE_SECTION_HEADER lastSection = (PIMAGE_SECTION_HEADER)((DWORD)lpBase + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + numsec * sizeof(IMAGE_SECTION_HEADER));
	DWORD saveEP;
	DWORD realEP;
	DWORD num;
	//DWORD ez = ntHeader->OptionalHeader.AddressOfEntryPoint;
	//DWORD EntryP = RvaToOffset(ez, lastSection, ntHeader);
	DWORD EntryP = (DWORD)&ntHeader->OptionalHeader.AddressOfEntryPoint - (DWORD)lpBase;
	SetFilePointer(hRead, EntryP, 0, FILE_BEGIN);
	ReadFile(hRead, &saveEP, 4, &num, NULL);
	if (saveEP == 0x79037860) {
		DWORD *pshellcodeEP = &opHeader.AddressOfEntryPoint;
		DWORD AddressEP = *pshellcodeEP;
		DWORD *pEP = (DWORD *)((DWORD)lpBase + RvaToOffset(AddressEP, lastSection, ntHeader));
		LONG *newEP = (LONG*)pEP + 0x1B;
		LONG epoint = *newEP;
		DWORD test1 = (DWORD)lpBase;
		DWORD cacheEP = 0x000B853F;
		SetFilePointer(hRead, cacheEP, 0, FILE_BEGIN);
		ReadFile(hRead, &realEP, 4, &num, NULL);
		DWORD EntryPoint = (DWORD)&ntHeader->OptionalHeader.AddressOfEntryPoint - (DWORD)lpBase;
		DWORD imagebase = opHeader.ImageBase;
		DWORD EP = realEP - imagebase;
		CloseHandle(hRead);
		HANDLE hWrite = CreateFile(Dirname, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		SetFilePointer(hWrite, EntryPoint, 0, FILE_BEGIN);
		WriteFile(hWrite, &EP, 4, &num, NULL);
		CloseHandle(hWrite);
		CloseHandle(hMapObject);
		UnmapViewOfFile(lpBase);
	}
	else
	{
		CloseHandle(hRead);
		CloseHandle(hMapObject);
		UnmapViewOfFile(lpBase);
	}
	//return EntryP;
}

int searchFile(const string directory) {
	
	HANDLE dir;
	WIN32_FIND_DATA file_data;
	if ((dir = FindFirstFile((directory + "/*").c_str(), &file_data)) == INVALID_HANDLE_VALUE) {
		return false;
	}
	do {
		const string file_name = file_data.cFileName;
		const string full_file_name = directory + "/" + file_name;
		const bool is_directory = (file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
		if (file_name[0] == '.')
			continue;

		else if (is_directory)
		{
			searchFile(full_file_name);
			continue;

		}
		else {
			//if (file_name == "*.exe" || full_file_name == "*.crv") {
				clearShellCode(full_file_name);
				cutfile(full_file_name);
				continue;
			//}
		}
	} while (FindNextFile(dir, &file_data));
	return true;
}

int main()
{
	killProcessByName("A.exe");
	killProcessByName("Serverx.exe");
	const string directory = "D://dir/";
	searchFile(directory);
}