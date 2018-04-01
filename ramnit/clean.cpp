#include <windows.h>
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

HANDLE hMapObject, hRead;
LPVOID lpBase;
PIMAGE_DOS_HEADER dosHeader;
PIMAGE_NT_HEADERS ntHeader;
IMAGE_FILE_HEADER header;
IMAGE_OPTIONAL_HEADER opHeader;
PIMAGE_SECTION_HEADER pSecHeader;
char Ramnit_N[] = {
	0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x8B, 0xC5, 0x81,
	0xED, 0xCE, 0xB2, 0x01, 0x20, 0x2B, 0x85, 0x35, 0xBA, 0x01,
	0x20, 0x89, 0x85, 0x31, 0xBA, 0x01, 0x20, 0xB0, 0x00, 0x86
};
BOOL CheckSig(char* bytes, char* sign, int number) {
	int i = 0;
	for (i = 0; i < number; i++) {
		if (*(bytes + i) != *(sign + i)) {
			return FALSE;
		}
	}
	return TRUE;
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
int cleanShellCode(const string directory) {
	LPCSTR Dirname = directory.c_str();
	hRead = CreateFile(Dirname, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hRead == INVALID_HANDLE_VALUE) {
		return 0;
	}
	hMapObject = CreateFileMapping(hRead, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMapObject == NULL) {
		return 0;
	}
	lpBase = MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);
	dosHeader = (PIMAGE_DOS_HEADER)lpBase;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return 0;
	}
	ntHeader = (PIMAGE_NT_HEADERS)((DWORD)(dosHeader)+(dosHeader->e_lfanew));
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		return 0;
	}
	opHeader = ntHeader->OptionalHeader;
	WORD numsec = ntHeader->FileHeader.NumberOfSections - 1;
	PIMAGE_SECTION_HEADER lastSection = (PIMAGE_SECTION_HEADER)((DWORD)lpBase + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + numsec * sizeof(IMAGE_SECTION_HEADER));
	DWORD shellcodeEP = opHeader.AddressOfEntryPoint;
	// Check Shellcode
	BYTE *rawData = (BYTE *)((DWORD)lpBase + RvaToOffset(shellcodeEP, lastSection, ntHeader) + 2);
	if (memcmp(rawData, Ramnit_N, 30) == 0) {
		DWORD saveEP;
		DWORD realEP;
		DWORD oldEP;
		DWORD num;
		DWORD ez = ntHeader->OptionalHeader.AddressOfEntryPoint;
		DWORD EntryP = RvaToOffset(ez, lastSection, ntHeader);
		DWORD dwFileSize = GetFileSize(hRead, NULL) - 0x1500;
		DWORD EP = 0x110;
		// tinh lai cac thong so

		DWORD newVirtualSize = dwFileSize - lastSection->PointerToRawData;
		DWORD newRawSize = dwFileSize - lastSection->PointerToRawData;
		DWORD newCharacteristics = lastSection->Characteristics - 0xA0000000;
		DWORD newSizeOfImage = newVirtualSize + lastSection->VirtualAddress;

		SetFilePointer(hRead, 0x771 + EntryP, 0, FILE_BEGIN);
		ReadFile(hRead, &saveEP, 4, &num, NULL);
		oldEP = EntryP - saveEP;
		DWORD Characteristics = (DWORD)((DWORD)lastSection - (DWORD)lpBase + 36);
		DWORD RawSize = (DWORD)((DWORD)lastSection - (DWORD)lpBase + 16);
		DWORD VirtualSize = (DWORD)((DWORD)lastSection - (DWORD)lpBase + 8);
		DWORD SizeOfImage = (DWORD)((DWORD)dosHeader - (DWORD)lpBase + 80);
		WORD NumberOfSection = (DWORD)ntHeader + 6;
		//
		SetFilePointer(hRead, SizeOfImage, 0, FILE_BEGIN);
		WriteFile(hRead, &newSizeOfImage, 4, &num, NULL);
		SetFilePointer(hRead, EP, 0, FILE_BEGIN);
		WriteFile(hRead, &oldEP, 4, &num, NULL);
		SetFilePointer(hRead, NumberOfSection, 0, FILE_BEGIN);
		WriteFile(hRead, &numsec, 4, &num, NULL);
		CloseHandle(hRead);
		CloseHandle(hMapObject);
		UnmapViewOfFile(lpBase);
	}
}
int searchFile(const string directory) {

	HANDLE dir;
	WIN32_FIND_DATA file_data;
	//stringvec out;
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
			//cout << &full_file_name << endl;
			cleanShellCode(full_file_name);
		}
	} while (FindNextFile(dir, &file_data));
	return true;
	//FindClose(dir);
}
int main()
{
	killProcessByName("iexplore.exe");
	const string directory = "B://ramnit/";
	searchFile(directory);
}