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

int flag = 0;
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
void cutFile(const string Dirname)
{
	LPCSTR filename = Dirname.c_str();
	LONG lsize = -4495;
	DWORD dwErr;
	HANDLE file = CreateFile(filename, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_NEW | OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	SetFilePointer(file, lsize, 0, FILE_END);
	int ok = SetEndOfFile(file);
	CloseHandle(file);
}
bool clearShellCode(const string directory) {
	LPCSTR Dirname = directory.c_str();
	hRead = CreateFile(Dirname, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hRead == INVALID_HANDLE_VALUE) {
		return false;
	}
	hMapObject = CreateFileMapping(hRead, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMapObject == NULL) {
		return false;
	}
	lpBase = MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);
	dosHeader = (PIMAGE_DOS_HEADER)lpBase;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}
	ntHeader = (PIMAGE_NT_HEADERS)((DWORD)(dosHeader)+(dosHeader->e_lfanew));
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		return false;
	}
	opHeader = ntHeader->OptionalHeader;
	WORD numsec = ntHeader->FileHeader.NumberOfSections - 1;
	PIMAGE_SECTION_HEADER lastSection = (PIMAGE_SECTION_HEADER)((DWORD)lpBase + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + numsec * sizeof(IMAGE_SECTION_HEADER));
	DWORD saveEP;
	DWORD realEP;
	DWORD num;
	DWORD ez = ntHeader->OptionalHeader.AddressOfEntryPoint;
	DWORD cacheEP = ez + 0x1B;
	DWORD Ept = RvaToOffset(cacheEP, lastSection, ntHeader);
	DWORD EntryP = RvaToOffset(ez, lastSection, ntHeader);
	DWORD dwFileSize = GetFileSize(hRead, NULL) - 0x118F;

	DWORD Characteristics = (DWORD)((DWORD)lastSection - (DWORD)lpBase + 36);
	DWORD RawSize = (DWORD)((DWORD)lastSection - (DWORD)lpBase + 16);
	DWORD VirtualSize = (DWORD)((DWORD)lastSection - (DWORD)lpBase + 8);
	DWORD SizeOfImage = (DWORD)((DWORD)ntHeader - (DWORD)lpBase + 80);
	// tinh lai cac thong so
	
	DWORD newVirtualSize = dwFileSize - lastSection->PointerToRawData;
	DWORD newRawSize = dwFileSize - lastSection->PointerToRawData;
	DWORD newCharacteristics = lastSection->Characteristics - 0xA0000000;
	DWORD newSizeOfImage = newVirtualSize + lastSection->VirtualAddress;
	
	SetFilePointer(hRead, EntryP, 0, FILE_BEGIN);
	ReadFile(hRead, &saveEP, 4, &num, NULL);
	if (saveEP == 0x79037860) {
		SetFilePointer(hRead, EntryP + 4, 0, FILE_BEGIN);
		//if (!ReadFile(hRead, &saveEP, 4, &num, NULL)) {
		//	return false;
		//}
		//if(saveEP == 0x74E8Eb01){
		DWORD *pshellcodeEP = &opHeader.AddressOfEntryPoint;
		DWORD AddressEP = *pshellcodeEP;
		DWORD *pEP = (DWORD *)((DWORD)lpBase + RvaToOffset(AddressEP, lastSection, ntHeader));
		LONG *newEP = (LONG*)pEP + 0x1B;
		LONG epoint = *newEP;
		DWORD test1 = (DWORD)lpBase;
		//DWORD cacheEP = 0x000B853F;
		SetFilePointer(hRead, Ept, 0, FILE_BEGIN);
		if (!ReadFile(hRead, &realEP, 4, &num, NULL)) {
			return false;
		}
		DWORD EntryPoint = (DWORD)&ntHeader->OptionalHeader.AddressOfEntryPoint - (DWORD)lpBase;
		//DWORD imagebase = opHeader.ImageBase;
		DWORD EP = realEP - opHeader.ImageBase;
		CloseHandle(hRead);
		HANDLE hWrite = CreateFile(Dirname, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hWrite == INVALID_HANDLE_VALUE) {
			return false;
		}
		SetFilePointer(hWrite, EntryPoint, 0, FILE_BEGIN);
		WriteFile(hWrite, &EP, 4, &num, NULL);
		SetFilePointer(hWrite, Characteristics, 0, FILE_BEGIN);
		WriteFile(hWrite, &newCharacteristics, 4, &num, NULL);
		SetFilePointer(hWrite, VirtualSize, 0, FILE_BEGIN);
		WriteFile(hWrite, &newVirtualSize, 4, &num, NULL);
		SetFilePointer(hWrite, RawSize, 0, FILE_BEGIN);
		WriteFile(hWrite, &newRawSize, 4, &num, NULL);
		SetFilePointer(hWrite, SizeOfImage, 0, FILE_BEGIN);
		WriteFile(hWrite, &newSizeOfImage, 4, &num, NULL);
		CloseHandle(hWrite);
		CloseHandle(hMapObject);
		UnmapViewOfFile(lpBase);
		return true;
		//}
	}
	else
	{
		CloseHandle(hRead);
		CloseHandle(hMapObject);
		UnmapViewOfFile(lpBase);
		//return false;
	}
}

int searchFile(const char * dirn)
{
	
	char dirnPath[1024];
	sprintf_s(dirnPath, "%s\\*", dirn);

	WIN32_FIND_DATA f;
	HANDLE h = FindFirstFile(dirnPath, &f);

	if (h == INVALID_HANDLE_VALUE) { return 0; }

	do
	{
		const char * name = f.cFileName;
		char filePath[1024];
		sprintf_s(filePath, "%s%s%s", dirn, "\\", name);

		if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) { 
			continue; 
		}

		if (f.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)
		{
			searchFile(filePath);
			continue;
		}
		else {
			//if (fn.substr(fn.find_last_of(".") + 1) == "exe" || fn.substr(fn.find_last_of(".") + 1) == "src") {
				killProcessByName(name);
				do{
					flag = clearShellCode(filePath);
					cutFile(filePath);
				}while(flag == 1);
			//}
		}
	} while (FindNextFile(h, &f));
	FindClose(h);
	return 1;
}

int main()
{
	killProcessByName("Serverx.exe");
	const char* directory = "D:\\dire";
	searchFile(directory);
	cout << "Clear done!" << endl;
	system("pause");
}