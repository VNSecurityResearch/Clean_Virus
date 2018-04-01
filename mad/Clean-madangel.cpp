#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
using namespace std;

int i = 0;
HANDLE hMapObject, hFile, hWrite;
LPVOID lpBase;
PIMAGE_DOS_HEADER dosHeader;
PIMAGE_NT_HEADERS ntHeader;
IMAGE_FILE_HEADER header;
IMAGE_OPTIONAL_HEADER opHeader;
PIMAGE_SECTION_HEADER pSecHeader;
OPENFILENAME ofn;
char szFile[100];

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
int main()
{	
		LPSTR Dirname = "D:\\ted.exe";
		hFile = CreateFile(Dirname, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			cout << "ERROR : Could not open the file" << endl;
		};
		hMapObject = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		CloseHandle(hFile);
		CloseHandle(hMapObject);
		UnmapViewOfFile(lpBase);
		lpBase = MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);
		dosHeader = (PIMAGE_DOS_HEADER)lpBase;
		ntHeader = (PIMAGE_NT_HEADERS)((DWORD)(dosHeader)+(dosHeader->e_lfanew));
		opHeader = ntHeader->OptionalHeader;
		// Chinh lai cac thong so
		DWORD readEP, num;
		WORD numsec = ntHeader->FileHeader.NumberOfSections - 1;
		PIMAGE_SECTION_HEADER lastSection = (PIMAGE_SECTION_HEADER)((DWORD)lpBase + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + numsec * sizeof(IMAGE_SECTION_HEADER));
		DWORD EP = 0x110;
		DWORD *pshellcodeEP = &opHeader.AddressOfEntryPoint;
		DWORD AddressEP = *pshellcodeEP;
		DWORD *pEP = (DWORD *)((DWORD)lpBase + RvaToOffset(AddressEP, lastSection, ntHeader));
		//BYTE *newEP = (BYTE*)pEP + 0x1B;
		DWORD *newEP = (DWORD*)pEP + 7;
		DWORD epoint = *newEP;
		HANDLE hRead = CreateFile(Dirname, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		SetFilePointer(hRead, epoint, 0, FILE_BEGIN);
		ReadFile(hRead, &readEP, 4, &num, NULL);
		DWORD shellcodeEP = opHeader.AddressOfEntryPoint;
		DWORD zero = RvaToOffset(shellcodeEP, lastSection, ntHeader);
		SetFilePointer(hFile, EP, 0, FILE_BEGIN);
		WriteFile(hFile, &newEP, 4, &num, NULL);
		SetFilePointer(hFile, zero, 0, FILE_BEGIN);
		WriteFile(hFile, "\x00", 0x100, &num, NULL);
		// Close
		CloseHandle(hRead);
		
	}