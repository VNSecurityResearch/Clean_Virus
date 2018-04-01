#include <Windows.h>
#include <iostream>
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
	/****************************************************************************
	fill struct openfilename
	*/
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.lpstrFile = (LPWSTR)szFile;
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrFilter = L"ALL\0*.*\0Text\0*.TXT\0";
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_LONGNAMES | OFN_EXPLORER | OFN_HIDEREADONLY;
	if (GetOpenFileName(&ofn))
	{
		// Doc khoang cach quay ve de suy ra oldEP, set EP = oldEP, luu lai EPshellcode de xoa shellcode
		hFile = CreateFile(ofn.lpstrFile, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			cout << "ERROR : Could not open the file" << endl; 
		};
		hMapObject = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		lpBase = MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);
		dosHeader = (PIMAGE_DOS_HEADER)lpBase;
		ntHeader = (PIMAGE_NT_HEADERS)((DWORD)(dosHeader)+(dosHeader->e_lfanew));
		opHeader = ntHeader->OptionalHeader;
		// Chinh lai cac thong so
		DWORD num;
		WORD numsec = ntHeader->FileHeader.NumberOfSections - 1;
		PIMAGE_SECTION_HEADER lastSection = (PIMAGE_SECTION_HEADER)((DWORD)lpBase + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + numsec * sizeof(IMAGE_SECTION_HEADER));
		
		
		// Tinh lai EP
		DWORD shellcodeEP = opHeader.AddressOfEntryPoint;
		// Check Shellcode
		BYTE *rawData = (BYTE *)((DWORD)lpBase + RvaToOffset(shellcodeEP,lastSection, ntHeader)+2);
		if (memcmp(rawData, "\x33\xc9\x64\x8b\x49\x30\x8b\x49\x0c\x8b", 10)==0) {
		DWORD zero = RvaToOffset(shellcodeEP,lastSection, ntHeader);
		DWORD endShellCode = shellcodeEP + 0xc8;
		DWORD sizeJump = endShellCode;
		DWORD jum_oldEOP = *(DWORD*)((DWORD)lpBase + RvaToOffset(endShellCode,lastSection, ntHeader));
		DWORD newEP = jum_oldEOP  + endShellCode + 4;
		// Tinh vi tri con tro cua cac thong tin can chinh sua
		DWORD Characteristics = (DWORD)((DWORD)lastSection - (DWORD)lpBase + 36);
		DWORD RawSize = (DWORD)((DWORD)lastSection - (DWORD)lpBase + 16);
		DWORD VirtualSize = (DWORD)((DWORD)lastSection - (DWORD)lpBase + 8);
		DWORD SizeOfImage = (DWORD)((DWORD)dosHeader - (DWORD)lpBase + 80);
		// Tinh lai cac thong tin
		DWORD newVirtualSize = lastSection->SizeOfRawData - 0x100;
		DWORD newRawSize = lastSection->SizeOfRawData - 0x100;
		DWORD newSizeOfImage = 0x400000;
		DWORD EP = 0x110;
		// Sua thong tin & chen byte 0
		SetFilePointer(hFile, SizeOfImage, 0, FILE_BEGIN);
		WriteFile(hFile, &newSizeOfImage, 4, &num, NULL);
		SetFilePointer(hFile, VirtualSize, 0, FILE_BEGIN);
		WriteFile(hFile, &newVirtualSize, 4, &num, NULL);
		SetFilePointer(hFile, RawSize, 0, FILE_BEGIN);
		WriteFile(hFile, &newRawSize, 4, &num, NULL);
		SetFilePointer(hFile, EP, 0, FILE_BEGIN);
		WriteFile(hFile, &newEP, 4, &num, NULL);
		SetFilePointer(hFile, zero, 0, FILE_BEGIN);
		WriteFile(hFile, "\x00", 0x100, &num, NULL);
		}
		// Close
		CloseHandle(hFile);
		CloseHandle(hMapObject);
		UnmapViewOfFile(lpBase);
}
}