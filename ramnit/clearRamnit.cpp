#include<stdio.h>
#include<Windows.h>
#include <process.h>
#include<TlHelp32.h>
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Advapi32.lib")
void Create_fake_name_folder(char *fake_name_folder)
{
	int dir, i;
	CHAR Buffer[256] = { 0 };
	CHAR name[9] = { 0 };
	DWORD VolumeSerialNumber;
	dir = GetWindowsDirectoryA(Buffer, 0x104);
	for (i = 0; i < strlen(Buffer); i++)
	{
		if (Buffer[i] == ':')
		{
			Buffer[i + 1] = '\\';
			Buffer[i + 2] = '\0';
			break;
		}
	}
	GetVolumeInformationA(Buffer, 0, 0, &VolumeSerialNumber, 0, 0, 0, 0);
	for (i = 0; i < 8; i++)
	{
		VolumeSerialNumber += 0x1a79;
		VolumeSerialNumber = (16807 * (VolumeSerialNumber % 0x1F31D) - 2836 * (VolumeSerialNumber / 0x1F31D));
		name[i] = (char)((VolumeSerialNumber % 0x19) + 97);
	}
	strcpy_s(fake_name_folder, 9, name);
}
void Create_fake_name_file(char *fake_name_file)
{
	int dir, i;
	char Buffer[256] = { 0 };
	char name[15] = { 0 };
	DWORD VolumeSerialNumber;
	dir = GetWindowsDirectoryA(Buffer, 0x104);
	for (i = 0; i < strlen(Buffer); i++)
	{
		if (Buffer[i] == ':')
		{
			Buffer[i + 1] = '\\';
			Buffer[i + 2] = '\0';
			break;
		}
	}
	GetVolumeInformationA(Buffer, 0, 0, &VolumeSerialNumber, 0, 0, 0, 0);
	for (i = 0; i < 8; i++)
	{
		VolumeSerialNumber += 0x911;
		VolumeSerialNumber = (16807 * (VolumeSerialNumber % 0x1F31D) - 2836 * (VolumeSerialNumber / 0x1F31D));
		name[i] = (char)((VolumeSerialNumber % 0x19) + 97);
	}
	strcat_s(name, ".exe");
	strcpy_s(fake_name_file, 15, name);
}
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
int check_file(CHAR *path, char *fake_name_file)
{
	WIN32_FIND_DATAA FindFileData;
	HANDLE hFind;
	SetCurrentDirectoryA(path);
	hFind = FindFirstFileA("*.exe", &FindFileData);
	int result = 0;
	if (hFind != INVALID_HANDLE_VALUE)
	{
		do {
			if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			{
				if (strcmp(fake_name_file, (const char*)&FindFileData.cFileName) == 0)
				{
					result = 1;
				}
			}
		} while (FindNextFileA(hFind, &FindFileData));
	}
	return result;
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

void Del_virus(char *fake_name_file, char *fake_name_folder)
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
        printf("%s\n", pe32.szExeFile);
        if(strncmp(pe32.szExeFile, "IEXPLORE.EXE", 12) == 0 || strncmp(pe32.szExeFile, "iexplore.exe", 12) == 0) {
            KillSpecialProc(pe32.th32ParentProcessID);
            KillSpecialProc(pe32.th32ProcessID);
            //ListProcessThreads(pe32.th32ProcessID);
            printf("%s, %s\n", "ByeBye Angel ", pe32.szExeFile );
            break;
        }
    } while(Process32Next( hProcessSnap, &pe32 ) );
    CloseHandle( hProcessSnap );
	// Delete file
	DeleteFileA(fake_name_file);
	DeleteFileA(fake_name_folder);
}
void kill_file_pe(const char *file_name)
{
	HANDLE hFile;
	DWORD NumberOfBytesRead;
	DWORD FileSizeHigh, filesize, OEP;
	hFile = CreateFile(file_name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
	if (hFile != NULL)
	{
		filesize = GetFileSize(hFile, &FileSizeHigh);
		if (filesize > 0x24 && filesize != -1 && !FileSizeHigh)
		{
			// doc 24byte cuoi cung de kiem tra chu ky malware
			SetFilePointer(hFile, filesize - 0x24, 0, 0);
			CHAR Buffer[0x25] = { 0 };
			if (ReadFile(hFile, Buffer, 0x24u, &NumberOfBytesRead, 0))
			{
				// XOR de tim chu ky
				DWORD i, temp;
				memcpy(&i, Buffer, 4);
				memcpy(&temp, (Buffer + 4), 4);
				temp ^= i;
				if (temp == 0xFA1BC352)
				{
					// Co chu ky -> file da bi lay nhiem tien hanh khoi phuc
					HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, 0);
					if (hMapping != NULL)
					{
						char* pMapping = (char*)MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
						PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)pMapping;
						if (dos_header->e_magic == IMAGE_DOS_SIGNATURE)
						{
							PIMAGE_NT_HEADERS header = (PIMAGE_NT_HEADERS)(pMapping + dos_header->e_lfanew);
							if (header->Signature == IMAGE_NT_SIGNATURE)
							{
								// xoa section cua malware
								// sua lai entry point
								// sizeofimages
								// -> file duoc sua xong chay binh thuong
								WORD numsec = header->FileHeader.NumberOfSections - 1;
								header->FileHeader.NumberOfSections = numsec;
								PIMAGE_SECTION_HEADER Final_Section = (PIMAGE_SECTION_HEADER)(pMapping + dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) + numsec * sizeof(IMAGE_SECTION_HEADER));
								header->OptionalHeader.SizeOfImage = header->OptionalHeader.SizeOfImage - Final_Section->Misc.VirtualSize;
								memcpy(&OEP, (pMapping + Final_Section->PointerToRawData + 0x771), 4);
								DWORD newOEP = header->OptionalHeader.AddressOfEntryPoint - OEP;
								header->OptionalHeader.AddressOfEntryPoint = newOEP;
								memset((pMapping + Final_Section->PointerToRawData), 0, Final_Section->SizeOfRawData + 0x300);
								Final_Section->Characteristics = 0x00000000;
								Final_Section->Misc.PhysicalAddress = 0x00000000;
								Final_Section->Misc.VirtualSize = 0x00000000;
								memset(&Final_Section->Name, 0, 5);
								Final_Section->NumberOfLinenumbers = 0x0000;
								Final_Section->NumberOfRelocations = 0x0000;
								Final_Section->PointerToLinenumbers = 0x00000000;
								Final_Section->PointerToRawData = 0x00000000;
								Final_Section->PointerToRelocations = 0x00000000;
								Final_Section->SizeOfRawData = 0x00000000;
								Final_Section->VirtualAddress = 0x00000000;
								UnmapViewOfFile(pMapping);
								CloseHandle(hMapping);
								CloseHandle(hFile);
								printf("Clean virus on file %s complete\n", file_name);
							}
						}
					}
				}
				else
				{
					CloseHandle(hFile);
				}
			}
		}
	}
}
void kill_file_htm(const char *file_name)
{
	HANDLE hFile, hMap;
	DWORD NumberOfBytesRead;
	DWORD FileSizeHigh, filesize, OEP;
	CHAR Buffer[0x25] = { 0 };
	hFile = CreateFileA(file_name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, 0);
	if (hFile != NULL)
	{
		filesize = GetFileSize(hFile, &FileSizeHigh);
		if (filesize > 0x24 && filesize != -1 && !FileSizeHigh)
		{
			// doc 24byte tai vi tri filesize - 0x27 de kiem tra chu ky malware
			SetFilePointer(hFile, filesize - 0x27, 0, 0);
			if (ReadFile(hFile, Buffer, 0x24u, &NumberOfBytesRead, 0))
			{
				// XOR de lay chu ky ( neu co)
				DWORD i, temp;
				memcpy(&i, Buffer, 4);
				memcpy(&temp, (Buffer + 4), 4);
				temp ^= i;
				if (temp == 0xFA1BC352)
				{
					// Chu ky hop le -> file da bi lay nhiem
					HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, 0);
					if (hMapping != NULL)
					{
						char* pMapping = (char*)MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
						for (i = 0; i < filesize; i++)
						{
							if (!memcmp(pMapping + i, "<SCRIPT Language=VBScript>", 26))
							{
								// xoa phan lay nhiem cua malware
								DWORD len = filesize - i;
								memset((pMapping + i), 0, len);
							}
						}
						UnmapViewOfFile(pMapping);
						CloseHandle(hMapping);
						CloseHandle(hFile);
						printf("Clean virus on file %s complete\n", file_name);
					}
				}
				else
				{
					CloseHandle(hFile);
				}
			}
		}
	}
}
void Search_file(char* startDir) {
	HANDLE hFind;
	WIN32_FIND_DATA wfd;
	char path[MAX_PATH];
	char path_exe[MAX_PATH];
	int temp = 0;
	sprintf(path, "%s\\*", startDir);
	if ((hFind = FindFirstFile(path, &wfd)) == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "FindFirstFIle failed on path = \"%s\"\n", path);
		return;
	}
	do {
		if ((strncmp(".", wfd.cFileName, 1) != 0) && (strncmp("..", wfd.cFileName, 2) != 0))
		{
			if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				sprintf(path, "%s\\%s", startDir, wfd.cFileName);
				Search_file(path);
			}
			else {
				sprintf(path_exe, "%s\\%s", startDir, wfd.cFileName);
				temp = *(int*)(wfd.cFileName + strlen(wfd.cFileName) - 4);
				temp |= 0x20202000;
				if (strlen(wfd.cFileName) > 4) {
					if (temp == 0x6578652e || temp == 0x6372732e || temp == 0x6c6c642e) {
						sprintf(path_exe, "%s\\%s", startDir, wfd.cFileName);
						kill_file_pe(path_exe);
						SetFileAttributes(path_exe, wfd.dwFileAttributes);
					}
					if (temp == 0x6c6d74682e || temp == 0x6d74682e) {
						sprintf(path_exe, "%s\\%s", startDir, wfd.cFileName);
						kill_file_htm(path_exe);
						SetFileAttributes(path_exe, wfd.dwFileAttributes);
					}
				}
			}
		}
	} while (FindNextFile(hFind, &wfd) != 0);
	FindClose(hFind);
	return;
}


void Kill()
{
	Search_file("C:\\");
}
int main()
{
	char fake_name_file[15] = { 0 };
	char fake_name_folder[9] = { 0 };
	char path_file[255] = { 0 };
	char path_folder[255] = "C:\\Program Files\\";
	// tao fake name file va fake name folder tren may tinh bang thuat toan cua malware
	Create_fake_name_file(fake_name_file);
	Create_fake_name_folder(fake_name_folder);
	// lay duong dan thu muc startup
	get_path_startup(path_file);
	strcat_s(path_folder, fake_name_folder);
	// kiem tra cac file do malware tao co ton tai khong, neu co tien hanh cac ham diet
	//	if (check_file(path_file, fake_name_file) == 1 && check_file(path_folder, fake_name_file) == 1)
	//	{
	strcat_s(path_file, "\\");
	strcat_s(path_file, fake_name_file);
	strcat_s(path_folder, "\\");
	strcat_s(path_folder, fake_name_file);
	// Kill process bi lay nhiem
	// xoa cac file do malware tao
	// Sua lai Regitry key value do malware sua doi
	Del_virus(path_file, path_folder);

	// quet cac file trong duong dan cho nguoi dung chi dinh de kiem tra malware
	Kill();
	return 0;
}