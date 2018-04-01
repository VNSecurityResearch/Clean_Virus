#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tlhelp32.h>
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Advapi32.lib")
#define CLEAN 0
#define INFECTED 1
char RAMNIT32[] = {
                    0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x8B, 0xC5, 0x81,
                    0xED, 0xCE, 0xB2, 0x01, 0x20, 0x2B, 0x85, 0x35, 0xBA, 0x01,
                    0x20, 0x89, 0x85, 0x31, 0xBA, 0x01, 0x20, 0xB0, 0x00, 0x86,
                    0x85, 0x66, 0xBC, 0x01, 0x20, 0x3C, 0x01, 0x0F, 0x85, 0xBC,
                    0x01, 0x00, 0x00, 0x83, 0xBD, 0x61, 0xBB, 0x01, 0x20, 0x00,
                    0x74, 0x33, 0x83, 0xBD, 0x65, 0xBB, 0x01, 0x20, 0x00, 0x74,
                    0x2A, 0x8B, 0x85, 0x31
};
typedef struct MyPEHeader {
    int OEP;
    int NumberSections;
    void *pNtHeader;
    void *pOptionalHeader;
    void *pFileHeader;
    void *pSectionHeader;
    void *pLastSectionOffset;
    char buffer[0x1000];
    BOOL Infected;
} MyPEHeader;
int AlignSize(int number, int alignvalue) {
    if ((number % alignvalue) == 0)
        return alignvalue*(number/alignvalue);
    else 
        return alignvalue*((number/alignvalue)+1);
}
int RVAtoOffset(int rva, int Num_Section, void *pSectionHeader) {
    void* sectionptr;
    int i = 1;
    int temp = 0;
    sectionptr = (char*)pSectionHeader;
    while (i <= Num_Section) {
        temp = ((PIMAGE_SECTION_HEADER)sectionptr)->VirtualAddress;
        if (rva >= temp && rva < (temp + (((PIMAGE_SECTION_HEADER)sectionptr)->Misc).VirtualSize))
            break;
        i++;
        sectionptr = (char*)sectionptr + sizeof(IMAGE_SECTION_HEADER);
    }
    sectionptr = (char*)pSectionHeader + (i-1)*sizeof(IMAGE_SECTION_HEADER);
    if (rva == ((PIMAGE_SECTION_HEADER)sectionptr)->VirtualAddress)
        return ((PIMAGE_SECTION_HEADER)sectionptr)->PointerToRawData;
    return rva - ((PIMAGE_SECTION_HEADER)sectionptr)->VirtualAddress + ((PIMAGE_SECTION_HEADER)sectionptr)->PointerToRawData;
}
BOOL SignatureCompare(char* bytes, char* sign, int number) {
    int i = 0;
    for (i = 0; i < number; i++) {
        if (*(bytes+i) != *(sign+i)) {
            return FALSE;
        }
    }
    return TRUE;
}
MyPEHeader HeaederCheck(HANDLE hFile) {
    MyPEHeader header;
    char buf[0x100] = "";
    int temp = 0;
    int data = 0;

    ReadFile(hFile, header.buffer, 0x1000, &temp, NULL);
    if (*(WORD*)header.buffer != 0x5a4d) {
        header.Infected = FALSE;
        return header;
    }
    header.pNtHeader = (char*)header.buffer + 0x3c;
    if (*((int*)header.pNtHeader) > 1000) {
        header.Infected = FALSE;
        return header;
    }
    header.pNtHeader = (char*)header.buffer + *(int*)header.pNtHeader;
    if ((((PIMAGE_NT_HEADERS)header.pNtHeader)->Signature) != 0x4550) {
        header.Infected = FALSE;
        return header;
    }
    header.pFileHeader = &((PIMAGE_NT_HEADERS)header.pNtHeader)->FileHeader;
    header.pOptionalHeader = &((PIMAGE_NT_HEADERS)header.pNtHeader)->OptionalHeader;
    header.NumberSections = ((PIMAGE_FILE_HEADER)header.pFileHeader)->NumberOfSections;
    header.pSectionHeader = (char*)header.pNtHeader +sizeof(IMAGE_NT_HEADERS);
    header.OEP = ((PIMAGE_OPTIONAL_HEADER)header.pOptionalHeader)->AddressOfEntryPoint;
    SetFilePointer(hFile, 
        RVAtoOffset(header.OEP, header.NumberSections, header.pSectionHeader), 
        0, 
        FILE_BEGIN);
    ReadFile(hFile, buf, sizeof(buf), &temp, NULL);
    if (SignatureCompare(buf, RAMNIT32, sizeof(RAMNIT32)) == FALSE) {
        header.Infected = FALSE;
        printf("aaa");
        return header;
    }
    header.Infected = TRUE;
    printf("%x %x\n", header.NumberSections, header.Infected);
    return header;
}

void CleanRamnit(char* filename) {
    HANDLE hFileInfec = INVALID_HANDLE_VALUE;
    DWORD org_oep = 0;
    int file_status = INFECTED;
    int temp = 0;
    int data = 0;
    void* pDataOffset = NULL;
    MyPEHeader myheader;
    SetFileAttributes(filename, FILE_ATTRIBUTE_NORMAL);
    do {
        hFileInfec = CreateFile(
            filename,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL   
        );
        myheader = HeaederCheck(hFileInfec);
        if (myheader.Infected == FALSE) {
            CloseHandle(hFileInfec);
            break;
        }
        file_status = INFECTED;
        SetFilePointer(hFileInfec, 
            0x771+RVAtoOffset(myheader.OEP, myheader.NumberSections, myheader.pSectionHeader), 
            0, 
            FILE_BEGIN);
        pDataOffset = (char*)myheader.pSectionHeader + sizeof(IMAGE_SECTION_HEADER)*(myheader.NumberSections-2);
        ReadFile(hFileInfec, &data, 4, &temp, NULL); // OEP
        org_oep = myheader.OEP - data;
        ((PIMAGE_OPTIONAL_HEADER)myheader.pOptionalHeader)->AddressOfEntryPoint = org_oep;
        data = ((PIMAGE_SECTION_HEADER)pDataOffset)->VirtualAddress;
        data += (((PIMAGE_SECTION_HEADER)pDataOffset)->Misc).VirtualSize;
        data = AlignSize(data, ((PIMAGE_OPTIONAL_HEADER)myheader.pOptionalHeader)->SectionAlignment);
        ((PIMAGE_FILE_HEADER)myheader.pFileHeader)->NumberOfSections = myheader.NumberSections-1;
        ((PIMAGE_OPTIONAL_HEADER)myheader.pOptionalHeader)->AddressOfEntryPoint = org_oep;
        ((PIMAGE_OPTIONAL_HEADER)myheader.pOptionalHeader)->SizeOfImage = data;

        pDataOffset = (char*)myheader.pSectionHeader + sizeof(IMAGE_SECTION_HEADER)*(myheader.NumberSections-1);
        SetFilePointer(hFileInfec, ((PIMAGE_SECTION_HEADER)pDataOffset)->PointerToRawData, 0, FILE_BEGIN);
        SetEndOfFile(hFileInfec);
        printf("%s W32.RAMNIT :))\n", filename);
    } while (file_status == INFECTED);
    return;
}
void CleanAngel(char* filename) {
    int NumberSections = 0;
    DWORD OEP = 0;
    void *pNtHeader;
    void *pOptionalHeader;
    void *pFileHeader;
    void *pSectionHeader;
    void *pLastSectionOffset;
    HANDLE hFileInfec = INVALID_HANDLE_VALUE;
    char buffer[0x1001] = "";
    int temp = 0;
    int data = 0;
    DWORD org_oep = 0;
    int file_status = INFECTED;
    SetFileAttributes(filename, FILE_ATTRIBUTE_NORMAL);
    do {
        hFileInfec = CreateFile(
            filename,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL   
        );
        ReadFile(hFileInfec, buffer, 0x1000, &temp, NULL);
        if (*(WORD*)buffer != 0x5a4d) {
            CloseHandle(hFileInfec); 
            break;
        }
        pNtHeader = (char*)buffer + 0x3c;
        if (*((int*)pNtHeader) > 1000) {
                CloseHandle(hFileInfec); 
                break;
        }
        pNtHeader = (char*)buffer + *(int*)pNtHeader;
        if ((((PIMAGE_NT_HEADERS)pNtHeader)->Signature) != 0x4550) {
                CloseHandle(hFileInfec); 
                break;
        }
        pFileHeader = &((PIMAGE_NT_HEADERS)pNtHeader)->FileHeader;
        pOptionalHeader = &((PIMAGE_NT_HEADERS)pNtHeader)->OptionalHeader;
        NumberSections = ((PIMAGE_FILE_HEADER)pFileHeader)->NumberOfSections;
        pSectionHeader = (char*)pNtHeader +sizeof(IMAGE_NT_HEADERS);
        OEP = ((PIMAGE_OPTIONAL_HEADER)pOptionalHeader)->AddressOfEntryPoint;
        SetFilePointer(hFileInfec, 
            RVAtoOffset(OEP, NumberSections, pSectionHeader), 
            0, 
            FILE_BEGIN);
        ReadFile(hFileInfec, &data, 4, &temp, NULL);
        if (data != 0x79037860) {
            file_status = CLEAN;
            CloseHandle(hFileInfec); 
            break;
        }
        file_status = INFECTED;
        SetFilePointer(hFileInfec, 
            0x1b+RVAtoOffset(OEP, NumberSections, pSectionHeader), 
            0, 
            FILE_BEGIN);
        ReadFile(hFileInfec, &data, 4, &temp, NULL); // OEP
        org_oep = data - ((PIMAGE_OPTIONAL_HEADER)pOptionalHeader)->ImageBase;
        ((PIMAGE_OPTIONAL_HEADER)pOptionalHeader)->AddressOfEntryPoint = org_oep;
        
        pLastSectionOffset = (char*)pSectionHeader + 
                            sizeof(IMAGE_SECTION_HEADER)*(NumberSections-1);
        ((PIMAGE_SECTION_HEADER)pLastSectionOffset)->Characteristics -= IMAGE_SCN_MEM_EXECUTE;
        data = AlignSize(((PIMAGE_SECTION_HEADER)pLastSectionOffset)->SizeOfRawData-0x118f,
            ((PIMAGE_OPTIONAL_HEADER)pOptionalHeader)->FileAlignment
            );
        ((PIMAGE_SECTION_HEADER)pLastSectionOffset)->SizeOfRawData = data;
        data = AlignSize((((PIMAGE_SECTION_HEADER)pLastSectionOffset)->Misc).VirtualSize-0x118f,
            ((PIMAGE_OPTIONAL_HEADER)pOptionalHeader)->SectionAlignment
            );
        (((PIMAGE_SECTION_HEADER)pLastSectionOffset)->Misc).VirtualSize = data;
        data += ((PIMAGE_SECTION_HEADER)pLastSectionOffset)->VirtualAddress;
        data = AlignSize(data, ((PIMAGE_OPTIONAL_HEADER)pOptionalHeader)->SectionAlignment);
        ((PIMAGE_OPTIONAL_HEADER)pOptionalHeader)->SizeOfImage = data;
        SetFilePointer(hFileInfec, 0, 0, FILE_BEGIN);
        WriteFile(hFileInfec, buffer, 0x1000, &temp, NULL);
        data = ((PIMAGE_SECTION_HEADER)pLastSectionOffset)->SizeOfRawData;
        data += ((PIMAGE_SECTION_HEADER)pLastSectionOffset)->PointerToRawData;
        SetFilePointer(hFileInfec, data, 0, FILE_BEGIN);
        SetEndOfFile(hFileInfec);
        CloseHandle(hFileInfec); 
    } while (file_status == INFECTED);
    printf("Complete: %s OK\n", filename);
    return;
}
void ScanDirectory(char* startDir) {
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
        if ((strncmp(".", wfd.cFileName, 1) != 0) && (strncmp("..", wfd.cFileName, 2) != 0) )
        {
            if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                sprintf(path, "%s\\%s", startDir, wfd.cFileName);
                ScanDirectory(path);
            }
            else {
                sprintf(path_exe, "%s\\%s", startDir, wfd.cFileName);
                CleanAngel(path_exe);
                /*do your work here -- mildly klugy comparison
                temp = *(int*)(wfd.cFileName + strlen(wfd.cFileName)-4);
                temp |= 0x20202000;
                if (strlen(wfd.cFileName) > 4) {
                    if (temp == 0x6578652e) {
                        sprintf(path_exe, "%s\\%s", startDir, wfd.cFileName);
                        //CleanAngel(path_exe);
                        CleanRamnit(path_exe);
                        SetFileAttributes(path_exe, wfd.dwFileAttributes);
                    }
                    if (temp == 0x6372732e) {
                        sprintf(path_exe, "%s\\%s", startDir, wfd.cFileName);
                        //CleanAngel(path_exe);
                        SetFileAttributes(path_exe, wfd.dwFileAttributes);
                    }
                }*/
            }
        }
    }  while (FindNextFile(hFind, &wfd)  != 0 );
    FindClose(hFind);
    return;
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
/*void ListProcessThreads( DWORD dwOwnerPID ) { 
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    HANDLE threads = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32;  
  // Take a snapshot of all running threads  
    hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ); 
    if( hThreadSnap == INVALID_HANDLE_VALUE ) 
        return;
  // Fill in the size of the structure before using it. 
    te32.dwSize = sizeof(THREADENTRY32 ); 

  // Retrieve information about the first thread,
  // and exit if unsuccessful
    if( !Thread32First( hThreadSnap, &te32 ) ) {
        CloseHandle( hThreadSnap );     // Must clean up the snapshot object!
        return;
    }
  // Now walk the thread list of the system,
  // and display information about each thread
  // associated with the specified process
  do { 
    if( te32.th32OwnerProcessID == dwOwnerPID ) {
        printf("%d\n", te32.th32ThreadID);
        threads = OpenThread(THREAD_TERMINATE, FALSE, te32.th32ThreadID);
        TerminateThread(threads, -1);
        //KillSpecialProc(te32.th32OwnerProcessID);
        //KillSpecialProc(dwOwnerPID);
        //break;
    }
  } while( Thread32Next(hThreadSnap, &te32 ) );
  CloseHandle( hThreadSnap );
  return;
}
*/
void KillAngelProc() {
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
        if(strncmp(pe32.szExeFile, "Serverx.exe", 11) == 0) {
            KillSpecialProc(pe32.th32ParentProcessID);
            KillSpecialProc(pe32.th32ProcessID);
            //ListProcessThreads(pe32.th32ProcessID);
            printf("%s, %s\n", "ByeBye Angel ", pe32.szExeFile );
            break;
        }
    } while(Process32Next( hProcessSnap, &pe32 ) );
    CloseHandle( hProcessSnap );
    return;
}
int main (int argc, char *argv[])
{
    char src[MAX_PATH] = "";
    HKEY hKey;
    /* Kill Angel running */
    
    while (OpenMutex(SYNCHRONIZE, FALSE, "Angry Angel v3.0") != NULL) {
        KillAngelProc();
        OpenMutex(SYNCHRONIZE, FALSE, "Angry Angel v3.0");
        if (GetLastError() != ERROR_FILE_NOT_FOUND) {
            break;
        }
    }
    RegOpenKeyEx (HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
    RegDeleteValue(hKey, "Serverx");
    /* Clean Infected file */
    printf("\nUsage: %s [FOLDER_NAME]\n", argv[0]);
    if (argv[1] == NULL) {
        printf("\nEnter folder to clean: ");
        fgets(src, MAX_PATH, stdin);
        src[strlen(src)-1] = '\0';
    }
    else {
        strcpy(src, argv[1]);
    }
    ScanDirectory(src);
    printf("\n%s\n", "OK");
    getchar();
    return 0;
}