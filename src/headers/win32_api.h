#pragma once
#include <windows.h>
#include "syscalls.h"

#define OBJ_CASE_INSENSITIVE 0x00000040L


typedef NTSTATUS (WINAPI* _RtlSetCurrentTransaction) (PHANDLE);
typedef void (WINAPI* _RtlInitUnicodeString) (PUNICODE_STRING DestinationString, PCWSTR SourceString);

WINBASEAPI HANDLE   WINAPI  KERNEL32$CreateFileA (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI HANDLE   WINAPI  KERNEL32$CreateFileMappingA (HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
WINBASEAPI BOOL     WINAPI  KERNEL32$GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize);
WINBASEAPI LPVOID   WINAPI  KERNEL32$MapViewOfFile (HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
WINBASEAPI WINBOOL  WINAPI  KERNEL32$UnmapViewOfFile (LPCVOID lpBaseAddress);
WINBASEAPI WINBOOL  WINAPI  KERNEL32$WriteFile (HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
WINBASEAPI void*    WINAPI  MSVCRT$malloc(SIZE_T);
WINBASEAPI int      WINAPI  MSVCRT$rand();
WINBASEAPI void     WINAPI  MSVCRT$srand(int initial);
WINBASEAPI void     WINAPI  MSVCRT$sprintf(char*, char[], ...);
WINBASEAPI int      __cdecl MSVCRT$_snprintf(char* s, size_t n, const char* fmt, ...);
WINBASEAPI time_t   WINAPI  MSVCRT$time(time_t *time);