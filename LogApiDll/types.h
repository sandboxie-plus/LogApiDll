/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	types.h

Abstract:

	Self defined types.

	Last change 07.02.13

--*/

#ifndef _SHTYPES_
#define _SHTYPES_

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#define MAXUSHORT   0xffff      // winnt
#define MAX_USTRING ( sizeof(WCHAR) * (MAXUSHORT/sizeof(WCHAR)) )
#define MAXDLLVER 50

#define LOGBUFFERSIZEEXTRA  16384
#define LOGBUFFERSIZELONG	4096
#define LOGBUFFERSIZE		MAX_PATH * 2
#define LOGBUFFERSIZESMALL	MAX_PATH

typedef struct _TLS {
	BOOL msgflag;
	BOOL showcomparision;
	BOOL ourcall; //multithreading
} TLS, *PTLS;

typedef struct _DLLENTRY {
	PVOID BaseAddress;
	ULONG SizeOfImage;
} DLLENTRY, *PDLLENTRY;

/* all internally used ntdll routines that are hooked must be declared here */

typedef NTSTATUS (NTAPI *PNtAllocateVirtualMemory)(
	HANDLE ProcessHandle, 
	PVOID *BaseAddress, 
	ULONG_PTR ZeroBits, 
	PSIZE_T RegionSize, 
	ULONG AllocationType, 
	ULONG Protect);

typedef NTSTATUS (NTAPI *PNtOpenProcess) (
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
	);

typedef NTSTATUS (NTAPI *PNtQuerySystemInformation) (
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS (NTAPI *PNtReadVirtualMemory) (
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesRead
	);

typedef NTSTATUS (NTAPI *PNtQueryInformationProcess) (
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

typedef VOID (WINAPI *POutputDebugStringA)(
	__in_opt LPCSTR lpOutputString
	);

typedef DWORD (WINAPI *PGetFinalPathNameByHandleW)(
	HANDLE hFile,
	LPWSTR lpszFilePath,
	DWORD cchFilePath,
	DWORD dwFlags
	);

typedef DWORD (WINAPI *PGetWindowThreadProcessId)(
	HWND hWnd,
	LPDWORD lpdwProcessId
	);

typedef BOOLEAN (WINAPI *PFNDllCallback) (
	PVOID Callback
	);

typedef PVOID (CALLBACK *PFNHook)(
	LPCSTR ApiName, 
	PVOID ApiFunc, 
	PVOID NewFunc
	);

typedef struct _SPYHOOKCONTEXT {

	BOOL SandboxieProcess;

	PFNHook	SboxHook; //sandboxie hook procedure
	PFNDllCallback SboxDllCallback; //sandboxie loader callback

	HWND hwndServer; // BSA server window
	HANDLE hServerPipe; // Log server pipe
	volatile long lLock;

	DWORD dwCurrentProcessId;
	DWORD dwExplorerProcessId;
	DWORD dwSystemProcessId;
	DWORD dwTlsIndex;
	ACCESS_MASK ProcessAllAccess;

	HMODULE hmNTDLL;
	HMODULE hmKernel32;
	HMODULE hmUser32;
	HMODULE hmGdi32;
	HMODULE hmAdvapi32;
	HMODULE hmShell32;
	HMODULE hmWs2_32;
	HMODULE hmUrlmon;
	HMODULE hmWininet;
	HMODULE hmNetapi32;
	HMODULE hmMpr;
	HMODULE hmPsapi;
	HMODULE hmRasapi32;
	HMODULE hmSrclient;
	HMODULE hmSfc_os;
	HMODULE hmOle32;
	HMODULE hmWinscard;

	DLLENTRY SbieDll;
	DLLENTRY ThisDll;	

	OSVERSIONINFOW osver;

	WCHAR szAppName[MAX_PATH]; //current sandboxed application full path + exename
	WCHAR szDllName[MAX_PATH]; //current api logger dll name
	CHAR szLogApp[MAX_PATH]; //ANSI app name for logger 

	CHAR szDLLVersion[MAXDLLVER]; //field used to store BSA related version string

} SHCONTEXT, *PSHCONTEXT;

#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* _SHTYPES_ */