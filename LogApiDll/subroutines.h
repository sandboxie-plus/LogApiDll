/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	subroutines.h

Abstract:

	Subroutines interface, macroses and types.

	Last change 05.02.13

--*/

#ifndef _SHSUBROUTINES_
#define _SHSUBROUTINES_

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

DWORD GetProcessIdByHandle(
	HANDLE hProcess
	);

DWORD GetThreadIdByHandle(
	HANDLE hThread
	);

BOOL IsSandboxieProcessW(
	LPCWSTR lpProcessName
	);

TLS *GetTls(
	VOID
	);

VOID FreeTls(
	VOID
	);

PVOID mmalloc(
	IN SIZE_T Length
	);

VOID mmfree(
	IN PVOID BaseAddress
	);

NTSTATUS QueryProcessNameByProcessHandle(
	HANDLE hProcess,
	PWSTR Buffer,
	ULONG BufferSize
	);

NTSTATUS QueryProcessNameByProcessId(
	HANDLE ProcessId,
	PWSTR Buffer,
	ULONG BufferSize
	);

BOOL QueryProcessName(
	HANDLE ProcessHandle,
	PWSTR Buffer,
	ULONG BufferSize,
	PDWORD pdwProcessId
	);

NTSTATUS QueryLoaderEntryForDllHandle(
	PVOID DllHandle,
	PLDR_DATA_TABLE_ENTRY *ReturnEntry
	);

INT CheckNtName(
	PWSTR Name
	);

BOOL LogSystemProcess(
	DWORD dwProcessId,
	PWSTR Buffer
	);

VOID LogAsCall(
	PCWSTR CallName,
	ULONG LogFlag
	);

VOID LogAsCallA(
	PCSTR CallName,
	ULONG LogFlag
	);

BOOL IsProcessRunning(
	HANDLE ProcessId
	);

PVOID AllocateInfoBuffer(
	IN SYSTEM_INFORMATION_CLASS InfoClass, 
	PULONG ReturnLength
	);

VOID FindExplorerProcessId(
	VOID
	);

BOOL QueryKeyName(
	HKEY hKey,
	PVOID Buffer,
	ULONG BufferSize,
	BOOL IsUnicodeCall
	);

ULONG GetModuleSize(
	PVOID DllHandle
	);

VOID EnterSpinLock(
	volatile LONG* isLocked
	);

VOID LeaveSpinLock(
	volatile LONG* isLocked
	);

wchar_t *ExtractSufixW_S(
	const wchar_t *f,
	const wchar_t s,
	wchar_t* buf,
	unsigned int sz
	);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* _SHSUBROUTINES_ */