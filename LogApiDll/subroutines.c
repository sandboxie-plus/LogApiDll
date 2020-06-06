/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	subroutines.c

Abstract:

	Subroutines implementation.

	Last change 25.02.13

--*/

#include "global.h"

#define MAX_SNDBOX_PROCESSES 9
WCHAR *SboxProcessesW[MAX_SNDBOX_PROCESSES] = {
	L"BSA.EXE",
	L"sbiectrl.exe",
	L"sbiesvc.exe",
	L"sandboxiedcomlaunch.exe", 
	L"sandboxiecrypto.exe",
	L"sandboxiebits.exe",
	L"sandboxiewuau.exe",
	L"SandboxieRpcSs.exe", 
	L"start.exe"
};

BOOL IsSandboxieProcessW(
	LPCWSTR lpProcessName
	)
{
	INT i;

	if ( ARGUMENT_PRESENT(lpProcessName) ) {
		for (i = 0; i < MAX_SNDBOX_PROCESSES; i++) {
			if ( _strcmpiW(SboxProcessesW[i], lpProcessName) == 0 ) 
				return TRUE;
		}
	}
	return FALSE;
}

TLS *GetTls(
	VOID
	)

/*++

Routine Description:

    This function returns internal tls stored structure 
	or initializes it if it absent.

Arguments:

    None.


Return Value:

    Pointer to Tls structure or NULL in case of out of memory.

--*/

{
    PTLS pTls = (PTLS)TlsGetValue(shctx.dwTlsIndex);
    if ( pTls == NULL ) {     
		pTls = (PTLS)mmalloc( sizeof(TLS) );
		if ( pTls != NULL ) {	
			pTls->msgflag = TRUE;
			pTls->showcomparision = FALSE;
			pTls->ourcall = FALSE;
		    TlsSetValue(shctx.dwTlsIndex, pTls);
		}
    }
    return pTls;
}

VOID FreeTls(
	VOID
	)
{
	PTLS pTls = (PTLS)TlsGetValue(shctx.dwTlsIndex);
	if ( pTls != NULL ) {
		mmfree(pTls);
		pTls = NULL;
	}
}

DWORD GetProcessIdByHandle(
	HANDLE hProcess
	)

/*++

Routine Description:

    Windows API GetProcessId() equivalent. GetProcessId() maybe unavailable on earlier versions of Windows XP.

Arguments:

    hProcess - Handle of process to retrieve it Id.


Notes:
	
	x64 Windows threats ProcessId as ULONG_PTR value, however GetProcessId() always casts it to DWORD.
	So we do the same.


Return Value:

    Id of process or zero in case of error.

--*/

{
	NTSTATUS Status;
	PROCESS_BASIC_INFORMATION pbi;

	if ( pNtQueryInformationProcess == NULL )
		return (DWORD)0;

	Status = pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
	if (NT_SUCCESS(Status)) {
		return (DWORD)pbi.UniqueProcessId;
	}
	return (DWORD)0;
}

DWORD GetThreadIdByHandle(
	HANDLE hThread
	)

/*++

Routine Description:

    Windows API GetThreadId() equivalent. GetThreadId() maybe unavailable on earlier versions of Windows XP.

Arguments:

    hProcess - Handle of process to retrieve it Id.


Notes:
	
	x64 Windows threats ThreadId as ULONG_PTR value, however GetThreadId() always casts it to DWORD.
	So we do the same.


Return Value:

    Id of process or zero in case of error.

--*/

{
	NTSTATUS Status;
	THREAD_BASIC_INFORMATION tbi;

	Status = NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(THREAD_BASIC_INFORMATION), NULL);
	if (NT_SUCCESS(Status)) {
		_WARNING_OFF(4305);
		return (DWORD)tbi.ClientId.UniqueThread;
		_WARNING_ON(4305);
	}
	return (DWORD)0;
}

BOOL QueryProcessName(
	HANDLE ProcessHandle,
	PWSTR Buffer,
	ULONG BufferSize,
	PDWORD pdwProcessId
	)

/*++

Routine Description:

    This function returns process name and process id 
	by given process handle.

Arguments:

    ProcessHandle - Handle of process to retrieve it name and id.

	Buffer - Where store process name, must be allocated before call.

	BufferSize - Size of input buffer in bytes.

	pdwProcessId - Optional parameter to receive process id.


Return Value:

    TRUE on success.

--*/

{
	NTSTATUS Status;
	DWORD dwProcessId = 0;
	HANDLE hDuplicate = NULL;
	BOOL bResult = FALSE;

	//duplicate handle with required rights
	Status = NtDuplicateObject(NtCurrentProcess(), ProcessHandle, NtCurrentProcess(), &hDuplicate,
				PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, 0);
	if ( NT_SUCCESS(Status)) {						

		dwProcessId = GetProcessIdByHandle(hDuplicate);
		if (ARGUMENT_PRESENT(pdwProcessId)) *pdwProcessId = dwProcessId;

		Status = QueryProcessNameByProcessHandle(hDuplicate, Buffer, BufferSize);
		if (NT_SUCCESS(Status)) {
			bResult = TRUE;
		} else {
			//query error
			bResult = FALSE;
		}
		NtClose(hDuplicate);

	} else {
		//cannot duplicate handle
		if (ARGUMENT_PRESENT(pdwProcessId)) *pdwProcessId = 0;
		bResult = FALSE;
	}
	return bResult;
}

NTSTATUS QueryProcessNameByProcessId(
	HANDLE ProcessId,
	PWSTR Buffer,
	ULONG BufferSize
	)

/*++

Routine Description:

    This function returns process name and process id 
	by given process handle.

Arguments:

    ProcessId - Id of process to query name.

	Buffer - Where store process name, must be allocated before call.

	BufferSize - Size of input buffer in bytes.


Return Value:

    STATUS_SUCCESS on success.

--*/

{
	NTSTATUS Status;
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES attr;
	CLIENT_ID cid;
	PWSTR ProcessImageBuf = NULL;
	PUNICODE_STRING DynamicString = NULL;

	cid.UniqueProcess = ProcessId;
	cid.UniqueThread = (HANDLE)0;
	InitializeObjectAttributes(&attr, NULL, 0, NULL, NULL);

	Status = STATUS_UNSUCCESSFUL;

	if ( pNtOpenProcess == NULL )
		return Status;

	if ( pNtQueryInformationProcess == NULL )
		return Status;

	__try {
		ProcessImageBuf = (PWSTR)mmalloc(BufferSize);
		if ( !ProcessImageBuf )
			__leave;

		Status = pNtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &attr, &cid);
		if (!NT_SUCCESS(Status)) {
			__leave;
		}

		Status = pNtQueryInformationProcess(hProcess, ProcessImageFileName, ProcessImageBuf, BufferSize, NULL);
		if (NT_SUCCESS(Status)) {
			DynamicString = (PUNICODE_STRING)ProcessImageBuf;
			if ( (DynamicString->Buffer != NULL)  && (DynamicString->Length > 0) )  {
				_strncpyW(Buffer, BufferSize / sizeof(wchar_t), DynamicString->Buffer, BufferSize / sizeof(wchar_t));
			} else {
				//returned string empty
				Status = STATUS_UNSUCCESSFUL;
			}
		} 

	} __finally {
		if ( ProcessImageBuf ) mmfree(ProcessImageBuf);
		if ( hProcess != NULL ) NtClose(hProcess);
	}
	return Status;
}

NTSTATUS QueryProcessNameByProcessHandle(
	HANDLE hProcess,
	PWSTR Buffer,
	ULONG BufferSize
	)

/*++

Routine Description:

    This function returns process name and process id 
	by given process handle.

Arguments:

    hProcess - Handle of process to query name.

	Buffer - Where store process name, must be allocated before call.

	BufferSize - Size of input buffer in bytes.


Return Value:

    STATUS_SUCCESS on success.

--*/

{
	NTSTATUS Status;
	HANDLE ProcessId = NULL;
	PWSTR ProcessImageBuf = NULL;
	PUNICODE_STRING DynamicString = NULL;

	Status = STATUS_UNSUCCESSFUL;

	if ( pNtQueryInformationProcess == NULL )
		return Status;

	__try {

		ProcessImageBuf = (PWSTR)mmalloc(BufferSize);
		if ( !ProcessImageBuf )
			__leave;

		//first try to query with existing handle
		Status = pNtQueryInformationProcess(hProcess, ProcessImageFileName, ProcessImageBuf, BufferSize, NULL);
		if ( NT_SUCCESS(Status) ) {
			DynamicString = (PUNICODE_STRING)ProcessImageBuf;
			if (( DynamicString->Buffer != NULL ) && (DynamicString->Length > 0) ) {
				_strncpyW(Buffer, BufferSize / sizeof(wchar_t), DynamicString->Buffer, BufferSize / sizeof(wchar_t));
			} else {
				Status = STATUS_UNSUCCESSFUL;
			}
			__leave;

		} else {

			//existing handle rights not enough, try to query using reopen process
			_WARNING_OFF(4306);
			ProcessId = (HANDLE)GetProcessIdByHandle(hProcess);
			_WARNING_ON(4306);
			if ( ProcessId == NULL ) {
				Status = STATUS_ACCESS_DENIED;
				__leave;
			}
			Status = QueryProcessNameByProcessId(ProcessId, Buffer, BufferSize);
		}

	} __finally {
		if ( ProcessImageBuf ) 
			mmfree(ProcessImageBuf);
	}
	return Status;
}

PVOID mmalloc(
	IN SIZE_T Length
	)
{
	PVOID BaseAddress = NULL;

	if ( pNtAllocateVirtualMemory == NULL )
		return NULL;

	if ( Length > 0 ) {
		if (NT_SUCCESS(pNtAllocateVirtualMemory(
			NtCurrentProcess(), &BaseAddress,
			0, &Length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
				RtlSecureZeroMemory(BaseAddress, Length);
		}
	}
	return BaseAddress;
}

VOID mmfree(
	IN PVOID BaseAddress
	)
{
	SIZE_T FreeSize = 0;

	if ( ARGUMENT_PRESENT(BaseAddress) ) {
		NtFreeVirtualMemory(
			NtCurrentProcess(),
			&BaseAddress,
			&FreeSize,
			MEM_RELEASE);
	}
}

INT CheckNtName(
	PWSTR Name
	)
{
	__try {

		if ( ARGUMENT_PRESENT(Name) ) {

			if (Name[0] == L'\\' &&
				Name[1] == L'?' &&
				Name[2] == L'?' &&
				Name[3] == L'\\') 
			
			return 4;
		}

	} __except (EXCEPTION_EXECUTE_HANDLER) {

		return 0;
	}
	return 0;
}

BOOL LogSystemProcess(
	DWORD dwProcessId,
	PWSTR Buffer
	)
{
	if ( dwProcessId == shctx.dwSystemProcessId ) {
		ultostrW(dwProcessId, Buffer);
		return TRUE;
	}
	if ( dwProcessId == 0 ) {
		_strcpyW(Buffer, L"0");
		return TRUE;
	}
	return FALSE;
}

VOID LogAsCall(
	PCWSTR CallName,
	ULONG LogFlag
	)
{
	WCHAR szLog[LOGBUFFERSIZESMALL];

	RtlSecureZeroMemory(szLog, sizeof(szLog));

	if ( ARGUMENT_PRESENT(CallName) ) {
		_strcpyW(szLog, CallName);
	} else {
		_strcpyW(szLog, NullStrW); 
	}
	PushToLogW(szLog, LOGBUFFERSIZESMALL, LogFlag);
}

VOID LogAsCallA(
	PCSTR CallName,
	ULONG LogFlag
	)
{
	CHAR szLog[LOGBUFFERSIZESMALL];

	RtlSecureZeroMemory(szLog, sizeof(szLog));

	if ( ARGUMENT_PRESENT(CallName) ) {
		_strcpyA(szLog, CallName);
	} else {
		_strcpyA(szLog, NullStrA); 
	}
	PushToLogA(szLog, LOGBUFFERSIZESMALL, LogFlag);
}

NTSTATUS QueryLoaderEntryForDllHandle(
	PVOID DllHandle,
	PLDR_DATA_TABLE_ENTRY *ReturnEntry
	)
{
	NTSTATUS Status;
	PLIST_ENTRY Head, Next;
	PLDR_DATA_TABLE_ENTRY Entry;

	if (!ARGUMENT_PRESENT(ReturnEntry))
		return STATUS_INVALID_PARAMETER;

	RtlEnterCriticalSection( (PRTL_CRITICAL_SECTION)NtCurrentPeb()->LoaderLock);

	Head = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
	Next = Head->Flink;

	Status = STATUS_NOT_FOUND;

	while ( Next != Head ) {
		Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if ( Entry->DllBase == (PVOID)DllHandle ) {
			*ReturnEntry = Entry;
			Status = STATUS_SUCCESS;
			break;
		}
		Next = Next->Flink;
	}
	RtlLeaveCriticalSection( (PRTL_CRITICAL_SECTION)NtCurrentPeb()->LoaderLock);
	
	return Status;
}

BOOL IsProcessRunning(
	HANDLE ProcessId
	)
{
	HANDLE hProcess; 
	OBJECT_ATTRIBUTES attr;
	CLIENT_ID cid;
	NTSTATUS Status;

	DWORD dwRet = WAIT_FAILED;
	
	cid.UniqueProcess = ProcessId;
	cid.UniqueThread = (HANDLE)0;
	InitializeObjectAttributes(&attr, NULL, 0, NULL, NULL);
	hProcess = NULL;

	Status = pNtOpenProcess(&hProcess, SYNCHRONIZE, &attr, &cid);
	if ( NT_SUCCESS(Status) ) { 
		dwRet = WaitForSingleObject(hProcess, 0);
		NtClose(hProcess);
	}
	return (dwRet == WAIT_TIMEOUT);
}

PVOID AllocateInfoBuffer(
	IN SYSTEM_INFORMATION_CLASS InfoClass, 
	PULONG ReturnLength
	)
{
	PVOID		pBuffer = NULL;
	ULONG		uSize   = PAGE_SIZE;
	NTSTATUS	Status;
	ULONG       memIO;

	if ( pNtQuerySystemInformation == NULL )
		return NULL;

	do {

		pBuffer = mmalloc(uSize);
		if (pBuffer != NULL) {
			Status = pNtQuerySystemInformation(InfoClass, pBuffer, uSize, &memIO);
		} 
		else return NULL;	

		if (Status == STATUS_INFO_LENGTH_MISMATCH) {
			mmfree(pBuffer);
			uSize *= 2;
		}

	} while (Status == STATUS_INFO_LENGTH_MISMATCH);

	if (NT_SUCCESS(Status)) {

		if ( ARGUMENT_PRESENT(ReturnLength) ) 
			*ReturnLength = uSize;
		
		return pBuffer;
	}

	if (pBuffer) mmfree(pBuffer);
	return NULL;
}

VOID FindExplorerProcessId(
	VOID
	)
{	
	PSYSTEM_PROCESSES_INFORMATION ProcessList = NULL;

	__try {
		ProcessList = (PSYSTEM_PROCESSES_INFORMATION)AllocateInfoBuffer(SystemProcessInformation, NULL);
		if ( ProcessList == NULL )
			__leave;

		for (; ; ) {
			if ( ProcessList->ImageName.Buffer != NULL ) {
				if (_strcmpiW(ProcessList->ImageName.Buffer, L"explorer.exe") == 0) {
					_WARNING_OFF(4305);
					shctx.dwExplorerProcessId = (DWORD)ProcessList->UniqueProcessId;
					_WARNING_ON(4305);
					break;
				}
			}
			if (ProcessList->NextEntryDelta == 0) break;
			ProcessList = (PSYSTEM_PROCESSES_INFORMATION)(((LPBYTE)ProcessList) + ProcessList->NextEntryDelta);
			if ( ProcessList == NULL ) break;
		}
	} __finally {
		if ( ProcessList != NULL) mmfree(ProcessList);
	}
}

BOOL QueryKeyName(
	HKEY hKey,
	PVOID Buffer,
	ULONG BufferSize,
	BOOL IsUnicodeCall
	)
{
	POBJECT_NAME_INFORMATION pObjName;
	NTSTATUS Status;
	ULONG ReturnLength;
	BOOL bResult;
	ULONG len;

	LPSTR StrA = NULL;
	LPWSTR StrW = NULL;

	pObjName = NULL;
	ReturnLength = 0;
	bResult = FALSE;

	if ( IsUnicodeCall ) {
		StrW = (LPWSTR)Buffer; 
	} else {
		StrA = (LPSTR)Buffer;
	}

	__try {

		NtQueryObject(hKey, ObjectNameInformation, NULL, ReturnLength, &ReturnLength);

		pObjName = (POBJECT_NAME_INFORMATION)mmalloc(ReturnLength);
		if ( pObjName == NULL )
			__leave;

		Status = NtQueryObject(hKey, ObjectNameInformation, pObjName, ReturnLength, NULL);
		if (NT_SUCCESS(Status)) {

			if ( (pObjName->Name.Buffer != NULL) && (pObjName->Name.Length > 0) ) {			

				bResult = TRUE;

				len = (ULONG)_strlenW(pObjName->Name.Buffer);
				if (len > BufferSize) len = BufferSize; 
				if ( IsUnicodeCall ) {
					_strncpyW(StrW, BufferSize, pObjName->Name.Buffer, BufferSize);
				} else {
					WideCharToMultiByte(CP_ACP, 0, pObjName->Name.Buffer, len, StrA, len, 0, 0);
				}		
			}
		}
	} __finally {
		if (pObjName != NULL) mmfree(pObjName);
	}
	return bResult;
}

ULONG GetModuleSize(
	PVOID DllHandle
	)
{
	ULONG SizeOfImage;
	PLIST_ENTRY Head, Next;
	PLDR_DATA_TABLE_ENTRY Entry;

	SizeOfImage = 0;
	if (!ARGUMENT_PRESENT(DllHandle)) {
		return SizeOfImage;
	}

	RtlEnterCriticalSection( (PRTL_CRITICAL_SECTION)NtCurrentPeb()->LoaderLock);

	Head = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
	Next = Head->Flink;

	while ( Next != Head ) {
		Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if ( Entry->DllBase == (PVOID)DllHandle ) {			
			SizeOfImage = Entry->SizeOfImage;
			break;
		}
		Next = Next->Flink;
	}

	RtlLeaveCriticalSection( (PRTL_CRITICAL_SECTION)NtCurrentPeb()->LoaderLock);
	
	return SizeOfImage;
}

VOID EnterSpinLock(volatile LONG* isLocked)
{
	__int64 spinCount = 0;
	while (InterlockedCompareExchange(isLocked, TRUE, FALSE) != FALSE)
	{
		if (spinCount++ > 50)
			Sleep(1);
	}
}

VOID LeaveSpinLock(volatile LONG* isLocked)
{
	InterlockedExchange(isLocked, FALSE);
}

wchar_t *ExtractSufixW_S(
	const wchar_t *f,
	const wchar_t s,
	wchar_t* buf,
	unsigned int sz
	)
{
	wchar_t *p = (wchar_t *)f;
	unsigned int l;

	if ( f == 0 )
		return 0;

	if ( sz == 0 )
		return 0;

	__try {

		while ( *f != (wchar_t)0 )
		{
			if ( *f == s )
				p = (wchar_t *)f+1;
			f++;
		}
		if ( buf != 0 )	{

			l = (unsigned int)_strlenW(p);
			if ( l < sz )
				_strcpyW(buf, p);

		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {

		return NULL;
	}
	return p;
}