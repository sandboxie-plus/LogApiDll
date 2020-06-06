/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	protect.c

Abstract:

	Protected processes list implementation.

	Last change 25.02.13

--*/

#include "global.h"

PROTECTEDENTRY PsProcessList[MAX_PROTECTED_PROCESSES];

CRITICAL_SECTION PsListLock;

BOOL PsIsInList(
	HANDLE ProcessId
	)
{
	BOOL bResult;
	INT ListIndex;
	DWORD dwRet;

	EnterCriticalSection(&PsListLock);

	bResult = FALSE;

	for ( ListIndex=0; ListIndex<MAX_PROTECTED_PROCESSES; ListIndex+=1 ) {

		if ( PsProcessList[ListIndex].ProcessId == 0 ) 
			continue;

		if ( PsProcessList[ListIndex].ProcessId == ProcessId ) {
			
			bResult = TRUE;

			if ( PsProcessList[ListIndex].hProcess != NULL ) {
				dwRet = WaitForSingleObject(PsProcessList[ListIndex].hProcess, 0);
				if ( dwRet == WAIT_TIMEOUT ) {
					bResult = TRUE;	
				} else {
					NtClose(PsProcessList[ListIndex].hProcess);
					PsProcessList[ListIndex].hProcess = NULL;
					PsProcessList[ListIndex].ProcessId = NULL;
					bResult = FALSE;
				}
			}

			break;
		}
	}

	LeaveCriticalSection(&PsListLock);
	return bResult;
}

VOID PsPrintList(
	VOID
	)
{
	INT ListIndex;
	CHAR t[100];

	for ( ListIndex=0; ListIndex<MAX_PROTECTED_PROCESSES; ListIndex+=1 ) {
		t[0] = 0;
		_WARNING_OFF(4305);
		wsprintfA(t, "PsProcessList[%u]=%u", ListIndex, (DWORD)PsProcessList[ListIndex].ProcessId); 
		_WARNING_ON(4305);
		OutputDebugStringA(t);
	}
}

BOOL PsAddToList(
	HANDLE ProcessId,
	INT ListIndex
	)
{
	HANDLE hProcess; 
	NTSTATUS Status;
	OBJECT_ATTRIBUTES attr;
	CLIENT_ID cid;

	if ( ListIndex >= MAX_PROTECTED_PROCESSES )
		return FALSE;

	/* save process id */
	PsProcessList[ListIndex].ProcessId = ProcessId;

	hProcess = NULL;
	cid.UniqueProcess = ProcessId;
	cid.UniqueThread = NULL;
	InitializeObjectAttributes(&attr, NULL, 0, NULL, NULL);
	Status = pNtOpenProcess(&hProcess, SYNCHRONIZE, &attr, &cid);
	if ( NT_SUCCESS(Status) ) {
		/* save process handle */
		PsProcessList[ListIndex].hProcess = hProcess;
	} 

	return TRUE;
}

BOOL PsInsertToList(
	HANDLE ProcessId
	)
{
	BOOL bResult;
	INT ListIndex;

	EnterCriticalSection(&PsListLock);

	bResult = FALSE;

	for ( ListIndex=0; ListIndex<MAX_PROTECTED_PROCESSES; ListIndex+=1 ) {
		if (( PsProcessList[ListIndex].ProcessId == NULL ) && ( PsProcessList[ListIndex].hProcess == NULL) ) {
			bResult = PsAddToList(ProcessId, ListIndex);
			if ( bResult ) break;
		}
	}

	LeaveCriticalSection(&PsListLock);

	return bResult;
}

VOID PsFreeList(
	VOID
	)
{
	INT ListIndex;

	for ( ListIndex=0; ListIndex<MAX_PROTECTED_PROCESSES; ListIndex+=1 ) {
		if ( PsProcessList[ListIndex].hProcess != NULL ) {
			NtClose(PsProcessList[ListIndex].hProcess);
			PsProcessList[ListIndex].hProcess = NULL;
		}
	}
	DeleteCriticalSection(&PsListLock);
}

#pragma warning (disable: 4127)
VOID PsCreateList(
	 VOID
	 )
{
	PCWSTR pImageName;
	PSYSTEM_PROCESSES_INFORMATION ProcessInfo = NULL;
	HANDLE ProcessId = NULL;
	INT ListIndex = 0;

	InitializeCriticalSection(&PsListLock);

	__try {

		ProcessInfo = (PSYSTEM_PROCESSES_INFORMATION)AllocateInfoBuffer(SystemProcessInformation, NULL);
		if ( ProcessInfo == NULL ) {
			__leave;
		}

		while ( TRUE ) {
			
			pImageName = ProcessInfo->ImageName.Buffer;
			if ( (pImageName == NULL) || (ProcessInfo->ImageName.Length == 0) ) {
				_JMPTO(Next);
			}

			if ( IsSandboxieProcessW(pImageName) == FALSE ) {
				_JMPTO(Next);
			}

			ProcessId = ProcessInfo->UniqueProcessId;
			if ( ProcessId == 0 ) {
				_JMPTO(Next);
			}

			if ( !PsIsInList(ProcessId) ) {
				if ( PsAddToList(ProcessId, ListIndex) ) {
					ListIndex += 1;
					if ( ListIndex >= MAX_PROTECTED_PROCESSES )
						break;
				}
			}
					
Next:
			if (ProcessInfo->NextEntryDelta == 0) 
				break;
			
			ProcessInfo = (PSYSTEM_PROCESSES_INFORMATION)(((LPBYTE)ProcessInfo) + ProcessInfo->NextEntryDelta);
		}

	} __finally {
		if ( ProcessInfo != NULL) { 
			mmfree(ProcessInfo);
		}
	}
}
#pragma warning (default: 4127)

BOOL IsProtectedProcess(
	 PCLIENT_ID ClientId
	 )
{
	NTSTATUS Status;
	BOOL bResult = FALSE;
	HANDLE hProcess = NULL;

	OBJECT_ATTRIBUTES attr;
	WCHAR tBuff[LOGBUFFERSIZE];

	if ( !ARGUMENT_PRESENT(ClientId)) {
		return FALSE;
	}

	__try {

		bResult = PsIsInList(ClientId->UniqueProcess);

		if ( bResult == FALSE ) {
			InitializeObjectAttributes(&attr, NULL, 0, NULL, NULL);
			Status = pNtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &attr, ClientId);
			if (!NT_SUCCESS(Status)) {								
				PsInsertToList(ClientId->UniqueProcess);
				bResult = TRUE;
			} else {
				RtlSecureZeroMemory(tBuff, sizeof(tBuff));
				Status = QueryProcessNameByProcessHandle(hProcess, tBuff, MAX_PATH * 2);
				if (NT_SUCCESS(Status)) {
					ExtractFileNameW_S(tBuff, tBuff, MAX_PATH);
					if ( IsSandboxieProcessW(tBuff) ) {				
						PsInsertToList(ClientId->UniqueProcess);
						bResult = TRUE;
					}
				}
				NtClose(hProcess);
			}
		}

	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
	return bResult;
}
