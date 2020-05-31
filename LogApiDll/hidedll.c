/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	hidedll.c

Abstract:
	
	Dll hiding implementation.


	Last change 05.02.13

--*/

#include "global.h"

BOOL RandomizeDllName(
	PLDR_DATA_TABLE_ENTRY Entry
	)

/*++

Routine Description:

    Randomize dll name using GetTickCount() result.

Arguments:

    Entry - Loader entry describing dll.


Return Value:

    TRUE on success.

--*/


{
	WCHAR *FullDllName = NULL, *BaseDllName = NULL;
	DWORD t;
	
	__try {
		t = GetTickCount();
		FullDllName = (PWCHAR)mmalloc(PAGE_SIZE);
		if ( FullDllName ) {
			GetSystemDirectoryW(FullDllName, MAX_PATH);
			_strcatW(FullDllName, L"\\");
			BaseDllName = _strendW(FullDllName);

			utohexW((ULONG_PTR)t, _strendW(BaseDllName));
			_strcatW(BaseDllName, L".dll");
#ifdef _DEBUG
			OutputDebugString(FullDllName);
			OutputDebugString(BaseDllName);
#endif			
			RtlInitUnicodeString(&Entry->BaseDllName, BaseDllName);
			RtlInitUnicodeString(&Entry->FullDllName, FullDllName);
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {

		return FALSE;
	}
	return TRUE;
}

NTSTATUS HideDllFromPEB(
	PVOID DllHandle,
	DWORD dwFlags
	)

/*++

Routine Description:

    Removes dll from various PEB loader lists.

Arguments:

    DllHandle - dll to be removed.


Return Value:

    STATUS_SUCCESS if removal was done and STATUS_OBJECT_NAME_NOT_FOUND otherwise.

--*/

{
	BOOL bFound;
	PLIST_ENTRY Head, Next;
	PLDR_DATA_TABLE_ENTRY Entry;

	RtlEnterCriticalSection( (PRTL_CRITICAL_SECTION)NtCurrentPeb()->LoaderLock);

	Head = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
	Next = Head->Flink;
	bFound = FALSE;

	while ( Next != Head ) {

		Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if ( Entry->DllBase == DllHandle ) {

			bFound = TRUE;
			RemoveEntryList(&Entry->InLoadOrderLinks);
			RemoveEntryList(&Entry->InInitializationOrderLinks);
			RemoveEntryList(&Entry->HashLinks);

			switch ( dwFlags ) {

			case DLL_RENAME_MEMORYORDERENTRY:

				RandomizeDllName(Entry);
				break;

			default:
				RemoveEntryList(&Entry->InMemoryOrderLinks);
				break;
			}
		
		}
		Next = Next->Flink;
	}

	RtlLeaveCriticalSection( (PRTL_CRITICAL_SECTION)NtCurrentPeb()->LoaderLock);

	if ( bFound == FALSE ) {
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	return STATUS_SUCCESS;
}