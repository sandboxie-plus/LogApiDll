/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	rasapi32_hook.c

Abstract:

	RAS API hook implementation.

	Last change 04.02.13

--*/

#include "..\global.h"
#include "rasapi32_hook.h"

PRasEnumEntriesA pRasEnumEntriesA = NULL;
PRasEnumEntriesW pRasEnumEntriesW = NULL;

DWORD WINAPI RasEnumEntriesHookA(
	LPCSTR reserved,
	LPCSTR lpszPhonebook, 
	LPRASENTRYNAMEA lprasentryname, 
	LPDWORD lpcb, 
	LPDWORD lpcEntries
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pRasEnumEntriesA(reserved, lpszPhonebook, lprasentryname, lpcb, lpcEntries);
		Tls->ourcall = TRUE;
	}

	//put api name and log
	LogAsCallA("RasEnumEntries()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pRasEnumEntriesA(reserved, lpszPhonebook, lprasentryname, lpcb, lpcEntries);
}

DWORD WINAPI RasEnumEntriesHookW(
	LPCWSTR reserved, 
	LPCWSTR lpszPhonebook, 
	LPRASENTRYNAMEW lprasentryname, 
	LPDWORD lpcb, 
	LPDWORD lpcEntries
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pRasEnumEntriesW(reserved, lpszPhonebook, lprasentryname, lpcb, lpcEntries);
		Tls->ourcall = TRUE;
	}

	//put api name and log
	LogAsCall(L"RasEnumEntries()", LOG_NORMAL);
	
	if ( Tls ) Tls->ourcall = FALSE;
	return pRasEnumEntriesW(reserved, lpszPhonebook, lprasentryname, lpcb, lpcEntries);
}