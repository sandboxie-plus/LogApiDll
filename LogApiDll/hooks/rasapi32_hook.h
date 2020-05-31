/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	gdi32_hook.h

Abstract:

	RAS API hook interface.

	Last change 14.01.13

--*/

#ifndef _SHRASAPI32HOOK_
#define _SHRASAPI32HOOK_

#include <Ras.h>

typedef DWORD (WINAPI *PRasEnumEntriesA)(LPCSTR reserved, LPCSTR lpszPhonebook, LPRASENTRYNAMEA lprasentryname, LPDWORD lpcb, LPDWORD lpcEntries);
typedef DWORD (WINAPI *PRasEnumEntriesW)(LPCWSTR reserved, LPCWSTR lpszPhonebook, LPRASENTRYNAMEW lprasentryname, LPDWORD lpcb, LPDWORD lpcEntries);

extern PRasEnumEntriesA pRasEnumEntriesA;
extern PRasEnumEntriesW pRasEnumEntriesW;

DWORD WINAPI RasEnumEntriesHookA(
	LPCSTR reserved,
	LPCSTR lpszPhonebook, 
	LPRASENTRYNAMEA lprasentryname, 
	LPDWORD lpcb, 
	LPDWORD lpcEntries
	);

DWORD WINAPI RasEnumEntriesHookW(
	LPCWSTR reserved, 
	LPCWSTR lpszPhonebook, 
	LPRASENTRYNAMEW lprasentryname, 
	LPDWORD lpcb, 
	LPDWORD lpcEntries
	);

#endif /* _SHRASAPI32HOOK_ */