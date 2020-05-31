/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	winscard_hook.c

Abstract:

	Smart Card API hook implementation.

	Last change 04.02.13

--*/

#include "..\global.h"
#include "winscard_hook.h"

PSCardListReadersA pSCardListReadersA = NULL;
PSCardListReadersW pSCardListReadersW = NULL;
PSCardEstablishContext pSCardEstablishContext = NULL;

LONG WINAPI SCardListReadersHookA(
    SCARDCONTEXT hContext,
    LPCSTR mszGroups,
    LPSTR mszReaders,
    LPDWORD pcchReaders
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pSCardListReadersA(hContext, mszGroups, mszReaders, pcchReaders);
		Tls->ourcall = TRUE;
	}

	LogAsCallA("SCardListReaders()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pSCardListReadersA(hContext, mszGroups, mszReaders, pcchReaders);
}

LONG WINAPI SCardListReadersHookW(
    SCARDCONTEXT hContext,
    LPCWSTR mszGroups,
    LPWSTR mszReaders,
    LPDWORD pcchReaders
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pSCardListReadersW(hContext, mszGroups, mszReaders, pcchReaders);
		Tls->ourcall = TRUE;
	}

	LogAsCallA("SCardListReaders()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pSCardListReadersW(hContext, mszGroups, mszReaders, pcchReaders);
}

LONG WINAPI SCardEstablishContextHook(
    DWORD dwScope,
    LPCVOID pvReserved1,
    LPCVOID pvReserved2,
    LPSCARDCONTEXT phContext
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pSCardEstablishContext(dwScope, pvReserved1, pvReserved2, phContext);
		Tls->ourcall = TRUE;
	}

	LogAsCallA("SCardEstablishContext()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pSCardEstablishContext(dwScope, pvReserved1, pvReserved2, phContext);
}