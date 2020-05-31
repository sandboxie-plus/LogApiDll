/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	winscard_hook.h

Abstract:

	Smart Card API hook interface.

	Last change 04.02.13

--*/

#ifndef _SHWINSCARDHOOK_
#define _SHWINSCARDHOOK_

#include <Winscard.h>

typedef LONG (WINAPI *PSCardListReadersA)(
    SCARDCONTEXT hContext,
    LPCSTR mszGroups,
    LPSTR mszReaders,
    LPDWORD pcchReaders
	);

typedef LONG (WINAPI *PSCardListReadersW)(
    SCARDCONTEXT hContext,
    LPCWSTR mszGroups,
    LPWSTR mszReaders,
    LPDWORD pcchReaders
	);

typedef LONG (WINAPI *PSCardEstablishContext)(
    DWORD dwScope,
    LPCVOID pvReserved1,
    LPCVOID pvReserved2,
    LPSCARDCONTEXT phContext
	);

extern PSCardListReadersA pSCardListReadersA;
extern PSCardListReadersW pSCardListReadersW;
extern PSCardEstablishContext pSCardEstablishContext;

LONG WINAPI SCardListReadersHookA(
    SCARDCONTEXT hContext,
    LPCSTR mszGroups,
    LPSTR mszReaders,
    LPDWORD pcchReaders
	);

LONG WINAPI SCardListReadersHookW(
    SCARDCONTEXT hContext,
    LPCWSTR mszGroups,
    LPWSTR mszReaders,
    LPDWORD pcchReaders
	);

LONG WINAPI SCardEstablishContextHook(
    DWORD dwScope,
    LPCVOID pvReserved1,
    LPCVOID pvReserved2,
    LPSCARDCONTEXT phContext
	);

#endif /* _SHWINSCARDHOOK_ */ 