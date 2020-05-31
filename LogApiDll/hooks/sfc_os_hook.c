/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	sfc_os_hook.c

Abstract:

	System File Checker hook implementation.

	Last change 04.02.13

--*/

#include "..\global.h"
#include "sfc_os_hook.h"

PSfcFileException pSfcFileOperation = NULL;

DWORD WINAPI SfcFileExceptionHook(
	HANDLE rpcHandle, 
	LPWSTR lpFileName, 
	DWORD dwFlag
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZE];
	
	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pSfcFileOperation(rpcHandle, lpFileName, dwFlag);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"SetSfcFileException(");

	//put lpFileName
	if ( ARGUMENT_PRESENT(lpFileName) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH, lpFileName, MAX_PATH);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, SFC_OS_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, EmptyStrW);
	}	

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pSfcFileOperation(rpcHandle, lpFileName, dwFlag);
}