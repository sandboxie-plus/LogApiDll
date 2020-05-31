/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	logger.c

Abstract:

	Logger subsystem.

	Last change 25.02.13

--*/

#include "global.h"

VOID PushToLogA(
	LPCSTR lpBuffer,
	ULONG_PTR uptrSize, //buffer size, not string len
	DWORD dwFlags
	)
{
	PTLS pTls;

	pTls = GetTls();
	if ( pTls == NULL ) 
		return;

	if (pTls->msgflag == FALSE)
		return;

	if (( uptrSize == 0 ) || ( lpBuffer == NULL )) 
		return;

	SendLog((PVOID)lpBuffer, uptrSize, dwFlags, FALSE);
}


VOID PushToLogW(
	LPWSTR lpBuffer,
	ULONG_PTR uptrSize,  //buffer size, not string len
	DWORD dwFlags
	)
{
	PTLS pTls;

	pTls = GetTls();
	if ( pTls == NULL ) 
		return;

	if (pTls->msgflag == FALSE)
		return;

	if (( uptrSize == 0 ) || ( lpBuffer == NULL )) 
		return;

	SendLog((PVOID)lpBuffer, uptrSize, dwFlags, TRUE);
}

#ifndef ServerPipeName
VOID SendLog(
	PVOID Buffer,
	ULONG_PTR uptrSize,  //buffer size, not string len
	DWORD dwFlags,
	BOOL IsUnicode
	)
{
	COPYDATASTRUCT cdata;
	CHAR* Log = NULL;
	INT i;
	DWORD MaximumStaticAllowedLength;
	DWORD BracketSize;

	CHAR tmpBuf[LOGBUFFERSIZEEXTRA];
	BOOL IsLocalBuf = FALSE;

	LPWSTR ustr = (LPWSTR)Buffer;
	LPCSTR astr = (LPCSTR)Buffer;

	/* recalculate bracket size if they are change */
	BracketSize = 3;
	MaximumStaticAllowedLength = (LOGBUFFERSIZEEXTRA - MAX_PATH) - sizeof(CHAR) - BracketSize;

	__try {
		if ( uptrSize < MaximumStaticAllowedLength ) {
			RtlSecureZeroMemory(tmpBuf, sizeof(tmpBuf));
			Log = (CHAR*)&tmpBuf;
			IsLocalBuf = TRUE;
		} else {
			Log = (PCHAR)mmalloc(uptrSize + align(uptrSize, PAGE_SIZE));
		}

		if ( Log == NULL )
			__leave;

		if ( IsUnicode ) {
			i = (INT)_strlenW(ustr);
			WideCharToMultiByte(CP_ACP, 0, ustr, i, Log, i, 0, 0);
		} else {
			_strcpyA(Log, astr);
		}

		switch ( dwFlags ) {
		/* append sandboxed application exename */
		case LOG_NORMAL:
			_strcatA(Log, OpenBracketExA);
			_strcatA(Log, shctx.szLogApp);
			_strcatA(Log, CloseBracketExA);
			break;
		default:
			break;
		}
		if ( shctx.hwndServer != NULL ) {
			cdata.cbData = (INT)_strlenA(Log);
			cdata.lpData = (PVOID)Log;
			cdata.dwData = 3;
			SendMessageA(shctx.hwndServer, WM_COPYDATA, (WPARAM)0, (LPARAM)&cdata);		
		}
	} __finally {
		if ( IsLocalBuf == FALSE ) {
			if ( Log != NULL )
				mmfree(Log);
		}
	}
}
#else

VOID SendLog(
	PVOID Buffer,
	ULONG_PTR uptrSize,  //buffer size, not string len
	DWORD dwFlags,
	BOOL IsUnicode
	)
{
	CHAR* Log = NULL;
	INT i;
	DWORD MaximumStaticAllowedLength;
	DWORD BracketSize;

	CHAR tmpBuf[LOGBUFFERSIZEEXTRA];
	BOOL IsLocalBuf = FALSE;

	LPWSTR ustr = (LPWSTR)Buffer;
	LPCSTR astr = (LPCSTR)Buffer;

	//PTLS Tls = GetTls();

	/* recalculate bracket size if they are change */
	BracketSize = 3;
	MaximumStaticAllowedLength = (LOGBUFFERSIZEEXTRA - MAX_PATH) - sizeof(CHAR) - BracketSize;

	__try {
		if (uptrSize < MaximumStaticAllowedLength) {
			RtlSecureZeroMemory(tmpBuf, sizeof(tmpBuf));
			Log = (CHAR*)&tmpBuf;
			IsLocalBuf = TRUE;
		}
		else {
			Log = (PCHAR)mmalloc(uptrSize + align(uptrSize, PAGE_SIZE));
		}

		if (Log == NULL)
			__leave;

		if (IsUnicode) {
			i = (INT)_strlenW(ustr);
			WideCharToMultiByte(CP_ACP, 0, ustr, i, Log, i, 0, 0);
		}
		else {
			_strcpyA(Log, astr);
		}

		switch (dwFlags) {
			/* append sandboxed application exename */
		case LOG_NORMAL:
			_strcatA(Log, OpenBracketExA);
			_strcatA(Log, shctx.szLogApp);
			_strcatA(Log, CloseBracketExA);
			break;
		default:
			break;
		}

		if (shctx.hServerPipe != NULL) 
		{
			EnterSpinLock(&shctx.lLock);

			for (DWORD Sent = 0; Sent < _strlenA(Log) + 1;)
			{
				DWORD dwNumberOfBytesWritten = 0;
				WriteFile(shctx.hServerPipe, Log + Sent, _strlenA(Log + Sent) + 1, &dwNumberOfBytesWritten, NULL);
				Sent += dwNumberOfBytesWritten;
			}

			LeaveSpinLock(&shctx.lLock);
		}
	}
	__finally {
		if (IsLocalBuf == FALSE) {
			if (Log != NULL)
				mmfree(Log);
		}
	}
}
#endif