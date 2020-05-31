/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	urlmon_hook.c

Abstract:

	URL monikers API hook implementation.

	Last change 04.02.13

--*/

#include "..\global.h"
#include "urlmon_hook.h"

PURLDownloadToFileW pURLDownloadToFileW = NULL;
PURLDownloadToCacheFileW pURLDownloadToCacheFileW = NULL;
PURLOpenStreamW pURLOpenStreamW = NULL;
PURLOpenBlockingStreamW pURLOpenBlockingStreamW = NULL;

VOID LogUrlmonCall(
	LPWSTR ApiName,
	LPCWSTR szURL
	)
{
	WCHAR tBuff[LOGBUFFERSIZE];

	if (! ARGUMENT_PRESENT(ApiName))
		return;

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, ApiName);
	_strcatW(tBuff, OpenBracketW);

	//put szURL
	if ( ARGUMENT_PRESENT(szURL) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH, szURL, MAX_PATH);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, URLMON_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}
	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);
}

HRESULT WINAPI URLDownloadToFileHookW(
	LPUNKNOWN pCaller,
	LPCWSTR szURL,
	LPCWSTR szFileName,
	DWORD dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pURLDownloadToFileW(pCaller, szURL, szFileName, dwReserved, lpfnCB);
		}
		Tls->ourcall = TRUE;
	}

	LogUrlmonCall(L"URLDownloadToFile", szURL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pURLDownloadToFileW(pCaller, szURL, szFileName, dwReserved, lpfnCB);
}

HRESULT WINAPI URLDownloadToCacheFileHookW(
	LPUNKNOWN caller,
	LPCWSTR szURL,
	LPWSTR szFileName,
	DWORD dwBufLength,
	DWORD dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pURLDownloadToCacheFileW(caller, szURL, szFileName, dwBufLength, dwReserved, lpfnCB);
		}
		Tls->ourcall = TRUE;
	}

	LogUrlmonCall(L"URLDownloadToCache", szURL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pURLDownloadToCacheFileW(caller, szURL, szFileName, dwBufLength, dwReserved, lpfnCB);
}

HRESULT WINAPI URLOpenStreamHookW(
	LPUNKNOWN caller,
	LPCWSTR szURL,
	DWORD dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pURLOpenStreamW(caller, szURL, dwReserved, lpfnCB);
		}
		Tls->ourcall = TRUE;
	}

	LogUrlmonCall(L"URLOpenStream", szURL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pURLOpenStreamW(caller, szURL, dwReserved, lpfnCB);
}

HRESULT WINAPI URLOpenBlockingStreamHookW(
	LPUNKNOWN caller,
	LPCWSTR szURL,
	LPSTREAM* ppStream,
	DWORD dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pURLOpenBlockingStreamW(caller, szURL, ppStream, dwReserved, lpfnCB);
		}
		Tls->ourcall = TRUE;
	}

	LogUrlmonCall(L"URLOpenBlockingStream", szURL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pURLOpenBlockingStreamW(caller, szURL, ppStream, dwReserved, lpfnCB);
}