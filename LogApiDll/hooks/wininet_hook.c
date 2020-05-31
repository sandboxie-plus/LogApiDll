/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	wininet_hook.c

Abstract:

	Windows Internet API hook implementation.

	Last change 04.02.13

--*/

#include "..\global.h"
#include "wininet_hook.h"

PInternetGetConnectedStateExW pInternetGetConnectedStateExW = NULL;
PInternetConnectA pInternetConnectA = NULL;
PInternetConnectW pInternetConnectW = NULL;
PInternetOpenA pInternetOpenA = NULL;
PInternetOpenW pInternetOpenW = NULL;
PInternetOpenUrlA pInternetOpenUrlA = NULL;
PInternetOpenUrlW pInternetOpenUrlW = NULL;
PInternetReadFile pInternetReadFile = NULL;
PInternetWriteFile pInternetWriteFile = NULL;
PDeleteUrlCacheEntryA pDeleteUrlCacheEntryA = NULL;
PDeleteUrlCacheEntryW pDeleteUrlCacheEntryW = NULL;
PInternetSetOptionA pInternetSetOptionA = NULL;
PInternetSetOptionW pInternetSetOptionW = NULL;
PFtpFindFirstFileA pFtpFindFirstFileA = NULL;
PFtpFindFirstFileW pFtpFindFirstFileW = NULL;
PFtpOpenFileA pFtpOpenFileA = NULL;
PFtpOpenFileW pFtpOpenFileW = NULL;
PFtpGetFileA pFtpGetFileA = NULL;
PFtpGetFileW pFtpGetFileW = NULL;
PFtpPutFileA pFtpPutFileA = NULL;
PFtpPutFileW pFtpPutFileW = NULL;
PHttpOpenRequestA pHttpOpenRequestA = NULL;
PHttpOpenRequestW pHttpOpenRequestW = NULL;
PHttpSendRequestA pHttpSendRequestA = NULL;
PHttpSendRequestW pHttpSendRequestW = NULL;
PHttpSendRequestExA pHttpSendRequestExA = NULL;
PHttpSendRequestExW pHttpSendRequestExW = NULL;

VOID LogWininetParamCallA(
	LPSTR ApiName,
	LPCSTR lpParam1,
	LPCSTR lpParam2,
	BOOL bSecondParam
	)
{
	CHAR tBuff[LOGBUFFERSIZELONG];

	if ( !ARGUMENT_PRESENT(ApiName) ) 
		return;

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyA(tBuff, ApiName); 
	_strcatA(tBuff, OpenBracketA);
	
	//put lpParam1
	if ( ARGUMENT_PRESENT(lpParam1) ) {
		__try {	
			_strncpyA(_strendA(tBuff), MAX_PATH * 2, lpParam1, MAX_PATH * 2);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatA(tBuff, WININET_EXCEPTION_A);
			utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
		}
	} else {
		_strcatA(tBuff, NullStrA);
	}

	//put lpParam2
	if ( bSecondParam == TRUE ) {	
		_strcatA(tBuff, CommaExA);
		if ( ARGUMENT_PRESENT(lpParam2) ) {
			__try {	
				_strncpyA(_strendA(tBuff), MAX_PATH * 2, lpParam2, MAX_PATH * 2);
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				_strcatA(tBuff, WININET_EXCEPTION_A);
				utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
			}
		} else {
			_strcatA(tBuff, NullStrA);
		}
	}

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);
}

VOID LogWininetParamCallW(
	LPWSTR ApiName,
	LPCWSTR lpParam1,
	LPCWSTR lpParam2,
	BOOL bSecondParam
	)
{
	WCHAR tBuff[LOGBUFFERSIZELONG];

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, ApiName);
	_strcatW(tBuff, OpenBracketW);

	//put lpParam
	if ( ARGUMENT_PRESENT(lpParam1) ) {
		__try {	
			_strncpyW(_strendW(tBuff), MAX_PATH * 2, lpParam1, MAX_PATH * 2);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, WININET_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put lpParam2
	if ( bSecondParam == TRUE ) {
		_strcatW(tBuff, CommaExW);
		if ( ARGUMENT_PRESENT(lpParam2) ) {
			__try {	
				_strncpyW(_strendW(tBuff), MAX_PATH * 2, lpParam2, MAX_PATH * 2);
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				_strcatW(tBuff, WININET_EXCEPTION);
				utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
			}
		} else {
			_strcatW(tBuff, NullStrW);
		}
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);
}

BOOL WINAPI InternetGetConnectedStateExHookW(
    LPDWORD lpdwFlags,
    LPWSTR lpszConnectionName,
    DWORD dwBufLen,
    DWORD dwReserved
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pInternetGetConnectedStateExW(lpdwFlags, lpszConnectionName, dwBufLen, dwReserved);
		Tls->ourcall = TRUE;
	}

	LogAsCall(L"InternetGetConnectedState()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pInternetGetConnectedStateExW(lpdwFlags, lpszConnectionName, dwBufLen, dwReserved);
}

HINTERNET WINAPI InternetConnectHookA(
	HINTERNET hInternet,
	LPCSTR lpszServerName,
	INTERNET_PORT nServerPort,
	LPCSTR lpszUserName,
	LPCSTR lpszPassword,
	DWORD dwService,
	DWORD dwFlags,
	DWORD_PTR dwContext
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pInternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
		Tls->ourcall = TRUE;
	}

	LogWininetParamCallA("InternetConnect", lpszServerName, NULL, FALSE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pInternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

HINTERNET WINAPI InternetConnectHookW(
    HINTERNET hInternet,
    LPCWSTR lpszServerName,
    INTERNET_PORT nServerPort,
    LPCWSTR lpszUserName,
    LPCWSTR lpszPassword,
    DWORD dwService,
    DWORD dwFlags,
    DWORD_PTR dwContext
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pInternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
		Tls->ourcall = TRUE;
	}

	LogWininetParamCallW(L"InternetConnect", lpszServerName, NULL, FALSE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pInternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

HINTERNET WINAPI InternetOpenHookA(
    LPCSTR lpszAgent,
    DWORD dwAccessType,
    LPCSTR lpszProxy,
    LPCSTR lpszProxyBypass,
    DWORD dwFlags
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pInternetOpenA(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
		Tls->ourcall = TRUE;
	}

	LogAsCallA("InternetOpen()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pInternetOpenA(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
}

HINTERNET WINAPI InternetOpenHookW(
    LPCWSTR lpszAgent,
    DWORD dwAccessType,
    LPCWSTR lpszProxy,
    LPCWSTR lpszProxyBypass,
    DWORD dwFlags
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pInternetOpenW(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
		Tls->ourcall = TRUE;
	}

	LogAsCall(L"InternetOpen()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pInternetOpenW(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
}

HINTERNET WINAPI InternetOpenUrlHookA(
    HINTERNET hInternet,
    LPCSTR lpszUrl,
    LPCSTR lpszHeaders,
    DWORD dwHeadersLength,
    DWORD dwFlags,
    DWORD_PTR dwContext
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pInternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
		Tls->ourcall = TRUE;
	}

	LogWininetParamCallA("InternetOpenUrl", lpszUrl, NULL, FALSE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pInternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
}

HINTERNET WINAPI InternetOpenUrlHookW(
    HINTERNET hInternet,
    LPCWSTR lpszUrl,
    LPCWSTR lpszHeaders,
    DWORD dwHeadersLength,
    DWORD dwFlags,
    DWORD_PTR dwContext
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pInternetOpenUrlW(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
		Tls->ourcall = TRUE;
	}

	LogWininetParamCallW(L"InternetOpenUrl", lpszUrl, NULL, FALSE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pInternetOpenUrlW(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
}

BOOL WINAPI InternetReadFileHook(
    HINTERNET hFile,
    LPVOID lpBuffer,
    DWORD dwNumberOfBytesToRead,
    LPDWORD lpdwNumberOfBytesRead
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pInternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
		Tls->ourcall = TRUE;
	}

	LogAsCall(L"InternetReadFile()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pInternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
}

BOOL WINAPI InternetWriteFileHook(
    HINTERNET hFile,
    LPCVOID lpBuffer,
    DWORD dwNumberOfBytesToWrite,
    LPDWORD lpdwNumberOfBytesWritten
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pInternetWriteFile(hFile, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);
		Tls->ourcall = TRUE;
	}

	LogAsCall(L"InternetWriteFile()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pInternetWriteFile(hFile, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);
}

BOOL WINAPI DeleteUrlCacheEntryHookA(
	LPCSTR lpszUrlName
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pDeleteUrlCacheEntryA(lpszUrlName);
		Tls->ourcall = TRUE;
	}

	LogWininetParamCallA("DeleteUrlCacheEntry", lpszUrlName, NULL, FALSE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pDeleteUrlCacheEntryA(lpszUrlName);
}

BOOL WINAPI DeleteUrlCacheEntryHookW(
	LPCWSTR lpszUrlName
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pDeleteUrlCacheEntryW(lpszUrlName);
		Tls->ourcall = TRUE;
	}

	LogWininetParamCallW(L"DeleteUrlCacheEntry", lpszUrlName, NULL, FALSE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pDeleteUrlCacheEntryW(lpszUrlName);
}

BOOL WINAPI InternetSetOptionHookA(
    HINTERNET hInternet,
    DWORD dwOption,
    LPVOID lpBuffer,
    DWORD dwBufferLength
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pInternetSetOptionA(hInternet, dwOption, lpBuffer, dwBufferLength);
		Tls->ourcall = TRUE;
	}

	LogAsCallA("InternetSetOption()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pInternetSetOptionA(hInternet, dwOption, lpBuffer, dwBufferLength);
}

BOOL WINAPI InternetSetOptionHookW(
    HINTERNET hInternet,
    DWORD dwOption,
    LPVOID lpBuffer,
    DWORD dwBufferLength
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pInternetSetOptionW(hInternet, dwOption, lpBuffer, dwBufferLength);
		Tls->ourcall = TRUE;
	}

	LogAsCall(L"InternetSetOption()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pInternetSetOptionW(hInternet, dwOption, lpBuffer, dwBufferLength);
}

HINTERNET WINAPI FtpFindFirstFileHookA(
    HINTERNET hConnect,
    LPCSTR lpszSearchFile,
    LPWIN32_FIND_DATAA lpFindFileData,
    DWORD dwFlags,
    DWORD_PTR dwContext
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pFtpFindFirstFileA(hConnect, lpszSearchFile, lpFindFileData, dwFlags, dwContext);
		Tls->ourcall = TRUE;
	}

	LogWininetParamCallA("FtpFindFirstFile", lpszSearchFile, NULL, FALSE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pFtpFindFirstFileA(hConnect, lpszSearchFile, lpFindFileData, dwFlags, dwContext);
}

HINTERNET WINAPI FtpFindFirstFileHookW(
    HINTERNET hConnect,
    LPCWSTR lpszSearchFile,
    LPWIN32_FIND_DATAW lpFindFileData,
    DWORD dwFlags,
    DWORD_PTR dwContext
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pFtpFindFirstFileW(hConnect, lpszSearchFile, lpFindFileData, dwFlags, dwContext);
		Tls->ourcall = TRUE;
	}

	LogWininetParamCallW(L"FtpFindFirstFile", lpszSearchFile, NULL, FALSE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pFtpFindFirstFileW(hConnect, lpszSearchFile, lpFindFileData, dwFlags, dwContext);
}

HINTERNET WINAPI FtpOpenFileHookA(
    HINTERNET hConnect,
    LPCSTR lpszFileName,
    DWORD dwAccess,
    DWORD dwFlags,
    DWORD_PTR dwContext
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pFtpOpenFileA(hConnect, lpszFileName, dwAccess, dwFlags, dwContext);
		Tls->ourcall = TRUE;
	}

	LogWininetParamCallA("FtpOpenFile", lpszFileName, NULL, FALSE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pFtpOpenFileA(hConnect, lpszFileName, dwAccess, dwFlags, dwContext);
}

HINTERNET WINAPI FtpOpenFileHookW(
    HINTERNET hConnect,
    LPCWSTR lpszFileName,
    DWORD dwAccess,
    DWORD dwFlags,
    DWORD_PTR dwContext
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pFtpOpenFileW(hConnect, lpszFileName, dwAccess, dwFlags, dwContext);
		Tls->ourcall = TRUE;
	}

	LogWininetParamCallW(L"FtpOpenFile", lpszFileName, NULL, FALSE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pFtpOpenFileW(hConnect, lpszFileName, dwAccess, dwFlags, dwContext);
}

BOOL WINAPI FtpGetFileHookA(
	HINTERNET hConnect,
	LPCSTR lpszRemoteFile,
	LPCSTR lpszNewFile,
	BOOL fFailIfExists,
	DWORD dwFlagsAndAttributes,
	DWORD dwFlags,
	DWORD_PTR dwContext
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pFtpGetFileA(hConnect, lpszRemoteFile, lpszNewFile, fFailIfExists, dwFlagsAndAttributes, dwFlags, dwContext);
		Tls->ourcall = TRUE;
	}

	LogWininetParamCallA("FtpGetFile", lpszRemoteFile, lpszNewFile, TRUE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pFtpGetFileA(hConnect, lpszRemoteFile, lpszNewFile, fFailIfExists, dwFlagsAndAttributes, dwFlags, dwContext);
}

BOOL WINAPI FtpGetFileHookW(
	HINTERNET hConnect,
	LPCWSTR lpszRemoteFile,
	LPCWSTR lpszNewFile,
	BOOL fFailIfExists,
	DWORD dwFlagsAndAttributes,
	DWORD dwFlags,
	DWORD_PTR dwContext
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pFtpGetFileW(hConnect, lpszRemoteFile, lpszNewFile, fFailIfExists, dwFlagsAndAttributes, dwFlags, dwContext);
		Tls->ourcall = TRUE;
	}

	LogWininetParamCallW(L"FtpGetFile", lpszRemoteFile, lpszNewFile, TRUE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pFtpGetFileW(hConnect, lpszRemoteFile, lpszNewFile, fFailIfExists, dwFlagsAndAttributes, dwFlags, dwContext);
}

BOOL WINAPI FtpPutFileHookA(
	HINTERNET hConnect,
	LPCSTR lpszLocalFile,
	LPCSTR lpszNewRemoteFile,
	DWORD dwFlags,
	DWORD_PTR dwContext
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pFtpPutFileA(hConnect, lpszLocalFile, lpszNewRemoteFile, dwFlags, dwContext);
		Tls->ourcall = TRUE;
	}

	LogWininetParamCallA("FtpPutFile", lpszLocalFile, lpszNewRemoteFile, TRUE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pFtpPutFileA(hConnect, lpszLocalFile, lpszNewRemoteFile, dwFlags, dwContext);
}

BOOL WINAPI FtpPutFileHookW(
	HINTERNET hConnect,
	LPCWSTR lpszLocalFile,
	LPCWSTR lpszNewRemoteFile,
	DWORD dwFlags,
	DWORD_PTR dwContext
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pFtpPutFileW(hConnect, lpszLocalFile, lpszNewRemoteFile, dwFlags, dwContext);
		Tls->ourcall = TRUE;
	}

	LogWininetParamCallW(L"FtpPutFile", lpszLocalFile, lpszNewRemoteFile, TRUE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pFtpPutFileW(hConnect, lpszLocalFile, lpszNewRemoteFile, dwFlags, dwContext);
}

HINTERNET WINAPI HttpOpenRequestHookA(
	HINTERNET hConnect,
	LPCSTR lpszVerb,
	LPCSTR lpszObjectName,
	LPCSTR lpszVersion,
	LPCSTR lpszReferrer,
	LPCSTR FAR * lplpszAcceptTypes,
	DWORD dwFlags,
	DWORD_PTR dwContext
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pHttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
		Tls->ourcall = TRUE;
	}

	LogWininetParamCallA("HttpOpenRequest", lpszObjectName, NULL, FALSE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pHttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, 
		lplpszAcceptTypes, dwFlags, dwContext);
}

HINTERNET WINAPI HttpOpenRequestHookW(
	HINTERNET hConnect,
	LPCWSTR lpszVerb,
	LPCWSTR lpszObjectName,
	LPCWSTR lpszVersion,
	LPCWSTR lpszReferrer,
	LPCWSTR FAR * lplpszAcceptTypes,
	DWORD dwFlags,
	DWORD_PTR dwContext
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pHttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
		Tls->ourcall = TRUE;
	}

	LogWininetParamCallW(L"HttpOpenRequest", lpszObjectName, NULL, FALSE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pHttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, 
		lplpszAcceptTypes, dwFlags, dwContext);
}

BOOL WINAPI HttpSendRequestHookA(
	HINTERNET hRequest,
	LPCSTR lpszHeaders,
	DWORD dwHeadersLength,
	LPVOID lpOptional,
	DWORD dwOptionalLength
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pHttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
		Tls->ourcall = TRUE;
	}

	LogAsCallA("HttpSendRequest()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pHttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}

BOOL WINAPI HttpSendRequestHookW(
	HINTERNET hRequest,
	LPCWSTR lpszHeaders,
	DWORD dwHeadersLength,
	LPVOID lpOptional,
	DWORD dwOptionalLength
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pHttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
		Tls->ourcall = TRUE;
	}

	LogAsCall(L"HttpSendRequest()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pHttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}

BOOL WINAPI HttpSendRequestExHookA(
	HINTERNET hRequest,
	LPINTERNET_BUFFERSA lpBuffersIn,
	LPINTERNET_BUFFERSA lpBuffersOut,
	DWORD dwFlags,
	DWORD_PTR dwContext
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pHttpSendRequestExA(hRequest, lpBuffersIn, lpBuffersOut, dwFlags, dwContext);
		Tls->ourcall = TRUE;
	}

	LogAsCallA("HttpSendRequestEx()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pHttpSendRequestExA(hRequest, lpBuffersIn, lpBuffersOut, dwFlags, dwContext);
}

BOOL WINAPI HttpSendRequestExHookW(
	HINTERNET hRequest,
	LPINTERNET_BUFFERSW lpBuffersIn,
	LPINTERNET_BUFFERSW lpBuffersOut,
	DWORD dwFlags,
	DWORD_PTR dwContext
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pHttpSendRequestExW(hRequest, lpBuffersIn, lpBuffersOut, dwFlags, dwContext);
		Tls->ourcall = TRUE;
	}

	LogAsCall(L"HttpSendRequestEx()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pHttpSendRequestExW(hRequest, lpBuffersIn, lpBuffersOut, dwFlags, dwContext);
}