/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	wininet_hook.h

Abstract:

	Windows Internet API hook interface.

	Last change 23.01.13

--*/

#ifndef _SHWININETHOOK_
#define _SHWININETHOOK_

#include <Wininet.h>

#define WININET_EXCEPTION   L" wininet!exception 0x"
#define WININET_EXCEPTION_A " wininet!exception 0x"


typedef BOOL (WINAPI *PInternetGetConnectedStateExW)(
	LPDWORD lpdwFlags,
	LPWSTR lpszConnectionName,
	DWORD dwBufLen,
	DWORD dwReserved
	);

typedef HINTERNET (WINAPI *PInternetConnectA)(
	HINTERNET hInternet,
	LPCSTR lpszServerName,
	INTERNET_PORT nServerPort,
	LPCSTR lpszUserName,
	LPCSTR lpszPassword,
	DWORD dwService,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

typedef HINTERNET (WINAPI *PInternetConnectW)(
	HINTERNET hInternet,
	LPCWSTR lpszServerName,
	INTERNET_PORT nServerPort,
	LPCWSTR lpszUserName,
	LPCWSTR lpszPassword,
	DWORD dwService,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

typedef HINTERNET (WINAPI *PInternetOpenA)(
	LPCSTR lpszAgent,
	DWORD dwAccessType,
	LPCSTR lpszProxy,
	LPCSTR lpszProxyBypass,
	DWORD dwFlags
	);

typedef HINTERNET (WINAPI *PInternetOpenW)(
	LPCWSTR lpszAgent,
	DWORD dwAccessType,
	LPCWSTR lpszProxy,
	LPCWSTR lpszProxyBypass,
	DWORD dwFlags
	);

typedef HINTERNET (WINAPI *PInternetOpenUrlA)(
	HINTERNET hInternet,
	LPCSTR lpszUrl,
	LPCSTR lpszHeaders,
	DWORD dwHeadersLength,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

typedef HINTERNET (WINAPI *PInternetOpenUrlW)(
	HINTERNET hInternet,
	LPCWSTR lpszUrl,
	LPCWSTR lpszHeaders,
	DWORD dwHeadersLength,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

typedef BOOL (WINAPI *PInternetReadFile)(
	HINTERNET hFile,
	LPVOID lpBuffer,
	DWORD dwNumberOfBytesToRead,
	LPDWORD lpdwNumberOfBytesRead
	);

typedef BOOL (WINAPI *PInternetWriteFile)(
	HINTERNET hFile,
	LPCVOID lpBuffer,
	DWORD dwNumberOfBytesToWrite,
	LPDWORD lpdwNumberOfBytesWritten
	);

typedef BOOL (WINAPI *PDeleteUrlCacheEntryA)(
	LPCSTR lpszUrlName
	);

typedef BOOL (WINAPI *PDeleteUrlCacheEntryW)(
	LPCWSTR lpszUrlName
	);

typedef BOOL (WINAPI *PInternetSetOptionA)(
	HINTERNET hInternet,
	DWORD dwOption,
	LPVOID lpBuffer,
	DWORD dwBufferLength
	);

typedef BOOL (WINAPI *PInternetSetOptionW)(
	HINTERNET hInternet,
	DWORD dwOption,
	LPVOID lpBuffer,
	DWORD dwBufferLength
	);

typedef HINTERNET (WINAPI *PFtpFindFirstFileA)(
	HINTERNET hConnect,
	LPCSTR lpszSearchFile,
	LPWIN32_FIND_DATAA lpFindFileData,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

typedef HINTERNET (WINAPI *PFtpFindFirstFileW)(
	HINTERNET hConnect,
	LPCWSTR lpszSearchFile,
	LPWIN32_FIND_DATAW lpFindFileData,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

typedef HINTERNET (WINAPI *PFtpOpenFileA)(
	HINTERNET hConnect,
	LPCSTR lpszFileName,
	DWORD dwAccess,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

typedef HINTERNET (WINAPI *PFtpOpenFileW)(
	HINTERNET hConnect,
	LPCWSTR lpszFileName,
	DWORD dwAccess,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

typedef BOOL (WINAPI *PFtpGetFileA)(
	HINTERNET hConnect,
	LPCSTR lpszRemoteFile,
	LPCSTR lpszNewFile,
	BOOL fFailIfExists,
	DWORD dwFlagsAndAttributes,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

typedef BOOL (WINAPI *PFtpGetFileW)(
	HINTERNET hConnect,
	LPCWSTR lpszRemoteFile,
	LPCWSTR lpszNewFile,
	BOOL fFailIfExists,
	DWORD dwFlagsAndAttributes,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

typedef BOOL (WINAPI *PFtpPutFileA)(
	HINTERNET hConnect,
	LPCSTR lpszLocalFile,
	LPCSTR lpszNewRemoteFile,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

typedef BOOL (WINAPI *PFtpPutFileW)(
	HINTERNET hConnect,
	LPCWSTR lpszLocalFile,
	LPCWSTR lpszNewRemoteFile,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

typedef HINTERNET (WINAPI *PHttpOpenRequestA)(
    HINTERNET hConnect,
    LPCSTR lpszVerb,
    LPCSTR lpszObjectName,
    LPCSTR lpszVersion,
    LPCSTR lpszReferrer,
    LPCSTR FAR * lplpszAcceptTypes,
    DWORD dwFlags,
    DWORD_PTR dwContext
    );

typedef HINTERNET (WINAPI *PHttpOpenRequestW)(
    HINTERNET hConnect,
    LPCWSTR lpszVerb,
    LPCWSTR lpszObjectName,
    LPCWSTR lpszVersion,
    LPCWSTR lpszReferrer,
    LPCWSTR FAR * lplpszAcceptTypes,
    DWORD dwFlags,
    DWORD_PTR dwContext
    );

typedef BOOL (WINAPI *PHttpSendRequestA)(
    HINTERNET hRequest,
    LPCSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength
    );

typedef BOOL (WINAPI *PHttpSendRequestW)(
    HINTERNET hRequest,
    LPCWSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength
    );

typedef BOOL (WINAPI *PHttpSendRequestExA)(
    HINTERNET hRequest,
    LPINTERNET_BUFFERSA lpBuffersIn,
    LPINTERNET_BUFFERSA lpBuffersOut,
    DWORD dwFlags,
    DWORD_PTR dwContext
    );

typedef BOOL (WINAPI *PHttpSendRequestExW)(
    HINTERNET hRequest,
    LPINTERNET_BUFFERSW lpBuffersIn,
    LPINTERNET_BUFFERSW lpBuffersOut,
    DWORD dwFlags,
    DWORD_PTR dwContext
    );

extern PInternetGetConnectedStateExW pInternetGetConnectedStateExW;
extern PInternetConnectA pInternetConnectA;
extern PInternetConnectW pInternetConnectW;
extern PInternetOpenA pInternetOpenA;
extern PInternetOpenW pInternetOpenW;
extern PInternetOpenUrlA pInternetOpenUrlA;
extern PInternetOpenUrlW pInternetOpenUrlW;
extern PInternetReadFile pInternetReadFile;
extern PInternetWriteFile pInternetWriteFile;
extern PDeleteUrlCacheEntryA pDeleteUrlCacheEntryA;
extern PDeleteUrlCacheEntryW pDeleteUrlCacheEntryW;
extern PInternetSetOptionA pInternetSetOptionA;
extern PInternetSetOptionW pInternetSetOptionW;
extern PFtpFindFirstFileA pFtpFindFirstFileA;
extern PFtpFindFirstFileW pFtpFindFirstFileW;
extern PFtpOpenFileA pFtpOpenFileA;
extern PFtpOpenFileW pFtpOpenFileW;
extern PFtpGetFileA pFtpGetFileA;
extern PFtpGetFileW pFtpGetFileW;
extern PFtpPutFileA pFtpPutFileA;
extern PFtpPutFileW pFtpPutFileW;
extern PHttpOpenRequestA pHttpOpenRequestA;
extern PHttpOpenRequestW pHttpOpenRequestW;
extern PHttpSendRequestA pHttpSendRequestA;
extern PHttpSendRequestW pHttpSendRequestW;
extern PHttpSendRequestExA pHttpSendRequestExA;
extern PHttpSendRequestExW pHttpSendRequestExW;

BOOL WINAPI InternetGetConnectedStateExHookW(
	LPDWORD lpdwFlags,
	LPWSTR lpszConnectionName,
	DWORD dwBufLen,
	DWORD dwReserved
	);

HINTERNET WINAPI InternetConnectHookA(
	HINTERNET hInternet,
	LPCSTR lpszServerName,
	INTERNET_PORT nServerPort,
	LPCSTR lpszUserName,
	LPCSTR lpszPassword,
	DWORD dwService,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

HINTERNET WINAPI InternetConnectHookW(
	HINTERNET hInternet,
	LPCWSTR lpszServerName,
	INTERNET_PORT nServerPort,
	LPCWSTR lpszUserName,
	LPCWSTR lpszPassword,
	DWORD dwService,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

HINTERNET WINAPI InternetOpenHookA(
	LPCSTR lpszAgent,
	DWORD dwAccessType,
	LPCSTR lpszProxy,
	LPCSTR lpszProxyBypass,
	DWORD dwFlags
	);

HINTERNET WINAPI InternetOpenHookW(
	LPCWSTR lpszAgent,
	DWORD dwAccessType,
	LPCWSTR lpszProxy,
	LPCWSTR lpszProxyBypass,
	DWORD dwFlags
	);

HINTERNET WINAPI InternetOpenUrlHookA(
	HINTERNET hInternet,
	LPCSTR lpszUrl,
	LPCSTR lpszHeaders,
	DWORD dwHeadersLength,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

HINTERNET WINAPI InternetOpenUrlHookW(
	HINTERNET hInternet,
	LPCWSTR lpszUrl,
	LPCWSTR lpszHeaders,
	DWORD dwHeadersLength,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

BOOL WINAPI InternetReadFileHook(
	HINTERNET hFile,
	LPVOID lpBuffer,
	DWORD dwNumberOfBytesToRead,
	LPDWORD lpdwNumberOfBytesRead
	);

BOOL WINAPI InternetWriteFileHook(
	HINTERNET hFile,
	LPCVOID lpBuffer,
	DWORD dwNumberOfBytesToWrite,
	LPDWORD lpdwNumberOfBytesWritten
	);

BOOL WINAPI DeleteUrlCacheEntryHookA(
	LPCSTR lpszUrlName
	);

BOOL WINAPI DeleteUrlCacheEntryHookW(
	LPCWSTR lpszUrlName
	);

BOOL WINAPI InternetSetOptionHookA(
	HINTERNET hInternet,
	DWORD dwOption,
	LPVOID lpBuffer,
	DWORD dwBufferLength
	);

BOOL WINAPI InternetSetOptionHookW(
	HINTERNET hInternet,
	DWORD dwOption,
	LPVOID lpBuffer,
	DWORD dwBufferLength
	);

HINTERNET WINAPI FtpFindFirstFileHookA(
	HINTERNET hConnect,
	LPCSTR lpszSearchFile,
	LPWIN32_FIND_DATAA lpFindFileData,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

HINTERNET WINAPI FtpFindFirstFileHookW(
	HINTERNET hConnect,
	LPCWSTR lpszSearchFile,
	LPWIN32_FIND_DATAW lpFindFileData,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

HINTERNET WINAPI FtpOpenFileHookA(
	HINTERNET hConnect,
	LPCSTR lpszFileName,
	DWORD dwAccess,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

HINTERNET WINAPI FtpOpenFileHookW(
	HINTERNET hConnect,
	LPCWSTR lpszFileName,
	DWORD dwAccess,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

BOOL WINAPI FtpGetFileHookA(
	HINTERNET hConnect,
	LPCSTR lpszRemoteFile,
	LPCSTR lpszNewFile,
	BOOL fFailIfExists,
	DWORD dwFlagsAndAttributes,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

BOOL WINAPI FtpGetFileHookW(
	HINTERNET hConnect,
	LPCWSTR lpszRemoteFile,
	LPCWSTR lpszNewFile,
	BOOL fFailIfExists,
	DWORD dwFlagsAndAttributes,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

BOOL WINAPI FtpPutFileHookA(
	HINTERNET hConnect,
	LPCSTR lpszLocalFile,
	LPCSTR lpszNewRemoteFile,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

BOOL WINAPI FtpPutFileHookW(
	HINTERNET hConnect,
	LPCWSTR lpszLocalFile,
	LPCWSTR lpszNewRemoteFile,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

HINTERNET WINAPI HttpOpenRequestHookA(
	HINTERNET hConnect,
	LPCSTR lpszVerb,
	LPCSTR lpszObjectName,
	LPCSTR lpszVersion,
	LPCSTR lpszReferrer,
	LPCSTR FAR * lplpszAcceptTypes,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

HINTERNET WINAPI HttpOpenRequestHookW(
	HINTERNET hConnect,
	LPCWSTR lpszVerb,
	LPCWSTR lpszObjectName,
	LPCWSTR lpszVersion,
	LPCWSTR lpszReferrer,
	LPCWSTR FAR * lplpszAcceptTypes,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

BOOL WINAPI HttpSendRequestHookA(
    HINTERNET hRequest,
    LPCSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength
    );

BOOL WINAPI HttpSendRequestHookW(
    HINTERNET hRequest,
    LPCWSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength
    );

BOOL WINAPI HttpSendRequestExHookA(
    HINTERNET hRequest,
    LPINTERNET_BUFFERSA lpBuffersIn,
    LPINTERNET_BUFFERSA lpBuffersOut,
    DWORD dwFlags,
    DWORD_PTR dwContext
    );

BOOL WINAPI HttpSendRequestExHookW(
	HINTERNET hRequest,
	LPINTERNET_BUFFERSW lpBuffersIn,
	LPINTERNET_BUFFERSW lpBuffersOut,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

#endif /* _SHWININETHOOK_ */
