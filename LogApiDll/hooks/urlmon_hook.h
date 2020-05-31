/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	urlmon_hook.h

Abstract:

	URL monikers API hook interface.

	Last change 20.01.13

--*/

#ifndef _SHURLMONHOOK_
#define _SHURLMONHOOK_

#include <Urlmon.h>

#define URLMON_EXCEPTION   L" urlmon!exception 0x"

typedef HRESULT (WINAPI *PURLDownloadToFileW)(
	LPUNKNOWN pCaller,
	LPCWSTR szURL,
	LPCWSTR szFileName,
	DWORD dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
	);

typedef HRESULT (WINAPI *PURLDownloadToCacheFileW)(
	LPUNKNOWN caller,
	LPCWSTR szURL,
	LPWSTR szFileName,
	DWORD dwBufLength,
	DWORD dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
	);

typedef HRESULT (WINAPI *PURLOpenStreamW)(
	LPUNKNOWN caller,
	LPCWSTR szURL,
	DWORD dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
	);

typedef HRESULT (WINAPI *PURLOpenBlockingStreamW)(
	LPUNKNOWN caller,
	LPCWSTR szURL,
	LPSTREAM* ppStream,
	DWORD dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
	);

extern PURLDownloadToFileW pURLDownloadToFileW;
extern PURLDownloadToCacheFileW pURLDownloadToCacheFileW;
extern PURLOpenStreamW pURLOpenStreamW;
extern PURLOpenBlockingStreamW pURLOpenBlockingStreamW;

HRESULT WINAPI URLDownloadToFileHookW(
	LPUNKNOWN pCaller,
	LPCWSTR szURL,
	LPCWSTR szFileName,
	DWORD dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
	);

HRESULT WINAPI URLDownloadToCacheFileHookW(
	LPUNKNOWN caller,
	LPCWSTR szURL,
	LPWSTR szFileName,
	DWORD dwBufLength,
	DWORD dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
	);

HRESULT WINAPI URLOpenStreamHookW(
	LPUNKNOWN caller,
	LPCWSTR szURL,
	DWORD dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
	);

HRESULT WINAPI URLOpenBlockingStreamHookW(
	LPUNKNOWN caller,
	LPCWSTR szURL,
	LPSTREAM* ppStream,
	DWORD dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
	);

#endif /* _SHURLMONHOOK_ */