/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	gdi32_hook.c

Abstract:

	Windows GDI hook implementation.

	Last change 04.02.13

--*/

#include "..\global.h"
#include "gdi32_hook.h"

PCreateDCA pCreateDCA = NULL;
PCreateDCW pCreateDCW = NULL;
PBitBlt pBitBlt = NULL;

HDC WINAPI CreateDCHookA(
	LPCSTR pwszDriver, 
	LPCSTR pwszDevice, 
	LPCSTR pszPort, 
	CONST DEVMODEA * pdm
	)
{
	PTLS Tls;
	CHAR tBuff[LOGBUFFERSIZE];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pCreateDCA(pwszDriver, pwszDevice, pszPort, pdm);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));
	_strcpyA(tBuff, "CreateDC(");

	__try {
		//put pwszDriver
		if ( ARGUMENT_PRESENT(pwszDriver) ) {
			_strncpyA(_strendA(tBuff), MAX_PATH, pwszDriver, MAX_PATH);
		} else {
			_strcatA(tBuff, NullStrA);
		}
		_strcatA(tBuff, CommaA);
		
		//put pszDevice
		if ( ARGUMENT_PRESENT(pwszDevice) ) {
			_strncpyA(_strendA(tBuff), MAX_PATH, pwszDevice, MAX_PATH);
		} else {
			_strcatA(tBuff, NullStrA);
		}
		_strcatA(tBuff, CommaA);

		//put pszPort
		if ( ARGUMENT_PRESENT(pszPort) ) { /* pszPort is unused, still log it */
			_strncpyA(_strendA(tBuff), MAX_PATH, pszPort, MAX_PATH);
		} else {
			_strcatA(tBuff, NullStrA);
		}
		//put pdm
		_strcatA(tBuff, CommaA);
		utohexA((ULONG_PTR)pdm, _strendA(tBuff));
		_strcatA(tBuff, CloseBracketA);

	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatA(tBuff, GDI32_EXCEPTION_A);
		utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
	}
	PushToLogA(tBuff, LOGBUFFERSIZE, LOG_NORMAL);
	
	if ( Tls ) Tls->ourcall = FALSE;
	return pCreateDCA(pwszDriver, pwszDevice, pszPort, pdm);
}

HDC WINAPI CreateDCHookW(
	LPCWSTR pwszDriver,
	LPCWSTR pwszDevice, 
	LPCWSTR pszPort, 
	CONST DEVMODEW * pdm
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZE];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pCreateDCW(pwszDriver, pwszDevice, pszPort, pdm);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));
	_strcpyW(tBuff, L"CreateDC(");

	__try {
		
		//put pwszDriver
		if ( ARGUMENT_PRESENT(pwszDriver) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH, pwszDriver, MAX_PATH);
		} else {
			_strcatW(tBuff, NullStrW);
		}
		_strcatW(tBuff, CommaW);
		
		//put pwszDevice
		if ( ARGUMENT_PRESENT(pwszDevice) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH, pwszDevice, MAX_PATH);
		} else {
			_strcatW(tBuff, NullStrW);
		}
		_strcatW(tBuff, CommaW);

		//put pszPort
		if ( ARGUMENT_PRESENT(pszPort) ) { /* pszPort is unused, still log it */
			_strncpyW(_strendW(tBuff), MAX_PATH, pszPort, MAX_PATH);
		} else {
			_strcatW(tBuff, NullStrW);
		}

		//put pdm
		_strcatW(tBuff, CommaW);
		utohexW((ULONG_PTR)pdm, _strendW(tBuff));
		_strcatW(tBuff, CloseBracketW);

	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatW(tBuff, GDI32_EXCEPTION);
		utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
	}
	PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCreateDCW(pwszDriver, pwszDevice, pszPort, pdm);
}

BOOL WINAPI BitBltHook(
	HDC hdc, 
	int x, 
	int y, 
	int cx, 
	int cy, 
	HDC hdcSrc, 
	int x1, 
	int y1, 
	DWORD rop
	)
{
	PTLS Tls;
	CHAR tBuff[LOGBUFFERSIZESMALL];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pBitBlt(hdc, x, y, cx, cy, hdcSrc, x1, y1, rop);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	_strcpyA(tBuff, "BitBlt(");

	//put hdc
	utohexA((ULONG_PTR)hdc, _strendA(tBuff));
	_strcatA(tBuff, CommaExA);

	//put x
	ultostrA(x, _strendA(tBuff));
	_strcatA(tBuff, CommaExA);

	//put y
	ultostrA(y, _strendA(tBuff));
	_strcatA(tBuff, CommaExA);

	//put cx
	ultostrA(cx, _strendA(tBuff));
	_strcatA(tBuff, CommaExA);

	//put cy
	ultostrA(cy, _strendA(tBuff));
	_strcatA(tBuff, CommaExA);
	
	//put hdcSrc
	utohexA((ULONG_PTR)hdcSrc, _strendA(tBuff));
	_strcatA(tBuff, CommaExA);

	//put x1
	ultostrA(x1, _strendA(tBuff));
	_strcatA(tBuff, CommaExA);

	//put y1
	ultostrA(y1, _strendA(tBuff));
	_strcatA(tBuff, CommaExA);

	//put rop
	ultostrA(rop, _strendA(tBuff));
	_strcatA(tBuff, CloseBracketA);

	PushToLogA(tBuff, LOGBUFFERSIZESMALL, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pBitBlt(hdc, x, y, cx, cy, hdcSrc, x1, y1, rop);
}