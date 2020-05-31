/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	gdi32_hook.h

Abstract:

	Windows GDI hook interface.

	Last change 19.01.13

--*/

#ifndef _SHGDI32HOOK_
#define _SHGDI32HOOK_

#define GDI32_EXCEPTION   L" gdi32!exception 0x"
#define GDI32_EXCEPTION_A " gdi32!exception 0x"

typedef HDC (WINAPI *PCreateDCA)(LPCSTR pwszDriver, LPCSTR pwszDevice, LPCSTR pszPort, CONST DEVMODEA * pdm);
typedef HDC (WINAPI *PCreateDCW)(LPCWSTR pwszDriver, LPCWSTR pwszDevice, LPCWSTR pszPort, CONST DEVMODEW * pdm);
typedef BOOL (WINAPI *PBitBlt)(HDC hdc, int x, int y, int cx, int cy, HDC hdcSrc, int x1, int y1, DWORD rop);

extern PCreateDCA pCreateDCA;
extern PCreateDCW pCreateDCW;
extern PBitBlt pBitBlt;

HDC WINAPI CreateDCHookA(
	LPCSTR pwszDriver, 
	LPCSTR pwszDevice, 
	LPCSTR pszPort, 
	CONST DEVMODEA * pdm
	);

HDC WINAPI CreateDCHookW(
	LPCWSTR pwszDriver,
	LPCWSTR pwszDevice, 
	LPCWSTR pszPort, 
	CONST DEVMODEW * pdm
	);

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
	);

#endif /* _SHGDI32HOOK_ */