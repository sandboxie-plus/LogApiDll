/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	mpr_hook.h

Abstract:

	Multiple Provider Router hook interface.

	Last change 14.01.13

--*/

#ifndef _SHMPRHOOK_
#define _SHMPRHOOK_

#include <Winnetwk.h>

typedef DWORD (WINAPI *PWNetOpenEnumA)(DWORD dwScope, DWORD dwType, DWORD dwUsage, LPNETRESOURCEA lpNetResource, LPHANDLE lphEnum);
typedef DWORD (WINAPI *PWNetOpenEnumW)(DWORD dwScope, DWORD dwType, DWORD dwUsage, LPNETRESOURCEW lpNetResource, LPHANDLE lphEnum);

extern PWNetOpenEnumA pWNetOpenEnumA;
extern PWNetOpenEnumW pWNetOpenEnumW;

DWORD WINAPI WNetOpenEnumHookA(
	DWORD dwScope, 
	DWORD dwType, 
	DWORD dwUsage, 
	LPNETRESOURCEA lpNetResource, 
	LPHANDLE lphEnum
	);

DWORD WINAPI WNetOpenEnumHookW(
	DWORD dwScope, 
	DWORD dwType, 
	DWORD dwUsage, 
	LPNETRESOURCEW lpNetResource, 
	LPHANDLE lphEnum
	);

#endif /* _SHMPRHOOK_ */