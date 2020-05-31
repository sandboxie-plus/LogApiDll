/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	mpr_hook.c

Abstract:

	Multiple Provider Router hook implementation.

	Last change 04.02.13

--*/

#include "..\global.h"
#include "mpr_hook.h"

PWNetOpenEnumA pWNetOpenEnumA = NULL;
PWNetOpenEnumW pWNetOpenEnumW = NULL;

DWORD WINAPI WNetOpenEnumHookA(
	DWORD dwScope, 
	DWORD dwType, 
	DWORD dwUsage, 
	LPNETRESOURCEA lpNetResource, 
	LPHANDLE lphEnum
	)
{
	PTLS Tls;
	
	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pWNetOpenEnumA(dwScope, dwType, dwUsage, lpNetResource, lphEnum);
		Tls->ourcall = TRUE;
	}

	//put api name and log
	LogAsCallA("WNetOpenEnum()", LOG_NORMAL); 

	if ( Tls ) Tls->ourcall = FALSE;
	return pWNetOpenEnumA(dwScope, dwType, dwUsage, lpNetResource, lphEnum);
}

DWORD WINAPI WNetOpenEnumHookW(
	DWORD dwScope, 
	DWORD dwType, 
	DWORD dwUsage, 
	LPNETRESOURCEW lpNetResource, 
	LPHANDLE lphEnum
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pWNetOpenEnumW(dwScope, dwType, dwUsage, lpNetResource, lphEnum);
		Tls->ourcall = TRUE;
	}

	//put api name and log
	LogAsCallA("WNetOpenEnum()", LOG_NORMAL); 

	if ( Tls ) Tls->ourcall = FALSE;
	return pWNetOpenEnumW(dwScope, dwType, dwUsage, lpNetResource, lphEnum);
}