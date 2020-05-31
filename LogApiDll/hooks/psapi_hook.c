/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	psapi_hook.c

Abstract:

	Process Status API hook implementation.

	Last change 04.02.13

--*/

#include "..\global.h"
#include "psapi_hook.h"

PEnumProcesses pEnumProcesses = NULL;
PEnumProcessModules pEnumProcessModules = NULL;
PEnumProcessModulesEx pEnumProcessModulesEx = NULL;

BOOL WINAPI EnumProcessesHook(
    DWORD * lpidProcess,
    DWORD cb,
    LPDWORD lpcbNeeded
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			pEnumProcesses(lpidProcess, cb, lpcbNeeded);
		Tls->ourcall = TRUE;
	}

	//put api name and log
	LogAsCall(L"EnumProcesses()", LOG_NORMAL); 

	if ( Tls ) Tls->ourcall = FALSE;
	return pEnumProcesses(lpidProcess, cb, lpcbNeeded);
}

BOOL WINAPI EnumProcessModulesHook(
    HANDLE hProcess,
    HMODULE *lphModule,
    DWORD cb,
    LPDWORD lpcbNeeded
    )
 {
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pEnumProcessModules(hProcess, lphModule, cb, lpcbNeeded);
		Tls->ourcall = TRUE;
	}

	//put api name and log
	LogAsCall(L"EnumProcessModules()", LOG_NORMAL); 

	if ( Tls ) Tls->ourcall = FALSE;
	return pEnumProcessModules(hProcess, lphModule, cb, lpcbNeeded);
 }

BOOL WINAPI EnumProcessModulesExHook(
    HANDLE hProcess,
    HMODULE *lphModule,
    DWORD cb,
    LPDWORD lpcbNeeded,
    DWORD dwFilterFlag
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pEnumProcessModulesEx(hProcess, lphModule, cb, lpcbNeeded, dwFilterFlag);
		Tls->ourcall = TRUE;
	}

	//put api name and log
	LogAsCall(L"EnumProcessModulesEx()", LOG_NORMAL); 

	if ( Tls ) Tls->ourcall = FALSE;
	return pEnumProcessModulesEx(hProcess, lphModule, cb, lpcbNeeded, dwFilterFlag);
}