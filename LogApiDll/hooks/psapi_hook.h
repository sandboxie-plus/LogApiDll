/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	psapi_hook.h

Abstract:

	Process Status API hook interface.

	Last change 27.01.13

--*/

#ifndef _SHPSAPIHOOK_
#define _SHPSAPIHOOK_

typedef BOOL (WINAPI *PEnumProcesses) (
    DWORD * lpidProcess,
    DWORD cb,
    LPDWORD lpcbNeeded
    );

typedef BOOL (WINAPI *PEnumProcessModules)(
    HANDLE hProcess,
    HMODULE *lphModule,
    DWORD cb,
    LPDWORD lpcbNeeded
    );

typedef BOOL (WINAPI *PEnumProcessModulesEx)(
    HANDLE hProcess,
    HMODULE *lphModule,
    DWORD cb,
    LPDWORD lpcbNeeded,
    DWORD dwFilterFlag
    );

extern PEnumProcesses pEnumProcesses;
extern PEnumProcessModules pEnumProcessModules;
extern PEnumProcessModulesEx pEnumProcessModulesEx;

BOOL WINAPI EnumProcessesHook (
    DWORD * lpidProcess,
    DWORD cb,
    LPDWORD lpcbNeeded
    );

BOOL WINAPI EnumProcessModulesHook(
    HANDLE hProcess,
    HMODULE *lphModule,
    DWORD cb,
    LPDWORD lpcbNeeded
    );

BOOL WINAPI EnumProcessModulesExHook(
    HANDLE hProcess,
    HMODULE *lphModule,
    DWORD cb,
    LPDWORD lpcbNeeded,
    DWORD dwFilterFlag
    );

#endif /* _SHPSAPIHOOK_ */