/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	hooks.h

Abstract:

	Hook install interfaces.

	Last change 05.02.13

--*/

#ifndef _SHHOOKS_
#define _SHHOOKS_

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#define ENDCALL(x) goto x

PVOID HookCode(
	HMODULE hLibrary,
	LPSTR RoutineName,
	PVOID DetourHandler,
	PVOID DetourRoutine //<- ordinal case
	);

VOID InstallHooks(
	VOID
	);

VOID InstallHooksCallback(
	LPWSTR lpLibraryName
	);

VOID HookNTDLL(
	VOID
	);

VOID HookAdvapi32(
	VOID
	);

VOID HookUser32(
	VOID
	);

VOID HookWs2_32(
	VOID
	);

VOID HookUrlmon(
	VOID
	);

VOID HookWininet(
	VOID
	);

VOID HookNetapi32(
	VOID
	);

VOID HookMpr(
	VOID
	);

VOID HookPsapi(
	VOID
	);

VOID HookRasapi32(
	VOID
	);

VOID HookGdi32(
	VOID
	);

VOID HookSrclient(
	VOID
	);

VOID HookShell32(
	VOID
	);

VOID HookSfc_os(
	VOID
	);

VOID HookKernel32(
	VOID
	);

VOID HookOle32(
	VOID
	);

VOID HookWinscard(
	VOID
	);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* _SHHOOKS_ */