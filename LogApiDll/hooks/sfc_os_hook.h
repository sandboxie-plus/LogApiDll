/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	sfc_os_hook.h

Abstract:

	System File Checker hook interface.

	Last change 19.01.13

--*/

#ifndef _SHSFCHOOK_
#define _SHSFCHOOK_

#define SFC_OS_EXCEPTION   L"sfc_os!exception 0x"

typedef DWORD (WINAPI *PSfcFileException)(HANDLE rpcHandle, PWCHAR lpFileName, DWORD dwFlag);

extern PSfcFileException pSfcFileOperation;

DWORD WINAPI SfcFileExceptionHook(
	HANDLE rpcHandle, 
	LPWSTR lpFileName, 
	DWORD dwFlag
	);

#endif /* _SHSFCHOOK_ */