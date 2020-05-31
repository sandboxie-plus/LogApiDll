/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	hidell.h

Abstract:

	Dll hiding interface.

	Last change 05.02.13

--*/

#ifndef _SHHIDEDLL_
#define _SHHIDEDLL_

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#define DLL_UNLINK_NORMAL			0
#define DLL_RENAME_MEMORYORDERENTRY 1

NTSTATUS HideDllFromPEB(
	PVOID DllHandle,
	DWORD dwFlags
	);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* _SHHIDEDLL_ */