/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	protect.h

Abstract:

	Protected processes list interface.

	Last change 06.02.13

--*/

#ifndef _SHPROTECT_
#define _SHPROTECT_

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#define _JMPTO(x) goto x
#define MAX_PROTECTED_PROCESSES 256

typedef struct _PROTECTEDENTRY {
	HANDLE hProcess;
	HANDLE ProcessId;
} PROTECTEDENTRY, *PPROTECTEDENTRY;

VOID PsCreateList(
	 VOID
	 );

VOID PsFreeList(
	VOID
	);

BOOL IsProtectedProcess(
	 PCLIENT_ID ClientId
	 );

#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* _SHPROTECT_ */