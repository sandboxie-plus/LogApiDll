/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	srclient_hook.h

Abstract:

	System Restore hook interface.

	Last change 19.01.13

--*/

#ifndef _SHSRESTOREHOOK_
#define _SHSRESTOREHOOK_

#include <SRRestorePtAPI.h>

#define SRCLIENT_EXCEPTION   L" srclient!exception 0x"
#define SRCLIENT_EXCEPTION_A   " srclient!exception 0x"

typedef DWORD (WINAPI *PSRRemoveRestorePoint)(DWORD dwRPNum);
typedef BOOL (WINAPI *PSRSetRestorePointA)(PRESTOREPOINTINFOA pRestorePtSpec, PSTATEMGRSTATUS pSMgrStatus);
typedef BOOL (WINAPI *PSRSetRestorePointW)(PRESTOREPOINTINFOW pRestorePtSpec, PSTATEMGRSTATUS pSMgrStatus);

extern PSRRemoveRestorePoint pSRRemoveRestorePoint;
extern PSRSetRestorePointA pSRSetRestorePointA;
extern PSRSetRestorePointW pSRSetRestorePointW;

DWORD WINAPI SRRemoveRestorePointHook(
	DWORD dwRPNum
	);

BOOL WINAPI SRSetRestorePointHookA(
	PRESTOREPOINTINFOA pRestorePtSpec, 
	PSTATEMGRSTATUS pSMgrStatus
	);

BOOL WINAPI SRSetRestorePointHookW(
	PRESTOREPOINTINFOW pRestorePtSpec, 
	PSTATEMGRSTATUS pSMgrStatus
	);

#endif /* _SHSRESTOREHOOK_ */