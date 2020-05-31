/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	srclient_hook.c

Abstract:

	System File Checker hook implementation.

	Last change 04.02.13

--*/

#include "..\global.h"
#include "srclient_hook.h"

PSRRemoveRestorePoint pSRRemoveRestorePoint = NULL;
PSRSetRestorePointA pSRSetRestorePointA = NULL;
PSRSetRestorePointW pSRSetRestorePointW = NULL;

DWORD WINAPI SRRemoveRestorePointHook(
	DWORD dwRPNum
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZESMALL];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pSRRemoveRestorePoint(dwRPNum);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"SRRemoveRestorePoint(");
	
	//put dwRPNum
	ultostrW(dwRPNum, _strendW(tBuff));
	
	//put epilog and lgo
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZESMALL, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pSRRemoveRestorePoint(dwRPNum);
}

BOOL WINAPI SRSetRestorePointHookA(
	PRESTOREPOINTINFOA pRestorePtSpec, 
	PSTATEMGRSTATUS pSMgrStatus
	)
{
	PTLS Tls;
	CHAR tBuff[LOGBUFFERSIZE];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pSRSetRestorePointA(pRestorePtSpec, pSMgrStatus);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyA(tBuff, "SRSetRestorePointA(");

	//put pRestorePtSpec->szDescription
	if ( ARGUMENT_PRESENT(pRestorePtSpec) ) {
		__try {
			_strncpyA(_strendA(tBuff), MAX_DESC, pRestorePtSpec->szDescription, MAX_DESC); 			
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatA(tBuff, SRCLIENT_EXCEPTION_A);
			utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
		}
	} else {
		_strcatA(tBuff, NullStrA);
	}

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pSRSetRestorePointA(pRestorePtSpec, pSMgrStatus);
}

BOOL WINAPI SRSetRestorePointHookW(
	PRESTOREPOINTINFOW pRestorePtSpec, 
	PSTATEMGRSTATUS pSMgrStatus
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZE];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pSRSetRestorePointW(pRestorePtSpec, pSMgrStatus);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));
	
	//put prolog
	_strcpyW(tBuff, L"SRSetRestorePointW(");

	//put pRestorePtSpec->szDescription
	if ( ARGUMENT_PRESENT(pRestorePtSpec) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_DESC_W, pRestorePtSpec->szDescription, MAX_DESC_W); 		
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, SRCLIENT_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pSRSetRestorePointW(pRestorePtSpec, pSMgrStatus);
}