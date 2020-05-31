/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	shell32_hook.c

Abstract:

	Shell32 hook implementation.

	Last change 04.02.13

--*/

#include "..\global.h"
#include "shell32_hook.h"

PIsUserAnAdmin pIsUserAnAdmin = NULL;

BOOL WINAPI IsUserAnAdminHook(
	VOID
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pIsUserAnAdmin();
		Tls->ourcall = TRUE;
	}

	LogAsCall(L"IsUserAnAdmin()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pIsUserAnAdmin();
}