/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	shell32_hook.h

Abstract:

	Shell32 hook interface.

	Last change 13.01.13

--*/

#ifndef _SHSHELL32HOOK_
#define _SHSHELL32HOOK_

typedef BOOL (WINAPI *PIsUserAnAdmin)(VOID);

extern PIsUserAnAdmin pIsUserAnAdmin;

BOOL WINAPI IsUserAnAdminHook(
	VOID
	);

#endif /* _SHSHELL32HOOK_ */