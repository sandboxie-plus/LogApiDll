/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	ws2_32_hook.h

Abstract:

	Winsock2 API hook interface.

	Last change 20.01.13

--*/

#ifndef _SHWS232HOOK_
#define _SHWS232HOOK_

#define WS2_32_EXCEPTION   L" ws2_32!exception 0x"

typedef int (PASCAL *pfnbind) (SOCKET s, const struct sockaddr FAR *addr, int namelen);
typedef int (PASCAL *pfnconnect) (SOCKET s, const struct sockaddr FAR *name, int namelen);

extern pfnbind pbind;
extern pfnconnect pconnect;

int PASCAL bindHook(
	SOCKET s, 
	const struct sockaddr FAR *addr, 
	int namelen
	);

int PASCAL connectHook(
	SOCKET s, 
	const struct sockaddr FAR *name, 
	int namelen
	);

#endif /* _SHWS232HOOK_ */ 