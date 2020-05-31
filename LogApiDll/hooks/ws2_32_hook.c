/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	ws2_32_hook.c

Abstract:

	Winsock2 API hook implementation.

	Last change 04.02.13

--*/

#include "..\global.h"
#include "ws2_32_hook.h"

pfnbind pbind = NULL;
pfnconnect pconnect = NULL;


int PASCAL bindHook(
	SOCKET s, 
	const struct sockaddr FAR *addr, 
	int namelen
	)
{
	PTLS Tls;
	SOCKADDR_IN *in = (SOCKADDR_IN *)addr;
	USHORT port;
	WCHAR tBuff[LOGBUFFERSIZESMALL];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pbind(s, addr, namelen);	 
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"bind(");

	//put port
	if ( ARGUMENT_PRESENT(addr) ) {
		__try {
			_strcatW(tBuff, L"port=");
			port = _htons(in->sin_port);
			_ultostrW(port, _strendW(tBuff));
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, WS2_32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZESMALL, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pbind(s, addr, namelen);
}

VOID PrintIP(
	SOCKADDR_IN *addr,
	PWSTR Buffer
	)
{
	UCHAR k;
	if ( !ARGUMENT_PRESENT(addr))
		return;
	if ( !ARGUMENT_PRESENT(Buffer))
		return;

	k = addr->sin_addr.S_un.S_un_b.s_b1;
	_ultostrW(k, Buffer);
	_strcatW(Buffer, DotW);

	k = addr->sin_addr.S_un.S_un_b.s_b2;
	_ultostrW(k, _strendW(Buffer));
	_strcatW(Buffer, DotW);

	k = addr->sin_addr.S_un.S_un_b.s_b3;
	_ultostrW(k, _strendW(Buffer));
	_strcatW(Buffer, DotW);

	k = addr->sin_addr.S_un.S_un_b.s_b4;
	_ultostrW(k, _strendW(Buffer));
}

int PASCAL connectHook(
	SOCKET s, 
	const struct sockaddr FAR *name, 
	int namelen
	)
{
	PTLS Tls;
	SOCKADDR_IN *in = (SOCKADDR_IN *)name;
	WCHAR tBuff[LOGBUFFERSIZESMALL];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pconnect(s, name, namelen);	 
		}
		Tls->ourcall = TRUE;
	}	

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"connect(");

	//put ip:port
	if ( ARGUMENT_PRESENT(name) ) {
		__try {
			PrintIP(in, _strendW(tBuff));
			_strcatW(tBuff, L":");
			_ultostrW(_htons(in->sin_port), _strendW(tBuff));
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, WS2_32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZESMALL, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pconnect(s, name, namelen);
}