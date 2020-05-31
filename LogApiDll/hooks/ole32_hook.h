/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	ole32_hook.h

Abstract:

	OLE32 API hook interface.

	Last change 07.02.13

--*/

#ifndef _SHOLE32HOOK_
#define _SHOLE32HOOK_

#include <Objbase.h>
#include <Wbemcli.h>
#include <Wbemidl.h>

#define OLE32_EXCEPTION   L"ole32!exception 0x"

#define ConnectServerOffset          3  /*+*/
#define ExecQueryOffset				 20 /*+*/
#define ExecNotificationQueryOffset  22 /*+*/
#define ExecMethodOffset             24 /*+*/

typedef HRESULT (STDMETHODCALLTYPE *PConnectServer)( 
	IUnknown* This, 
	const BSTR strNetworkResource,
	const BSTR strUser,
	const BSTR strPassword,
	const BSTR strLocale,
	long lSecurityFlags,
	const BSTR strAuthority,
	IWbemContext *pCtx,
	IWbemServices **ppNamespace
	);

typedef HRESULT (STDMETHODCALLTYPE *PExecQuery)( 
	IUnknown* This, 
	const BSTR strQueryLanguage,
	const BSTR strQuery,
	long lFlags,
	IWbemContext *pCtx,
	IEnumWbemClassObject **ppEnum
	);

typedef HRESULT (STDMETHODCALLTYPE *PExecMethod)( 
	IUnknown* This, 
	const BSTR strObjectPath,
	const BSTR strMethodName,
	long lFlags,
	IWbemContext *pCtx,
	IWbemClassObject *pInParams,
	IWbemClassObject **ppOutParams,
	IWbemCallResult **ppCallResult
	);

typedef HRESULT (STDMETHODCALLTYPE *PExecNotificationQuery)( 
	IUnknown* This, 
	const BSTR strQueryLanguage,
	const BSTR strQuery,
	long lFlags,
	IWbemContext *pCtx,
	IEnumWbemClassObject **ppEnum
	);

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

typedef HRESULT (WINAPI *PCoCreateInstance)(
	REFCLSID rclsid, 
    LPUNKNOWN pUnkOuter,
    DWORD dwClsContext, 
    REFCLSID riid, 
    LPVOID FAR* ppv
	);

extern PCoCreateInstance pCoCreateInstance;

HRESULT WINAPI CoCreateInstanceHook(
	REFCLSID rclsid, 
    LPUNKNOWN pUnkOuter,
    DWORD dwClsContext, 
    REFCLSID riid, 
    LPVOID FAR* ppv
	);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* _SHOLE32HOOK_ */ 