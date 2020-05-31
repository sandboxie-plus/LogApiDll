/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	ole32_hook.cpp (always C++)

Abstract:

	OLE32 API hook implementation.

	Last change 07.02.13

--*/

#include "..\global.h"
#include "ole32_hook.h"

PCoCreateInstance pCoCreateInstance = NULL;
PConnectServer pConnectServer = NULL;
PExecQuery pExecQuery = NULL;
PExecMethod pExecMethod = NULL;
PExecNotificationQuery pExecNotificationQuery = NULL;

HRESULT HookMethod(IUnknown* original, PVOID proxyMethod, PVOID* originalMethod, DWORD vtableOffset)
{
	DWORD dwOld;
	PVOID* originalVtable = *(PVOID**)original;

	if (originalVtable[vtableOffset] == proxyMethod) {
		return S_OK;
	}

	*originalMethod = originalVtable[vtableOffset];

	VirtualProtect(&originalVtable[vtableOffset], sizeof(LONG_PTR), PAGE_EXECUTE_READWRITE, &dwOld);
	originalVtable[vtableOffset] = proxyMethod;

	return S_OK;
}

VOID LogWMIQuery(
	const BSTR strQueryLanguage,
	const BSTR strQuery
	)
{
	WCHAR tBuff[LOGBUFFERSIZELONG];

	//put prolog
	_strcpyW(tBuff, L"ExecQueryWMI(");

	//put strQueryLanguage
	if ( ARGUMENT_PRESENT(strQueryLanguage) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH, strQueryLanguage, MAX_PATH);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, OLE32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, EmptyStrW);
	}	

	_strcatW(tBuff, CommaExW);

	//put strQuery
	if ( ARGUMENT_PRESENT(strQuery) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH, strQuery, MAX_PATH);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, OLE32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, EmptyStrW);
	}	

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);
}

HRESULT STDMETHODCALLTYPE ExecNotificationQueryHook( 
	IUnknown* This, 
	const BSTR strQueryLanguage,
	const BSTR strQuery,
	long lFlags,
	IWbemContext *pCtx,
	IEnumWbemClassObject **ppEnum
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pExecNotificationQuery(This, strQueryLanguage, strQuery, lFlags, pCtx, ppEnum);
		Tls->ourcall = TRUE;
	}

	LogWMIQuery(strQueryLanguage, strQuery);

	if ( Tls ) Tls->ourcall = FALSE;
	return pExecNotificationQuery(This, strQueryLanguage, strQuery, lFlags, pCtx, ppEnum);
}

HRESULT STDMETHODCALLTYPE ExecQueryHook( 
	IUnknown* This, 
	const BSTR strQueryLanguage,
	const BSTR strQuery,
	long lFlags,
	IWbemContext *pCtx,
	IEnumWbemClassObject **ppEnum
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pExecQuery(This, strQueryLanguage, strQuery, lFlags, pCtx, ppEnum);
		Tls->ourcall = TRUE;
	}

	LogWMIQuery(strQueryLanguage, strQuery);

	if ( Tls ) Tls->ourcall = FALSE;
	return pExecQuery(This, strQueryLanguage, strQuery, lFlags, pCtx, ppEnum);
}

HRESULT STDMETHODCALLTYPE ExecMethodHook( 
	IUnknown* This, 
	const BSTR strObjectPath,
	const BSTR strMethodName,
	long lFlags,
	IWbemContext *pCtx,
	IWbemClassObject *pInParams,
	IWbemClassObject **ppOutParams,
	IWbemCallResult **ppCallResult
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pExecMethod(This, strObjectPath, strMethodName, 
			lFlags, pCtx, pInParams, ppOutParams, ppCallResult);
		Tls->ourcall = TRUE;
	}

	//put prolog
	_strcpyW(tBuff, L"ExecMethodWMI(");

	//put strObjectPath
	if ( ARGUMENT_PRESENT(strObjectPath) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH, strObjectPath, MAX_PATH);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, OLE32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, EmptyStrW);
	}	

	_strcatW(tBuff, ArrowW);

	//put strMethodName
	if ( ARGUMENT_PRESENT(strMethodName) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH, strMethodName, MAX_PATH);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, OLE32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, EmptyStrW);
	}	

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pExecMethod(This, strObjectPath, strMethodName, lFlags, pCtx, pInParams, ppOutParams, ppCallResult);
}

HRESULT InstallWmiInterfaceHooks(IWbemServices* originalInterface)
{
	DWORD dwOld = 0;

	if ( !VirtualProtect(*(PVOID**)(originalInterface), 
		sizeof(LONG_PTR), PAGE_EXECUTE_READWRITE, &dwOld) ) 
	{
		return E_FAIL;
	}

	HookMethod(originalInterface, ExecQueryHook, (PVOID*)&pExecQuery, ExecQueryOffset);
	HookMethod(originalInterface, ExecMethodHook, (PVOID*)&pExecMethod, ExecMethodOffset);
	HookMethod(originalInterface, ExecNotificationQueryHook, (PVOID*)&pExecNotificationQuery, ExecNotificationQueryOffset);

	return S_OK;
}

HRESULT STDMETHODCALLTYPE ConnectServerHook( 
	IUnknown* This, 
	const BSTR strNetworkResource,
	const BSTR strUser,
	const BSTR strPassword,
	const BSTR strLocale,
	long lSecurityFlags,
	const BSTR strAuthority,
	IWbemContext *pCtx,
	IWbemServices **ppNamespace
	)
{
	HRESULT hResult;
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZE];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pConnectServer(This, strNetworkResource, strUser, strPassword, 
			strLocale, lSecurityFlags, strAuthority, pCtx, ppNamespace);
		Tls->ourcall = TRUE;
	}

	//put prolog
	_strcpyW(tBuff, L"ConnectServerWMI(");

	//put strNetworkResource
	if ( ARGUMENT_PRESENT(strNetworkResource) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH, strNetworkResource, MAX_PATH);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, OLE32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, EmptyStrW);
	}	

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	hResult = pConnectServer(This, strNetworkResource, strUser, strPassword, 
		strLocale, lSecurityFlags, strAuthority, pCtx, ppNamespace);

	if ( SUCCEEDED(hResult) ) {
		InstallWmiInterfaceHooks((IWbemServices*)*ppNamespace);
	}
	return hResult;
}

HRESULT InstallComInterfaceHooks(IWbemLocator* originalInterface)
{
	DWORD dwOld = 0;

	if ( !VirtualProtect(*(PVOID**)(originalInterface), 
		sizeof(LONG_PTR), PAGE_EXECUTE_READWRITE, &dwOld) ) 
	{
		return E_FAIL;
	}

	HookMethod(originalInterface, ConnectServerHook, (PVOID*)&pConnectServer, ConnectServerOffset);

	return S_OK;
}

HRESULT WINAPI CoCreateInstanceHook(
	REFCLSID rclsid, 
	LPUNKNOWN pUnkOuter,
	DWORD dwClsContext, 
	REFCLSID riid, 
	LPVOID FAR* ppv
	)
{
	HRESULT hResult;
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);
		Tls->ourcall = TRUE;
	}

	if ( rclsid == CLSID_WbemLocator ) {

		if ( pUnkOuter ) {
			if ( Tls ) Tls->ourcall = FALSE;
			return CLASS_E_NOAGGREGATION;
		}

		hResult = pCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);
		if ( SUCCEEDED(hResult) ) {
			InstallComInterfaceHooks((IWbemLocator*)*ppv);
		}	
		if ( Tls ) Tls->ourcall = FALSE;
		return hResult;
	}
	if ( Tls ) Tls->ourcall = FALSE;
	return pCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);
}
