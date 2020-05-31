/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	advapi32_hook.c

Abstract:

	Advanced Windows 32 Base API hook implementation.

	Last change 04.02.13

--*/

#include "..\global.h"
#include "advapi32_hook.h"

POpenSCManagerA pOpenSCManagerA = NULL;
POpenSCManagerW pOpenSCManagerW = NULL;
POpenServiceA pOpenServiceA = NULL;
POpenServiceW pOpenServiceW = NULL;
PCreateServiceA pCreateServiceA = NULL;
PCreateServiceW pCreateServiceW = NULL;
PStartServiceA pStartServiceA = NULL;
PStartServiceW pStartServiceW = NULL;
PControlService pControlService = NULL;
PDeleteService pDeleteService = NULL;
PChangeServiceConfigA pChangeServiceConfigA = NULL;
PChangeServiceConfigW pChangeServiceConfigW = NULL;
PAreAnyAccessesGranted pAreAnyAccessesGranted = NULL;
PGetUserNameA pGetUserNameA = NULL;
PGetUserNameW pGetUserNameW = NULL;
PGetCurrentHwProfileW pGetCurrentHwProfileW = NULL;
POpenEventLogA pOpenEventLogA = NULL;
POpenEventLogW pOpenEventLogW = NULL;
PClearEventLogA pClearEventLogA = NULL;
PClearEventLogW pClearEventLogW = NULL;
PCryptEncrypt pCryptEncrypt = NULL;
PCryptDecrypt pCryptDecrypt = NULL;
PCryptHashData pCryptHashData = NULL;
PSetFileSecurityW pSetFileSecurityW = NULL;
PSetNamedSecurityInfoA pSetNamedSecurityInfoA = NULL;
PSetNamedSecurityInfoW pSetNamedSecurityInfoW = NULL;
PSetSecurityInfo pSetSecurityInfo = NULL;

/* verbose mode items */
PRegCreateKeyExA pRegCreateKeyExA = NULL;
PRegCreateKeyExW pRegCreateKeyExW = NULL;
PRegOpenKeyExA pRegOpenKeyExA = NULL;
PRegOpenKeyExW pRegOpenKeyExW = NULL;
PRegDeleteKeyA pRegDeleteKeyA = NULL;
PRegDeleteKeyW pRegDeleteKeyW = NULL;
PRegDeleteValueA pRegDeleteValueA = NULL;
PRegDeleteValueW pRegDeleteValueW = NULL;
PRegEnumKeyExA pRegEnumKeyExA = NULL;
PRegEnumKeyExW pRegEnumKeyExW = NULL;
PRegEnumValueA pRegEnumValueA = NULL;
PRegEnumValueW pRegEnumValueW = NULL;
PRegSetValueA pRegSetValueA = NULL;
PRegSetValueW pRegSetValueW = NULL;
PRegSetValueExA pRegSetValueExA = NULL;
PRegSetValueExW pRegSetValueExW = NULL;
PRegSaveKeyA pRegSaveKeyA = NULL;
PRegSaveKeyW pRegSaveKeyW = NULL;
PRegSaveKeyExA pRegSaveKeyExA = NULL;
PRegSaveKeyExW pRegSaveKeyExW = NULL;
PRegLoadKeyA pRegLoadKeyA = NULL;
PRegLoadKeyW pRegLoadKeyW = NULL;
PRegCloseKey pRegCloseKey = NULL; 

VOID LogSCMDesiredAccessA(
	DWORD dwDesiredAccess,
	LPSTR Buffer, 
	BOOL Connect
	)
{
	if ( dwDesiredAccess == SC_MANAGER_ALL_ACCESS ) {
		_strcatA(Buffer, ", SC_MANAGER_ALL_ACCESS");
	} else {
		if ( Connect ) _strcatA(Buffer, ", SC_MANAGER_CONNECT");//implicitly specified always
		if ( dwDesiredAccess & SC_MANAGER_CREATE_SERVICE ) _strcatA(Buffer, ", SC_MANAGER_CREATE_SERVICE"); 
		if ( dwDesiredAccess & SC_MANAGER_ENUMERATE_SERVICE ) _strcatA(Buffer, ", SC_MANAGER_ENUMERATE_SERVICE"); 
		if ( dwDesiredAccess & SC_MANAGER_LOCK ) _strcatA(Buffer, ", SC_MANAGER_LOCK"); 
		if ( dwDesiredAccess & SC_MANAGER_MODIFY_BOOT_CONFIG ) _strcatA(Buffer, ", SC_MANAGER_MODIFY_BOOT_CONFIG"); 
		if ( dwDesiredAccess & SC_MANAGER_QUERY_LOCK_STATUS ) _strcatA(Buffer, ", SC_MANAGER_QUERY_LOCK_STATUS"); 
		if ( dwDesiredAccess & STANDARD_RIGHTS_READ ) _strcatA(Buffer, ", STANDARD_RIGHTS_READ");
		if ( dwDesiredAccess & STANDARD_RIGHTS_WRITE ) _strcatA(Buffer, ", STANDARD_RIGHTS_WRITE");
		if ( dwDesiredAccess & STANDARD_RIGHTS_EXECUTE ) _strcatA(Buffer, ", STANDARD_RIGHTS_EXECUTE");
	}
}

VOID LogSCMDesiredAccessW(
	DWORD dwDesiredAccess,
	LPWSTR Buffer,
	BOOL Connect
	)
{
	if ( dwDesiredAccess == SC_MANAGER_ALL_ACCESS ) {
		_strcatW(Buffer, L", SC_MANAGER_ALL_ACCESS");
	} else {
		if ( Connect ) _strcatW(Buffer, L", SC_MANAGER_CONNECT");//implicitly specified always
		if ( dwDesiredAccess & SC_MANAGER_CREATE_SERVICE ) _strcatW(Buffer, L", SC_MANAGER_CREATE_SERVICE"); 
		if ( dwDesiredAccess & SC_MANAGER_ENUMERATE_SERVICE ) _strcatW(Buffer, L", SC_MANAGER_ENUMERATE_SERVICE"); 
		if ( dwDesiredAccess & SC_MANAGER_LOCK ) _strcatW(Buffer, L", SC_MANAGER_LOCK"); 
		if ( dwDesiredAccess & SC_MANAGER_MODIFY_BOOT_CONFIG ) _strcatW(Buffer, L", SC_MANAGER_MODIFY_BOOT_CONFIG"); 
		if ( dwDesiredAccess & SC_MANAGER_QUERY_LOCK_STATUS ) _strcatW(Buffer, L", SC_MANAGER_QUERY_LOCK_STATUS"); 
		if ( dwDesiredAccess & STANDARD_RIGHTS_READ ) _strcatW(Buffer, L", STANDARD_RIGHTS_READ");
		if ( dwDesiredAccess & STANDARD_RIGHTS_WRITE ) _strcatW(Buffer, L", STANDARD_RIGHTS_WRITE");
		if ( dwDesiredAccess & STANDARD_RIGHTS_EXECUTE ) _strcatW(Buffer, L", STANDARD_RIGHTS_EXECUTE");
	}
}

SC_HANDLE WINAPI OpenSCManagerHookA(
	LPCSTR lpMachineName,
	LPCSTR lpDatabaseName,
	DWORD dwDesiredAccess
	)
{
	PTLS Tls;
	CHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pOpenSCManagerA(lpMachineName, lpDatabaseName, dwDesiredAccess);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog
	_strcpyA(tBuff, "OpenSCManager(");

	__try {
		//put lpMachineName & lpDatabaseName
		if ( ARGUMENT_PRESENT(lpMachineName) ) {
			_strncpyA(_strendA(tBuff), MAX_PATH, lpMachineName, MAX_PATH);
		} else {
			_strcatA(tBuff, "LocalMachine");
		}
		_strcatA(tBuff, CommaExA);
		if ( ARGUMENT_PRESENT(lpDatabaseName)) {
			_strncpyA(_strendA(tBuff), MAX_PATH, lpDatabaseName, MAX_PATH);
		} else {
			_strcatA(tBuff, "ServicesActiveDatabase");
		}
		//put DesiredAccess
		LogSCMDesiredAccessA(dwDesiredAccess, tBuff, TRUE);		
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatA(tBuff, ADVAPI32_EXCEPTION_A);
		utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
	}

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pOpenSCManagerA(lpMachineName, lpDatabaseName, dwDesiredAccess);
}

SC_HANDLE WINAPI OpenSCManagerHookW(
	LPCWSTR lpMachineName,
	LPCWSTR lpDatabaseName,
	DWORD dwDesiredAccess
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pOpenSCManagerW(lpMachineName, lpDatabaseName, dwDesiredAccess);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog
	_strcpyW(tBuff, L"OpenSCManager(");

	__try {
		//put lpMachineName & lpDatabaseName
		if ( ARGUMENT_PRESENT(lpMachineName) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH, lpMachineName, MAX_PATH);
		} else {
			_strcatW(tBuff, L"LocalMachine");
		}
		_strcatW(tBuff, CommaExW);
		if ( ARGUMENT_PRESENT(lpDatabaseName)) {
			_strncpyW(_strendW(tBuff), MAX_PATH, lpDatabaseName, MAX_PATH);
		} else {
			_strcatW(tBuff, L"ServicesActiveDatabase");
		}
		//put DesiredAccess
		LogSCMDesiredAccessW(dwDesiredAccess, tBuff, TRUE);		
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatW(tBuff, ADVAPI32_EXCEPTION);
		utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pOpenSCManagerW(lpMachineName, lpDatabaseName, dwDesiredAccess);
}

SC_HANDLE WINAPI OpenServiceHookA(
	SC_HANDLE hSCManager,
	LPCSTR lpServiceName,
	DWORD dwDesiredAccess
	)
{
	PTLS Tls;
	CHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pOpenServiceA(hSCManager, lpServiceName, dwDesiredAccess);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog
	_strcpyA(tBuff, "OpenService(");

	//put lpServiceName
	if ( ARGUMENT_PRESENT(lpServiceName) ) {
		__try {
			_strncpyA(_strendA(tBuff), MAX_PATH, lpServiceName, MAX_PATH);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatA(tBuff, ADVAPI32_EXCEPTION_A);
			utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
		}
	} else {
		_strcatA(tBuff, NullStrA);
	}
	//put DesiredAccess
	LogSCMDesiredAccessA(dwDesiredAccess, tBuff, FALSE);

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pOpenServiceA(hSCManager, lpServiceName, dwDesiredAccess);
}

SC_HANDLE WINAPI OpenServiceHookW(
	SC_HANDLE hSCManager,
	LPCWSTR lpServiceName,
	DWORD dwDesiredAccess
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pOpenServiceW(hSCManager, lpServiceName, dwDesiredAccess);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog
	_strcpyW(tBuff, L"OpenService(");

	//put lpServiceName
	if ( ARGUMENT_PRESENT(lpServiceName) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH, lpServiceName, MAX_PATH);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, ADVAPI32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}
	//put DesiredAccess
	LogSCMDesiredAccessW(dwDesiredAccess, tBuff, FALSE);

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pOpenServiceW(hSCManager, lpServiceName, dwDesiredAccess);
}

SC_HANDLE WINAPI CreateServiceHookA(
	SC_HANDLE hSCManager,
	LPCSTR lpServiceName,
	LPCSTR lpDisplayName,
	DWORD dwDesiredAccess,
	DWORD dwServiceType,
	DWORD dwStartType,
	DWORD dwErrorControl,
	LPCSTR lpBinaryPathName,
	LPCSTR lpLoadOrderGroup,
	LPDWORD lpdwTagId,
	LPCSTR lpDependencies,
	LPCSTR lpServiceStartName,
	LPCSTR lpPassword
	)
{
	PTLS Tls;
	CHAR tBuff[LOGBUFFERSIZE];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCreateServiceA(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess,
				dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup,
				lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog
	_strcpyA(tBuff, "CreateService(");

	//put lpServiceName (lpDisplayName is optional param while lpServiceName is required, that's why it logged instead of original logapi code
	if ( ARGUMENT_PRESENT(lpServiceName) ) {
		__try {
			_strncpyA(_strendA(tBuff), MAX_PATH, lpServiceName, MAX_PATH);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatA(tBuff, ADVAPI32_EXCEPTION_A);
			utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
		}
	} else {
		_strcatA(tBuff, NullStrA);
	}

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCreateServiceA(hSCManager,
		lpServiceName,
		lpDisplayName,
		dwDesiredAccess,
		dwServiceType,
		dwStartType,
		dwErrorControl,
		lpBinaryPathName,
		lpLoadOrderGroup,
		lpdwTagId,
		lpDependencies,
		lpServiceStartName,
		lpPassword
		);
}

SC_HANDLE WINAPI CreateServiceHookW(
	SC_HANDLE hSCManager,
	LPCWSTR lpServiceName,
	LPCWSTR lpDisplayName,
	DWORD dwDesiredAccess,
	DWORD dwServiceType,
	DWORD dwStartType,
	DWORD dwErrorControl,
	LPCWSTR lpBinaryPathName,
	LPCWSTR lpLoadOrderGroup,
	LPDWORD lpdwTagId,
	LPCWSTR lpDependencies,
	LPCWSTR lpServiceStartName,
	LPCWSTR lpPassword
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZE];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCreateServiceW(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess,
				dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup,
				lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog
	_strcpyW(tBuff, L"CreateService(");

	//put lpServiceName (lpDisplayName is optional param while lpServiceName is required, that's why it logged instead of original logapi code
	if ( ARGUMENT_PRESENT(lpServiceName) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH, lpServiceName, MAX_PATH);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, ADVAPI32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCreateServiceW(hSCManager,
		lpServiceName,
		lpDisplayName,
		dwDesiredAccess,
		dwServiceType,
		dwStartType,
		dwErrorControl,
		lpBinaryPathName,
		lpLoadOrderGroup,
		lpdwTagId,
		lpDependencies,
		lpServiceStartName,
		lpPassword
		);
}

BOOL WINAPI StartServiceHookA(
	SC_HANDLE hService,
	DWORD dwNumServiceArgs,
	LPCSTR *lpServiceArgVectors
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pStartServiceA(hService, dwNumServiceArgs, lpServiceArgVectors);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCallA("StartService()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pStartServiceA(hService, dwNumServiceArgs, lpServiceArgVectors);
}

BOOL WINAPI StartServiceHookW(
	SC_HANDLE hService,
	DWORD dwNumServiceArgs,
	LPCWSTR *lpServiceArgVectors
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pStartServiceW(hService, dwNumServiceArgs, lpServiceArgVectors);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCall(L"StartService()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pStartServiceW(hService, dwNumServiceArgs, lpServiceArgVectors);
}

BOOL WINAPI ControlServiceHook(
	SC_HANDLE hService,
	DWORD dwControl,
	LPSERVICE_STATUS lpServiceStatus
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZE];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pControlService(hService, dwControl, lpServiceStatus);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog
	_strcpyW(tBuff, L"ControlService(");

	switch ( dwControl ) {
	case SERVICE_CONTROL_STOP:
		_strcatW(tBuff, L"STOP");
		break;
	case SERVICE_CONTROL_PAUSE:
		_strcatW(tBuff, L"PAUSE");
		break;
	case SERVICE_CONTROL_CONTINUE:
		_strcatW(tBuff, L"CONTINUE");
		break;
	case SERVICE_CONTROL_INTERROGATE:
		_strcatW(tBuff, L"INTERROGATE");
		break;
	default:
		ultostrW(dwControl, _strendW(tBuff));
		break;
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pControlService(hService, dwControl, lpServiceStatus);
}

BOOL WINAPI DeleteServiceHook(
	SC_HANDLE hService
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pDeleteService(hService);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCall(L"DeleteService()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pDeleteService(hService);
}

BOOL WINAPI ChangeServiceConfigHookA(
	SC_HANDLE hService,
	DWORD dwServiceType,
	DWORD dwStartType,
	DWORD dwErrorControl,
	LPCSTR lpBinaryPathName,
	LPCSTR lpLoadOrderGroup,
	LPDWORD lpdwTagId,
	LPCSTR lpDependencies,
	LPCSTR lpServiceStartName,
	LPCSTR lpPassword,
	LPCSTR lpDisplayName
	)
{
	PTLS Tls;
	CHAR tBuff[LOGBUFFERSIZELONG];

	PSTR pszServiceType = NULL;
	PSTR pszStartType = NULL;
	PSTR pszErrorControl = NULL;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pChangeServiceConfigA(hService, dwServiceType, dwStartType, 
				dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, 
				lpDependencies, lpServiceStartName, lpPassword, lpDisplayName);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog
	_strcpyA(tBuff, "ChangeServiceConfig(");

	//put dwServiceType
	switch ( dwServiceType ) {
	case SERVICE_NO_CHANGE:
		pszServiceType = STR_SERVICE_NO_CHANGE_A;
		break;
	case SERVICE_KERNEL_DRIVER:
		pszServiceType = STR_SERVICE_KERNEL_DRIVER_A;
		break;
	case SERVICE_FILE_SYSTEM_DRIVER:
		pszServiceType = STR_SERVICE_FILE_SYSTEM_DRIVER_A;
		break;
	case SERVICE_WIN32_OWN_PROCESS:
		pszServiceType = STR_SERVICE_WIN32_OWN_PROCESS_A;
		break;
	case SERVICE_WIN32_SHARE_PROCESS:
		pszServiceType = STR_SERVICE_WIN32_SHARE_PROCESS_A;
		break;
	case SERVICE_INTERACTIVE_PROCESS:
		pszServiceType = STR_SERVICE_INTERACTIVE_PROCESS_A;
		break;
	default:
		pszServiceType = STR_SERVICE_TYPE_UNKNOWN_A;
		break;
	}
	if ( pszServiceType ) {
		_strcatA(tBuff, pszServiceType);
	} else {
		_strcatA(tBuff, NullStrA);
	}
	_strcatA(tBuff, CommaExA);

	//put dwStartType
	switch ( dwStartType ) {
	case SERVICE_NO_CHANGE:
		pszStartType = STR_SERVICE_NO_CHANGE_A;
		break;
	case SERVICE_BOOT_START:
		pszStartType = STR_SERVICE_BOOT_START_A;
		break;
	case SERVICE_SYSTEM_START:
		pszStartType = STR_SERVICE_SYSTEM_START_A;
		break;
	case SERVICE_AUTO_START:
		pszStartType = STR_SERVICE_AUTO_START_A;
		break;
	case SERVICE_DEMAND_START:
		pszStartType = STR_SERVICE_DEMAND_START_A;
		break;
	case SERVICE_DISABLED:
		pszStartType = STR_SERVICE_DISABLED_A;
		break;
	default:
		pszStartType = STR_SERVICE_TYPE_UNKNOWN_A;
		break;
	}
	if ( pszStartType ) {
		_strcatA(tBuff, pszStartType);
	} else {
		_strcatA(tBuff, NullStrA);
	}
	_strcatA(tBuff, CommaExA);

	//put dwErrorControl
	switch ( dwErrorControl ) {
	case SERVICE_NO_CHANGE:
		pszErrorControl = STR_SERVICE_NO_CHANGE_A;
		break;
	case SERVICE_ERROR_IGNORE:
		pszErrorControl = STR_SERVICE_ERROR_IGNORE_A;
		break;
	case SERVICE_ERROR_NORMAL:
		pszErrorControl = STR_SERVICE_ERROR_NORMAL_A;
		break;
	case SERVICE_ERROR_SEVERE:
		pszErrorControl = STR_SERVICE_ERROR_SEVERE_A;
		break;
	case SERVICE_ERROR_CRITICAL:
		pszErrorControl = STR_SERVICE_ERROR_CRITICAL_A;
		break;
	default:
		pszErrorControl = STR_SERVICE_START_TYPE_UNKNOWN_A;
		break;
	}
	if ( pszErrorControl ) {
		_strcatA(tBuff, pszErrorControl);
	} else {
		_strcatA(tBuff, NullStrA);
	}
	_strcatA(tBuff, CommaExA);

	__try {
		//put lpBinaryPathName
		if ( ARGUMENT_PRESENT( lpBinaryPathName ) ) {
			_strncpyA(_strendA(tBuff), MAX_PATH, lpBinaryPathName, MAX_PATH);
		} else {
			_strcatA(tBuff, NullStrA);
		}
		_strcatA(tBuff, CommaExA);
		//put lpLoadOrderGroup
		if ( ARGUMENT_PRESENT( lpLoadOrderGroup ) ) {
			_strncpyA(_strendA(tBuff), MAX_PATH, lpLoadOrderGroup, MAX_PATH);
		} else {
			_strcatA(tBuff, NullStrA);
		}
		_strcatA(tBuff, CommaExA);
		//put lpdwTagId
		if ( ARGUMENT_PRESENT( lpdwTagId ) ) {
			utohexA((ULONG_PTR)lpdwTagId, _strendA(tBuff));
		} else {
			_strcatA(tBuff, NullStrA);
		}
		_strcatA(tBuff, CommaExA);
		//put lpDependencies
		if ( ARGUMENT_PRESENT( lpDependencies ) ) {
			_strncpyA(_strendA(tBuff), MAX_PATH, lpDependencies, MAX_PATH);
		} else {
			_strcatA(tBuff, NullStrA);
		}
		_strcatA(tBuff, CommaExA);
		//put lpServiceStartName
		if ( ARGUMENT_PRESENT( lpServiceStartName ) ) {
			_strncpyA(_strendA(tBuff), MAX_PATH, lpServiceStartName, MAX_PATH);
		} else {
			_strcatA(tBuff, NullStrA);
		}
		_strcatA(tBuff, CommaExA);
		//put lpPassword
		if ( ARGUMENT_PRESENT( lpPassword ) ) {
			_strncpyA(_strendA(tBuff), MAX_PATH, lpPassword, MAX_PATH);
		} else {
			_strcatA(tBuff, NullStrA);
		}
		_strcatA(tBuff, CommaExA);
		//put lpDisplayName
		if ( ARGUMENT_PRESENT( lpDisplayName ) ) {
			_strncpyA(_strendA(tBuff), MAX_PATH, lpDisplayName, MAX_PATH);
		} else {
			_strcatA(tBuff, NullStrA);
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatA(tBuff, ADVAPI32_EXCEPTION_A);
		utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
	}

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pChangeServiceConfigA(hService, dwServiceType, dwStartType, 
		dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, 
		lpDependencies, lpServiceStartName, lpPassword, lpDisplayName);
}

BOOL WINAPI ChangeServiceConfigHookW(
	SC_HANDLE hService,
	DWORD dwServiceType,
	DWORD dwStartType,
	DWORD dwErrorControl,
	LPCWSTR lpBinaryPathName,
	LPCWSTR lpLoadOrderGroup,
	LPDWORD lpdwTagId,
	LPCWSTR lpDependencies,
	LPCWSTR lpServiceStartName,
	LPCWSTR lpPassword,
	LPCWSTR lpDisplayName
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	PWSTR pszServiceType = NULL;
	PWSTR pszStartType = NULL;
	PWSTR pszErrorControl = NULL;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pChangeServiceConfigW(hService, dwServiceType, dwStartType, 
				dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, 
				lpDependencies, lpServiceStartName, lpPassword, lpDisplayName);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog
	_strcpyW(tBuff, L"ChangeServiceConfig(");

	//put dwServiceType
	switch ( dwServiceType ) {
	case SERVICE_NO_CHANGE:
		pszServiceType = STR_SERVICE_NO_CHANGE;
		break;
	case SERVICE_KERNEL_DRIVER:
		pszServiceType = STR_SERVICE_KERNEL_DRIVER;
		break;
	case SERVICE_FILE_SYSTEM_DRIVER:
		pszServiceType = STR_SERVICE_FILE_SYSTEM_DRIVER;
		break;
	case SERVICE_WIN32_OWN_PROCESS:
		pszServiceType = STR_SERVICE_WIN32_OWN_PROCESS;
		break;
	case SERVICE_WIN32_SHARE_PROCESS:
		pszServiceType = STR_SERVICE_WIN32_SHARE_PROCESS;
		break;
	case SERVICE_INTERACTIVE_PROCESS:
		pszServiceType = STR_SERVICE_INTERACTIVE_PROCESS;
		break;
	default:
		pszServiceType = STR_SERVICE_TYPE_UNKNOWN;
		break;
	}
	if ( pszServiceType ) {
		_strcatW(tBuff, pszServiceType);
	} else {
		_strcatW(tBuff, NullStrW);
	}
	_strcatW(tBuff, CommaExW);

	//put dwStartType
	switch ( dwStartType ) {
	case SERVICE_NO_CHANGE:
		pszStartType = STR_SERVICE_NO_CHANGE;
		break;
	case SERVICE_BOOT_START:
		pszStartType = STR_SERVICE_BOOT_START;
		break;
	case SERVICE_SYSTEM_START:
		pszStartType = STR_SERVICE_SYSTEM_START;
		break;
	case SERVICE_AUTO_START:
		pszStartType = STR_SERVICE_AUTO_START;
		break;
	case SERVICE_DEMAND_START:
		pszStartType = STR_SERVICE_DEMAND_START;
		break;
	case SERVICE_DISABLED:
		pszStartType = STR_SERVICE_DISABLED;
		break;
	default:
		pszStartType = STR_SERVICE_TYPE_UNKNOWN;
		break;
	}
	if ( pszStartType ) {
		_strcatW(tBuff, pszStartType);
	} else {
		_strcatW(tBuff, NullStrW);
	}
	_strcatW(tBuff, CommaExW);

	//put dwErrorControl
	switch ( dwErrorControl ) {
	case SERVICE_NO_CHANGE:
		pszErrorControl = STR_SERVICE_NO_CHANGE;
		break;
	case SERVICE_ERROR_IGNORE:
		pszErrorControl = STR_SERVICE_ERROR_IGNORE;
		break;
	case SERVICE_ERROR_NORMAL:
		pszErrorControl = STR_SERVICE_ERROR_NORMAL;
		break;
	case SERVICE_ERROR_SEVERE:
		pszErrorControl = STR_SERVICE_ERROR_SEVERE;
		break;
	case SERVICE_ERROR_CRITICAL:
		pszErrorControl = STR_SERVICE_ERROR_CRITICAL;
		break;
	default:
		pszErrorControl = STR_SERVICE_START_TYPE_UNKNOWN;
		break;
	}
	if ( pszErrorControl ) {
		_strcatW(tBuff, pszErrorControl);
	} else {
		_strcatW(tBuff, NullStrW);
	}
	_strcatW(tBuff, CommaExW);

	__try {
		//put lpBinaryPathName
		if ( ARGUMENT_PRESENT( lpBinaryPathName ) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH, lpBinaryPathName, MAX_PATH);
		} else {
			_strcatW(tBuff, NullStrW);
		}
		_strcatW(tBuff, CommaExW);
		//put lpLoadOrderGroup
		if ( ARGUMENT_PRESENT( lpLoadOrderGroup ) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH, lpLoadOrderGroup, MAX_PATH);
		} else {
			_strcatW(tBuff, NullStrW);
		}
		_strcatW(tBuff, CommaExW);
		//put lpdwTagId
		if ( ARGUMENT_PRESENT( lpdwTagId ) ) {
			utohexW((ULONG_PTR)lpdwTagId, _strendW(tBuff));
		} else {
			_strcatW(tBuff, NullStrW);
		}
		_strcatW(tBuff, CommaExW);
		//put lpDependencies
		if ( ARGUMENT_PRESENT( lpDependencies ) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH, lpDependencies, MAX_PATH);
		} else {
			_strcatW(tBuff, NullStrW);
		}
		_strcatW(tBuff, CommaExW);
		//put lpServiceStartName
		if ( ARGUMENT_PRESENT( lpServiceStartName ) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH, lpServiceStartName, MAX_PATH);
		} else {
			_strcatW(tBuff, NullStrW);
		}
		_strcatW(tBuff, CommaExW);
		//put lpPassword
		if ( ARGUMENT_PRESENT( lpPassword ) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH, lpPassword, MAX_PATH);
		} else {
			_strcatW(tBuff, NullStrW);
		}
		_strcatW(tBuff, CommaExW);
		//put lpDisplayName
		if ( ARGUMENT_PRESENT( lpDisplayName ) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH, lpDisplayName, MAX_PATH);
		} else {
			_strcatW(tBuff, NullStrW);
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatW(tBuff, ADVAPI32_EXCEPTION);
		utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pChangeServiceConfigW(hService, dwServiceType, dwStartType, 
		dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, 
		lpDependencies, lpServiceStartName, lpPassword, lpDisplayName);
}

BOOL WINAPI AreAnyAccessesGrantedHook(
	DWORD GrantedAccess,
	DWORD DesiredAccess
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pAreAnyAccessesGranted(GrantedAccess, DesiredAccess);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCall(L"AreAnyAccessesGranted()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pAreAnyAccessesGranted(GrantedAccess, DesiredAccess);
}

BOOL WINAPI GetUserNameHookA(
	LPSTR lpBuffer,
	LPDWORD pcbBuffer
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = TRUE;
		if ( Tls->ourcall ) {
			return pGetUserNameA(lpBuffer, pcbBuffer);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCallA("GetUserName()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pGetUserNameA(lpBuffer, pcbBuffer);
}

BOOL WINAPI GetUserNameHookW(
	LPWSTR lpBuffer,
	LPDWORD pcbBuffer
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = TRUE;
		if ( Tls->ourcall ) {
			return pGetUserNameW(lpBuffer, pcbBuffer);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCall(L"GetUserName()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pGetUserNameW(lpBuffer, pcbBuffer);
}

BOOL WINAPI GetCurrentHwProfileHookW(
	LPHW_PROFILE_INFOW  lpHwProfileInfo
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pGetCurrentHwProfileW(lpHwProfileInfo);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCall(L"GetCurrentHwProfile()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pGetCurrentHwProfileW(lpHwProfileInfo);
}

HANDLE WINAPI OpenEventLogHookA(
	LPCSTR lpUNCServerName,
	LPCSTR lpSourceName
	)
{
	PTLS Tls;
	CHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return  pOpenEventLogA(lpUNCServerName, lpSourceName);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog
	_strcpyA(tBuff, "OpenEventLog(");

	__try {
		//put lpUNCServerName & lpSourceName
		if ( ARGUMENT_PRESENT(lpUNCServerName) ) {
			_strncpyA(_strendA(tBuff), MAX_PATH, lpUNCServerName, MAX_PATH);
		} else {
			_strcatA(tBuff, NullStrA);
		}
		_strcatA(tBuff, CommaExA);
		if ( ARGUMENT_PRESENT(lpSourceName) ) {
			_strncpyA(_strendA(tBuff), MAX_PATH, lpSourceName, MAX_PATH);
		} else {
			_strcatA(tBuff, NullStrA);
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatA(tBuff, ADVAPI32_EXCEPTION_A);
		utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
	}

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pOpenEventLogA(lpUNCServerName, lpSourceName);
}

HANDLE WINAPI OpenEventLogHookW(
	LPCWSTR lpUNCServerName,
	LPCWSTR lpSourceName
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pOpenEventLogW(lpUNCServerName, lpSourceName);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog
	_strcpyW(tBuff, L"OpenEventLog(");

	__try {
		//put lpUNCServerName & lpSourceName
		if ( ARGUMENT_PRESENT(lpUNCServerName) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH, lpUNCServerName, MAX_PATH);
		} else {
			_strcatW(tBuff, NullStrW);
		}
		_strcatW(tBuff, CommaExW);
		if ( ARGUMENT_PRESENT(lpSourceName) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH, lpSourceName, MAX_PATH);
		} else {
			_strcatW(tBuff, NullStrW);
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatW(tBuff, ADVAPI32_EXCEPTION);
		utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pOpenEventLogW(lpUNCServerName, lpSourceName);
}

BOOL WINAPI ClearEventLogHookA(
	HANDLE hEventLog,
	LPCSTR lpBackupFileName
	)
{
	PTLS Tls;
	CHAR tBuff[LOGBUFFERSIZE];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pClearEventLogA(hEventLog, lpBackupFileName);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog
	_strcpyA(tBuff, "ClearEventLog(");

	//put lpBackupFileName
	if ( ARGUMENT_PRESENT(lpBackupFileName) ) {
		__try {
			_strncpyA(_strendA(tBuff), MAX_PATH, lpBackupFileName, MAX_PATH);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatA(tBuff, ADVAPI32_EXCEPTION_A);
			utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
		}
	} else {
		_strcatA(tBuff, NullStrA);
	}

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pClearEventLogA(hEventLog, lpBackupFileName);
}

BOOL WINAPI ClearEventLogHookW(
	HANDLE hEventLog,
	LPCWSTR lpBackupFileName
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZE];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pClearEventLogW(hEventLog, lpBackupFileName);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog
	_strcpyW(tBuff, L"ClearEventLog(");

	//put lpBackupFileName
	if ( ARGUMENT_PRESENT(lpBackupFileName) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH, lpBackupFileName, MAX_PATH);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, ADVAPI32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pClearEventLogW(hEventLog, lpBackupFileName);
}

BOOL WINAPI CryptEncryptHook(
	HCRYPTKEY hKey,
	HCRYPTHASH hHash,
	BOOL Final,
	DWORD dwFlags,
	BYTE *pbData,
	DWORD *pdwDataLen,
	DWORD dwBufLen
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCall(L"CryptEncrypt()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
}

BOOL WINAPI CryptDecryptHook(
	HCRYPTKEY hKey,
	HCRYPTHASH hHash,
	BOOL Final,
	DWORD dwFlags,
	BYTE *pbData,
	DWORD *pdwDataLen
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCall(L"CryptDecrypt()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
}

BOOL WINAPI CryptHashDataHook(
	HCRYPTHASH hHash,
	CONST BYTE *pbData,
	DWORD dwDataLen,
	DWORD dwFlags
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCryptHashData(hHash, pbData, dwDataLen, dwFlags);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCall(L"CryptHashData()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCryptHashData(hHash, pbData, dwDataLen, dwFlags);
}

LPSTR LogGetHiveKeyA(
	HKEY hRootKey
	)
{
	if ( hRootKey == HKEY_CURRENT_USER )
		return STR_HKEY_CURRENT_USER_A;
	if ( hRootKey == HKEY_CLASSES_ROOT )
		return STR_HKEY_CLASSES_ROOT_A;	
	if ( hRootKey == HKEY_LOCAL_MACHINE )
		return STR_HKEY_LOCAL_MACHINE_A;
	if ( hRootKey == HKEY_USERS )
		return STR_HKEY_USERS_A;
	if ( hRootKey == HKEY_PERFORMANCE_DATA )
		return STR_HKEY_PERFORMANCE_DATA_A;
	if ( hRootKey == HKEY_PERFORMANCE_TEXT )
		return STR_HKEY_PERFORMANCE_TEXT_A;
	if ( hRootKey == HKEY_CURRENT_CONFIG )
		return STR_HKEY_CURRENT_CONFIG_A;
	return NULL;
}

LPWSTR LogGetHiveKeyW(
	HKEY hRootKey
	)
{
	if ( hRootKey == HKEY_CURRENT_USER )
		return STR_HKEY_CURRENT_USER;
	if ( hRootKey == HKEY_CLASSES_ROOT )
		return STR_HKEY_CLASSES_ROOT;	
	if ( hRootKey == HKEY_LOCAL_MACHINE )
		return STR_HKEY_LOCAL_MACHINE;
	if ( hRootKey == HKEY_USERS )
		return STR_HKEY_USERS;
	if ( hRootKey == HKEY_PERFORMANCE_DATA )
		return STR_HKEY_PERFORMANCE_DATA;
	if ( hRootKey == HKEY_PERFORMANCE_TEXT )
		return STR_HKEY_PERFORMANCE_TEXT;
	if ( hRootKey == HKEY_CURRENT_CONFIG )
		return STR_HKEY_CURRENT_CONFIG;
	return NULL;
}

VOID LogSamDesiredAccessA(
	REGSAM samDesired,
	LPSTR Buffer
	)
{
	if (!ARGUMENT_PRESENT(Buffer))
		return;

	if ( samDesired == KEY_ALL_ACCESS) {
		_strcatA(Buffer, ", KEY_ALL_ACCESS"); 
	} else {
		if ( samDesired & KEY_CREATE_LINK) _strcatA(Buffer, ", KEY_CREATE_LINK");
		if ( samDesired & KEY_CREATE_SUB_KEY) _strcatA(Buffer, ", KEY_CREATE_SUB_KEY");
		if ( samDesired & KEY_ENUMERATE_SUB_KEYS) _strcatA(Buffer, ", KEY_ENUMERATE_SUB_KEYS");
		if ( samDesired & KEY_READ) _strcatA(Buffer, ", KEY_READ");
		if ( samDesired & KEY_NOTIFY) _strcatA(Buffer, ", KEY_NOTIFY");
		if ( samDesired & KEY_QUERY_VALUE) _strcatA(Buffer, ", KEY_QUERY_VALUE");
		if ( samDesired & KEY_SET_VALUE) _strcatA(Buffer, ", KEY_SET_VALUE");
		if ( samDesired & KEY_WOW64_32KEY) _strcatA(Buffer, ", KEY_WOW64_32KEY");
		if ( samDesired & KEY_WOW64_64KEY) _strcatA(Buffer, ", KEY_WOW64_64KEY");
		if ( samDesired & KEY_WRITE) _strcatA(Buffer, ", KEY_WRITE");
		if ( samDesired & DELETE) _strcatA(Buffer, ", DELETE");
		if ( samDesired & READ_CONTROL) _strcatA(Buffer, ", READ_CONTROL");
		if ( samDesired & WRITE_DAC) _strcatA(Buffer, ", WRITE_DAC");
		if ( samDesired & WRITE_OWNER) _strcatA(Buffer, ", WRITE_OWNER");
		if ( samDesired & MAXIMUM_ALLOWED) _strcatA(Buffer, ", MAXIMUM_ALLOWED");
	}
}

VOID LogSamDesiredAccessW(
	REGSAM samDesired,
	LPWSTR Buffer
	)
{
	if (!ARGUMENT_PRESENT(Buffer))
		return;
	if ( samDesired == KEY_ALL_ACCESS) {
		_strcatW(Buffer, L", KEY_ALL_ACCESS"); 
	} else {
		if ( samDesired & KEY_CREATE_LINK) _strcatW(Buffer, L", KEY_CREATE_LINK");
		if ( samDesired & KEY_CREATE_SUB_KEY) _strcatW(Buffer, L", KEY_CREATE_SUB_KEY");
		if ( samDesired & KEY_ENUMERATE_SUB_KEYS) _strcatW(Buffer, L", KEY_ENUMERATE_SUB_KEYS");
		if ( samDesired & KEY_READ) _strcatW(Buffer, L", KEY_READ");
		if ( samDesired & KEY_NOTIFY) _strcatW(Buffer, L", KEY_NOTIFY");
		if ( samDesired & KEY_QUERY_VALUE) _strcatW(Buffer, L", KEY_QUERY_VALUE");
		if ( samDesired & KEY_SET_VALUE) _strcatW(Buffer, L", KEY_SET_VALUE");
		if ( samDesired & KEY_WOW64_32KEY) _strcatW(Buffer, L", KEY_WOW64_32KEY");
		if ( samDesired & KEY_WOW64_64KEY) _strcatW(Buffer, L", KEY_WOW64_64KEY");
		if ( samDesired & KEY_WRITE) _strcatW(Buffer, L", KEY_WRITE");
		if ( samDesired & DELETE) _strcatW(Buffer, L", DELETE");
		if ( samDesired & READ_CONTROL) _strcatW(Buffer, L", READ_CONTROL");
		if ( samDesired & WRITE_DAC) _strcatW(Buffer, L", WRITE_DAC");
		if ( samDesired & WRITE_OWNER) _strcatW(Buffer, L", WRITE_OWNER");
		if ( samDesired & MAXIMUM_ALLOWED) _strcatW(Buffer, L", MAXIMUM_ALLOWED");
	}
}

VOID LogRegCreateOpenExA(
	HKEY hKey,
	LPCSTR lpSubKey,
	REGSAM samDesired,
	LPSTR ApiName
	)
{
	LPSTR pRootKey;
	CHAR tBuff[LOGBUFFERSIZEEXTRA];

	if (!ARGUMENT_PRESENT(ApiName))
		return;

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyA(tBuff, ApiName);
	_strcatA(tBuff, OpenBracketA);

	//get hkey value
	pRootKey = LogGetHiveKeyA(hKey);
	if ( pRootKey != NULL ) {
		_strcatA(tBuff, pRootKey);
	} else {
		//query hkey value name, put hex value on error
		if ( QueryKeyName(hKey, (PVOID)_strendA(tBuff), LOGBUFFERSIZELONG, FALSE) == FALSE) {
			_strcatA(tBuff, HexPrepA);
			utohexA((ULONG_PTR)hKey, _strendA(tBuff));
			_strcatA(tBuff, SlashA);
		}
	}

	//put lpSubKey
	if ( ARGUMENT_PRESENT(lpSubKey) ) {
		__try {
			_strcatA(tBuff, SlashA);
			_strncpyA(_strendA(tBuff), LOGBUFFERSIZELONG, lpSubKey, LOGBUFFERSIZELONG);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatA(tBuff, ADVAPI32_EXCEPTION_A);
			utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
		}
	}

	//put samDesired
	LogSamDesiredAccessA(samDesired, tBuff);

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZEEXTRA, LOG_NORMAL);
}

VOID LogRegCreateOpenExW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	REGSAM samDesired,
	LPWSTR ApiName
	)
{
	LPWSTR pRootKey;
	WCHAR tBuff[LOGBUFFERSIZEEXTRA];

	if (!ARGUMENT_PRESENT(ApiName))
		return;

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, ApiName);
	_strcatW(tBuff, OpenBracketW);

	//get hkey value
	pRootKey = LogGetHiveKeyW(hKey);
	if ( pRootKey != NULL ) {
		_strcatW(tBuff, pRootKey);
	} else {
		//query hkey value name, put hex value on error
		if ( QueryKeyName(hKey, (PVOID)_strendW(tBuff), LOGBUFFERSIZELONG, TRUE) == FALSE) {
			_strcatW(tBuff, HexPrepW);
			utohexW((ULONG_PTR)hKey, _strendW(tBuff));
			_strcatW(tBuff, SlashW);
		}
	}

	//put lpSubKey
	if ( ARGUMENT_PRESENT(lpSubKey) ) {
		__try {
			_strcatW(tBuff, SlashW);
			_strncpyW(_strendW(tBuff), LOGBUFFERSIZELONG, lpSubKey, LOGBUFFERSIZELONG);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, ADVAPI32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	}

	//put samDesired
	LogSamDesiredAccessW(samDesired, tBuff);

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZEEXTRA, LOG_NORMAL);
}

LSTATUS APIENTRY RegCreateKeyExHookA(
	HKEY hKey,
	LPCSTR lpSubKey,
	DWORD Reserved,
	LPSTR lpClass,
	DWORD dwOptions,
	REGSAM samDesired,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PHKEY phkResult,
	LPDWORD lpdwDisposition
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, 
				samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
		}
		Tls->ourcall = TRUE;
	}

	LogRegCreateOpenExA(hKey, lpSubKey, samDesired, "RegCreateKeyEx");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, 
		samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
}

LSTATUS APIENTRY RegCreateKeyExHookW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	DWORD Reserved,
	LPWSTR lpClass,
	DWORD dwOptions,
	REGSAM samDesired,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PHKEY phkResult,
	LPDWORD lpdwDisposition
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, 
				samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
		}
		Tls->ourcall = TRUE;
	}

	LogRegCreateOpenExW(hKey, lpSubKey, samDesired, L"RegCreateKeyEx");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, 
		samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
}

LSTATUS APIENTRY RegOpenKeyExHookA(
	HKEY hKey,
	LPCSTR lpSubKey,
	DWORD ulOptions,
	REGSAM samDesired,
	PHKEY phkResult
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
		}
		Tls->ourcall = TRUE;
	}

	LogRegCreateOpenExA(hKey, lpSubKey, samDesired, "RegOpenKeyEx");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

LSTATUS APIENTRY RegOpenKeyExHookW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	DWORD ulOptions,
	REGSAM samDesired,
	PHKEY phkResult
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
		}
		Tls->ourcall = TRUE;
	}

	LogRegCreateOpenExW(hKey, lpSubKey, samDesired, L"RegOpenKeyEx");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

VOID LogRegDeleteKeyValueA(
	HKEY hKey,
	LPCSTR lpSubKeyValueName,
	LPSTR ApiName
	)
{
	LPSTR pRootKey;
	CHAR tBuff[LOGBUFFERSIZEEXTRA];

	if (!ARGUMENT_PRESENT(ApiName))
		return;

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyA(tBuff, ApiName);
	_strcatA(tBuff, OpenBracketA);

	//get hkey value
	pRootKey = LogGetHiveKeyA(hKey);
	if ( pRootKey != NULL ) {
		_strcatA(tBuff, pRootKey);
	} else {
		//query hkey value name, put hex value on error
		if ( QueryKeyName(hKey, (PVOID)_strendA(tBuff), LOGBUFFERSIZELONG, FALSE) == FALSE) {
			_strcatA(tBuff, HexPrepA);
			utohexA((ULONG_PTR)hKey, _strendA(tBuff));
			_strcatA(tBuff, SlashA);
		}
	}

	//put lpSubKeyValueName
	if ( ARGUMENT_PRESENT(lpSubKeyValueName) ) {
		__try {
			_strcatA(tBuff, SlashA);
			_strncpyA(_strendA(tBuff), LOGBUFFERSIZELONG, lpSubKeyValueName, LOGBUFFERSIZELONG);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatA(tBuff, ADVAPI32_EXCEPTION_A);
			utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
		}
	}

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZEEXTRA, LOG_NORMAL);
}

VOID LogRegDeleteKeyValueW(
	HKEY hKey,
	LPCWSTR lpSubKeyValueName,
	LPWSTR ApiName
	)
{
	LPWSTR pRootKey;
	WCHAR tBuff[LOGBUFFERSIZEEXTRA];

	if (!ARGUMENT_PRESENT(ApiName))
		return;

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, ApiName);
	_strcatW(tBuff, OpenBracketW);

	//get hkey value
	pRootKey = LogGetHiveKeyW(hKey);
	if ( pRootKey != NULL ) {
		_strcatW(tBuff, pRootKey);
	} else {
		//query hkey value name, put hex value on error
		if ( QueryKeyName(hKey, (PVOID)_strendW(tBuff), LOGBUFFERSIZELONG, TRUE) == FALSE) {
			_strcatW(tBuff, HexPrepW);
			utohexW((ULONG_PTR)hKey, _strendW(tBuff));
			_strcatW(tBuff, SlashW);
		}
	}

	//put lpSubKeyValueName
	if ( ARGUMENT_PRESENT(lpSubKeyValueName) ) {
		__try {
			_strcatW(tBuff, SlashW);
			_strncpyW(_strendW(tBuff), LOGBUFFERSIZELONG, lpSubKeyValueName, LOGBUFFERSIZELONG);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, ADVAPI32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZEEXTRA, LOG_NORMAL);
}

LSTATUS APIENTRY RegDeleteKeyHookA(
	HKEY hKey,
	LPCSTR lpSubKey
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegDeleteKeyA(hKey, lpSubKey);
		}
		Tls->ourcall = TRUE;
	}

	LogRegDeleteKeyValueA(hKey, lpSubKey, "RegDeleteKey");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegDeleteKeyA(hKey, lpSubKey);
}

LSTATUS APIENTRY RegDeleteKeyHookW(
	HKEY hKey,
	LPCWSTR lpSubKey
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegDeleteKeyW(hKey, lpSubKey);
		}
		Tls->ourcall = TRUE;
	}

	LogRegDeleteKeyValueW(hKey, lpSubKey, L"RegDeleteKey");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegDeleteKeyW(hKey, lpSubKey);
}

LSTATUS APIENTRY RegDeleteValueHookA(
	HKEY hKey,
	LPCSTR lpValueName
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegDeleteValueA(hKey, lpValueName);
		}
		Tls->ourcall = TRUE;
	}

	LogRegDeleteKeyValueA(hKey, lpValueName, "RegDeleteValue");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegDeleteValueA(hKey, lpValueName);
}

LSTATUS APIENTRY RegDeleteValueHookW(
	HKEY hKey,
	LPCWSTR lpValueName
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegDeleteValueW(hKey, lpValueName);
		}
		Tls->ourcall = TRUE;
	}

	LogRegDeleteKeyValueW(hKey, lpValueName, L"RegDeleteValue");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegDeleteValueW(hKey, lpValueName);
}

LSTATUS APIENTRY RegCloseKeyHook(
	HKEY hKey
	)
{
	PTLS Tls;
	LPWSTR pRootKey;
	WCHAR tBuff[LOGBUFFERSIZEEXTRA];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegCloseKey(hKey);
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"RegCloseKey(");

	//get hkey value
	pRootKey = LogGetHiveKeyW(hKey);
	if ( pRootKey != NULL ) {
		_strcatW(tBuff, pRootKey);
	} else {
		//query hkey value name, put hex value on error
		if ( QueryKeyName(hKey, (PVOID)_strendW(tBuff), LOGBUFFERSIZELONG, TRUE) == FALSE) {
			_strcatW(tBuff, HexPrepW);
			utohexW((ULONG_PTR)hKey, _strendW(tBuff));
			_strcatW(tBuff, SlashW);
		}
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZEEXTRA, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegCloseKey(hKey);
}

VOID LogRegEnumKeyValueA(
	HKEY hKey,
	LPSTR ApiName
	)
{
	LPSTR pRootKey;
	CHAR tBuff[LOGBUFFERSIZEEXTRA];

	if (!ARGUMENT_PRESENT(ApiName))
		return;

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyA(tBuff, ApiName);
	_strcatA(tBuff, OpenBracketA);

	//get hkey value
	pRootKey = LogGetHiveKeyA(hKey);
	if ( pRootKey != NULL ) {
		_strcatA(tBuff, pRootKey);
	} else {
		//query hkey value name, put hex value on error
		if ( QueryKeyName(hKey, (PVOID)_strendA(tBuff), LOGBUFFERSIZELONG, FALSE) == FALSE) {
			_strcatA(tBuff, HexPrepA);
			utohexA((ULONG_PTR)hKey, _strendA(tBuff));
		}
	}

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZEEXTRA, LOG_NORMAL);
}

VOID LogRegEnumKeyValueW(
	HKEY hKey,
	LPWSTR ApiName
	)
{
	LPWSTR pRootKey;
	WCHAR tBuff[LOGBUFFERSIZEEXTRA];

	if (!ARGUMENT_PRESENT(ApiName))
		return;

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, ApiName);
	_strcatW(tBuff, OpenBracketW);

	//get hkey value
	pRootKey = LogGetHiveKeyW(hKey);
	if ( pRootKey != NULL ) {
		_strcatW(tBuff, pRootKey);
	} else {
		//query hkey value name, put hex value on error
		if ( QueryKeyName(hKey, (PVOID)_strendW(tBuff), LOGBUFFERSIZELONG, TRUE) == FALSE) {
			_strcatW(tBuff, HexPrepW);
			utohexW((ULONG_PTR)hKey, _strendW(tBuff));
		}
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZEEXTRA, LOG_NORMAL);
}

LSTATUS APIENTRY RegEnumKeyExHookA(
	HKEY hKey,
	DWORD dwIndex,
	LPSTR lpName,
	LPDWORD lpcchName,
	LPDWORD lpReserved,
	LPSTR lpClass,
	LPDWORD lpcchClass,
	PFILETIME lpftLastWriteTime
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegEnumKeyExA(hKey, dwIndex, lpName, lpcchName, 
				lpReserved, lpClass, lpcchClass, lpftLastWriteTime);
		}
		Tls->ourcall = TRUE;
	}

	LogRegEnumKeyValueA(hKey, "RegEnumKeyEx");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegEnumKeyExA(hKey, dwIndex, lpName, lpcchName, 
		lpReserved, lpClass, lpcchClass, lpftLastWriteTime);
}

LSTATUS APIENTRY RegEnumKeyExHookW(
	HKEY hKey,
	DWORD dwIndex,
	LPWSTR lpName,
	LPDWORD lpcchName,
	LPDWORD lpReserved,
	LPWSTR lpClass,
	LPDWORD lpcchClass,
	PFILETIME lpftLastWriteTime
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegEnumKeyExW(hKey, dwIndex, lpName, lpcchName, 
				lpReserved, lpClass, lpcchClass, lpftLastWriteTime);
		}
		Tls->ourcall = TRUE;
	}

	LogRegEnumKeyValueW(hKey, L"RegEnumKeyEx");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegEnumKeyExW(hKey, dwIndex, lpName, lpcchName, 
		lpReserved, lpClass, lpcchClass, lpftLastWriteTime);
}

LSTATUS APIENTRY RegEnumValueHookA(
	HKEY hKey,
	DWORD dwIndex,
	LPSTR lpValueName,
	LPDWORD lpcchValueName,
	LPDWORD lpReserved,
	LPDWORD lpType,
	LPBYTE lpData,
	LPDWORD lpcbData
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegEnumValueA(hKey, dwIndex, lpValueName, 
				lpcchValueName, lpReserved, lpType, lpData, lpcbData);
		}
		Tls->ourcall = TRUE;
	}

	LogRegEnumKeyValueA(hKey, "RegEnumValue");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegEnumValueA(hKey, dwIndex, lpValueName, 
		lpcchValueName, lpReserved, lpType, lpData, lpcbData);
}

LSTATUS APIENTRY RegEnumValueHookW(
	HKEY hKey,
	DWORD dwIndex,
	LPWSTR lpValueName,
	LPDWORD lpcchValueName,
	LPDWORD lpReserved,
	LPDWORD lpType,
	LPBYTE lpData,
	LPDWORD lpcbData
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegEnumValueW(hKey, dwIndex, lpValueName, 
				lpcchValueName, lpReserved, lpType, lpData, lpcbData);
		}
		Tls->ourcall = TRUE;
	}

	LogRegEnumKeyValueW(hKey, L"RegEnumValue");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegEnumValueW(hKey, dwIndex, lpValueName, 
		lpcchValueName, lpReserved, lpType, lpData, lpcbData);
}

VOID LogPutRegTypeA(
	LPSTR Buffer,
	DWORD dwType
	)
{
	LPSTR lpType = NULL;

	if ( !ARGUMENT_PRESENT(Buffer))
		return;

	switch ( dwType ) {
	case REG_NONE:
		lpType = "REG_NONE";
		break;
	case REG_SZ:
		lpType = "REG_SZ";
		break;
	case REG_EXPAND_SZ:
		lpType = "REG_EXPAND_SZ";
		break;
	case REG_BINARY:
		lpType = "REG_BINARY";
		break;
	case REG_DWORD:
		lpType = "REG_DWORD";
		break;
	case REG_DWORD_BIG_ENDIAN:
		lpType = "REG_DWORD_BIG_ENDIAN";
		break;
	case REG_LINK:
		lpType = "REG_LINK";
		break;
	case REG_MULTI_SZ:
		lpType = "REG_MULTI_SZ";
		break;
	case REG_RESOURCE_LIST:
		lpType = "REG_RESOURCE_LIST";
		break;
	case REG_FULL_RESOURCE_DESCRIPTOR:
		lpType = "REG_FULL_RESOURCE_DESCRIPTOR";
		break;
	case REG_RESOURCE_REQUIREMENTS_LIST:
		lpType = "REG_RESOURCE_REQUIREMENTS_LIST";
		break;
	case REG_QWORD:
		lpType = "REG_QWORD";
		break;
	default:
		lpType = NullStrA;
		break;
	}
	if ( lpType != NULL) {
		_strcatA(Buffer, lpType);
	}
}

VOID LogPutRegTypeW(
	LPWSTR Buffer,
	DWORD dwType
	)
{
	LPWSTR lpType = NULL;

	if ( !ARGUMENT_PRESENT(Buffer))
		return;

	switch ( dwType ) {
	case REG_NONE:
		lpType = L"REG_NONE";
		break;
	case REG_SZ:
		lpType = L"REG_SZ";
		break;
	case REG_EXPAND_SZ:
		lpType = L"REG_EXPAND_SZ";
		break;
	case REG_BINARY:
		lpType = L"REG_BINARY";
		break;
	case REG_DWORD:
		lpType = L"REG_DWORD";
		break;
	case REG_DWORD_BIG_ENDIAN:
		lpType = L"REG_DWORD_BIG_ENDIAN";
		break;
	case REG_LINK:
		lpType = L"REG_LINK";
		break;
	case REG_MULTI_SZ:
		lpType = L"REG_MULTI_SZ";
		break;
	case REG_RESOURCE_LIST:
		lpType = L"REG_RESOURCE_LIST";
		break;
	case REG_FULL_RESOURCE_DESCRIPTOR:
		lpType = L"REG_FULL_RESOURCE_DESCRIPTOR";
		break;
	case REG_RESOURCE_REQUIREMENTS_LIST:
		lpType = L"REG_RESOURCE_REQUIREMENTS_LIST";
		break;
	case REG_QWORD:
		lpType = L"REG_QWORD";
		break;
	default:
		lpType = NullStrW;
		break;
	}
	if ( lpType != NULL) {
		_strcatW(Buffer, lpType);
	}
}

VOID LogRegSetValueExA(
	HKEY hKey,
	LPCSTR lpSubKeyValueName,
	LPCSTR lpData,
	DWORD dwType,
	CONST BYTE* lpDataEx,
	BOOL SetValueEx,
	LPSTR ApiName
	)
{
	LPSTR pRootKey;
	LPSTR StringA = NULL;
	DWORD dwValue = 0;
	CHAR tBuff[LOGBUFFERSIZEEXTRA];

	if (!ARGUMENT_PRESENT(ApiName))
		return;

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyA(tBuff, ApiName);
	_strcatA(tBuff, OpenBracketA);

	//get hkey value
	pRootKey = LogGetHiveKeyA(hKey);
	if ( pRootKey != NULL ) {
		_strcatA(tBuff, pRootKey);
	} else {
		//query hkey value name, put hex value on error
		if ( QueryKeyName(hKey, (PVOID)_strendA(tBuff), LOGBUFFERSIZELONG, FALSE) == FALSE) {
			_strcatA(tBuff, HexPrepA);
			utohexA((ULONG_PTR)hKey, _strendA(tBuff));
		}
	}

	//put lpSubKey
	if ( ARGUMENT_PRESENT(lpSubKeyValueName) ) {
		__try {
			_strcatA(tBuff, SlashA);
			_strncpyA(_strendA(tBuff), LOGBUFFERSIZELONG, lpSubKeyValueName, LOGBUFFERSIZELONG);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatA(tBuff, ADVAPI32_EXCEPTION_A);
			utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
		}
	}

	//parse SetValueEx/SetValue
	if ( SetValueEx == TRUE ) {

		//put registry type
		_strcatA(tBuff, CommaExA);
		LogPutRegTypeA(tBuff, dwType);

		//put value
		__try {

			switch ( dwType ) {

			case REG_SZ:
			case REG_EXPAND_SZ:

				_strcatA(tBuff, CommaExA);
				StringA = (LPSTR)lpDataEx;
				if ( StringA != NULL ) {
					_strncpyA(_strendA(tBuff), LOGBUFFERSIZELONG, StringA, LOGBUFFERSIZELONG);
				} else {
					_strcatA(tBuff, NullStrA);
				}
				break;

			case REG_DWORD:

				_strcatA(tBuff, ColonA);
				if ( lpDataEx != NULL ) {
					dwValue = *lpDataEx;
					ultostrA(dwValue, _strendA(tBuff));
				} else {
					_strcatA(tBuff, NullStrA);
				}
				break;

			default:
				break;
			}
		
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatA(tBuff, ADVAPI32_EXCEPTION_A);
			utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
		}
		/* example of result: RegSetValueEx(\RegistryPath\Key, ValueName, RegType: value */
	} else {

		_strcatA(tBuff, CommaExA);
		//put lpData
		if ( ARGUMENT_PRESENT(lpData) ) {
			__try {
				_strncpyA(_strendA(tBuff), LOGBUFFERSIZELONG, lpData, LOGBUFFERSIZELONG);
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				_strcatA(tBuff, ADVAPI32_EXCEPTION_A);
				utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
			}
		} else {
			_strcatA(tBuff, NullStrA);
		}
		/*example of result: RegSetValue(\RegistryPath\lpSubKey, lpData)*/
	}

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZEEXTRA, LOG_NORMAL);
	//OutputDebugStringA(tBuff);
}

VOID LogRegSetValueExW(
	HKEY hKey,
	LPCWSTR lpSubKeyValueName,
	LPCWSTR lpData,
	DWORD dwType,
	CONST BYTE* lpDataEx,
	BOOL SetValueEx,
	LPWSTR ApiName
	)
{
	LPWSTR pRootKey;
	LPWSTR StringW = NULL;
	DWORD dwValue = 0;
	WCHAR tBuff[LOGBUFFERSIZEEXTRA];
	
	if (!ARGUMENT_PRESENT(ApiName))
		return;

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, ApiName);
	_strcatW(tBuff, OpenBracketW);

	//get hkey value
	pRootKey = LogGetHiveKeyW(hKey);
	if ( pRootKey != NULL ) {
		_strcatW(tBuff, pRootKey);
	} else {
		//query hkey value name, put hex value on error
		if ( QueryKeyName(hKey, (PVOID)_strendW(tBuff), LOGBUFFERSIZELONG, TRUE) == FALSE) {
			_strcatW(tBuff, HexPrepW);
			utohexW((ULONG_PTR)hKey, _strendW(tBuff));
		}
	}

	//put lpSubKeyValueName as Key or Value
	if ( ARGUMENT_PRESENT(lpSubKeyValueName) ) {
		__try {
			if ( SetValueEx == TRUE ) {
				_strcatW(tBuff, CommaExW);
			} else {
				_strcatW(tBuff, SlashW);
			}
			_strncpyW(_strendW(tBuff), LOGBUFFERSIZELONG, lpSubKeyValueName, LOGBUFFERSIZELONG);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, ADVAPI32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	}

	//parse SetValueEx/SetValue
	if ( SetValueEx == TRUE ) {

		//put registry type
		_strcatW(tBuff, CommaExW);
		LogPutRegTypeW(tBuff, dwType);

		//put value
		__try {

			switch ( dwType ) {

			case REG_SZ:
			case REG_EXPAND_SZ:

				_strcatW(tBuff, CommaExW);
				StringW = (LPWSTR)lpDataEx;
				if ( StringW != NULL ) {
					_strncpyW(_strendW(tBuff), LOGBUFFERSIZELONG, StringW, LOGBUFFERSIZELONG);
				} else {
					_strcatW(tBuff, NullStrW);
				}

				break;

			case REG_DWORD:

				_strcatW(tBuff, ColonW);
				if ( lpDataEx != NULL ) {
					dwValue = *lpDataEx;
					ultostrW(dwValue, _strendW(tBuff));
				} else {
					_strcatW(tBuff, NullStrW);
				}
				break;

			default:
				break;
			}
		
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, ADVAPI32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
		/* example of result: RegSetValueEx(\RegistryPath\Key, ValueName, RegType: value */
	} else {

		_strcatW(tBuff, CommaExW);
		//put lpData
		if ( ARGUMENT_PRESENT(lpData) ) {
			__try {
				_strncpyW(_strendW(tBuff), LOGBUFFERSIZELONG, lpData, LOGBUFFERSIZELONG);
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				_strcatW(tBuff, ADVAPI32_EXCEPTION);
				utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
			}
		} else {
			_strcatW(tBuff, NullStrW);
		}
		/*example of result: RegSetValue(\RegistryPath\lpSubKey, lpData)*/
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZEEXTRA, LOG_NORMAL);
	//OutputDebugStringW(tBuff);
}

LSTATUS APIENTRY RegSetValueHookA(
	HKEY hKey,
	LPCSTR lpSubKey,
	DWORD dwType,
	LPCSTR lpData,
	DWORD cbData
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegSetValueA(hKey, lpSubKey, dwType, lpData, cbData);
		}
		Tls->ourcall = TRUE;
	}

	LogRegSetValueExA(hKey, lpSubKey, lpData, 0, NULL, FALSE, "RegSetValue");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegSetValueA(hKey, lpSubKey, dwType, lpData, cbData);
}

LSTATUS APIENTRY RegSetValueHookW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	DWORD dwType,
	LPCWSTR lpData,
	DWORD cbData
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegSetValueW(hKey, lpSubKey, dwType, lpData, cbData);
		}
		Tls->ourcall = TRUE;
	}

	LogRegSetValueExW(hKey, lpSubKey, lpData, 0, NULL, FALSE, L"RegSetValue");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegSetValueW(hKey, lpSubKey, dwType, lpData, cbData);
}

LSTATUS APIENTRY RegSetValueExHookA(
	HKEY hKey,
	LPCSTR lpValueName,
	DWORD Reserved,
	DWORD dwType,
	CONST BYTE* lpData,
	DWORD cbData
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
		}
		Tls->ourcall = TRUE;
	}

	LogRegSetValueExA(hKey, lpValueName, NULL, dwType, lpData, TRUE, "RegSetValueEx");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

LSTATUS APIENTRY RegSetValueExHookW(
	HKEY hKey,
	LPCWSTR lpValueName,
	DWORD Reserved,
	DWORD dwType,
	CONST BYTE* lpData,
	DWORD cbData
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
		}
		Tls->ourcall = TRUE;
	}

	LogRegSetValueExW(hKey, lpValueName, NULL, dwType, lpData, TRUE, L"RegSetValueEx");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

VOID LogSaveKeyA(
	HKEY hKey,
	LPCSTR lpFile,
	LPSTR ApiName
	)
{
	LPSTR pRootKey;
	CHAR tBuff[LOGBUFFERSIZEEXTRA];

	if (!ARGUMENT_PRESENT(ApiName))
		return;

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyA(tBuff, ApiName);
	_strcatA(tBuff, OpenBracketA);

	//get hkey value
	pRootKey = LogGetHiveKeyA(hKey);
	if ( pRootKey != NULL ) {
		_strcatA(tBuff, pRootKey);
	} else {
		//query hkey value name, put hex value on error
		if ( QueryKeyName(hKey, (PVOID)_strendA(tBuff), LOGBUFFERSIZELONG, FALSE) == FALSE) {
			_strcatA(tBuff, HexPrepA);
			utohexA((ULONG_PTR)hKey, _strendA(tBuff));
		}
	}

	//put lpFile
	_strcatA(tBuff, CommaExA);
	if ( ARGUMENT_PRESENT(lpFile) ) {
		__try {
			_strncpyA(_strendA(tBuff), LOGBUFFERSIZELONG, lpFile, LOGBUFFERSIZELONG);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatA(tBuff, ADVAPI32_EXCEPTION_A);
			utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
		}
	} else {
		_strcatA(tBuff, NullStrA);
	}

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZEEXTRA, LOG_NORMAL);
}

VOID LogSaveKeyW(
	HKEY hKey,
	LPCWSTR lpFile,
	LPWSTR ApiName
	)
{
	LPWSTR pRootKey;
	WCHAR tBuff[LOGBUFFERSIZEEXTRA];

	if (!ARGUMENT_PRESENT(ApiName))
		return;

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, ApiName);
	_strcatW(tBuff, OpenBracketW);

	//get hkey value
	pRootKey = LogGetHiveKeyW(hKey);
	if ( pRootKey != NULL ) {
		_strcatW(tBuff, pRootKey);
	} else {
		//query hkey value name, put hex value on error
		if ( QueryKeyName(hKey, (PVOID)_strendW(tBuff), LOGBUFFERSIZELONG, TRUE) == FALSE) {
			_strcatW(tBuff, HexPrepW);
			utohexW((ULONG_PTR)hKey, _strendW(tBuff));
		}
	}

	//put lpFile
	_strcatW(tBuff, CommaExW);
	if ( ARGUMENT_PRESENT(lpFile) ) {
		__try {
			_strncpyW(_strendW(tBuff), LOGBUFFERSIZELONG, lpFile, LOGBUFFERSIZELONG);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, ADVAPI32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZEEXTRA, LOG_NORMAL);
}

LSTATUS APIENTRY RegSaveKeyHookA(
	HKEY hKey,
	LPCSTR lpFile,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegSaveKeyA(hKey, lpFile, lpSecurityAttributes);
		}
		Tls->ourcall = TRUE;
	}

	LogSaveKeyA(hKey, lpFile, "RegSaveKey");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegSaveKeyA(hKey, lpFile, lpSecurityAttributes);
}

LSTATUS APIENTRY RegSaveKeyHookW(
	HKEY hKey,
	LPCWSTR lpFile,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegSaveKeyW(hKey, lpFile, lpSecurityAttributes);
		}
		Tls->ourcall = TRUE;
	}

	LogSaveKeyW(hKey, lpFile, L"RegSaveKey");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegSaveKeyW(hKey, lpFile, lpSecurityAttributes);
}

LSTATUS APIENTRY RegSaveKeyExHookA(
	HKEY hKey,
	LPCSTR lpFile,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD Flags
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegSaveKeyExA(hKey, lpFile, lpSecurityAttributes, Flags);
		}
		Tls->ourcall = TRUE;
	}

	LogSaveKeyA(hKey, lpFile, "RegSaveKeyEx");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegSaveKeyExA(hKey, lpFile, lpSecurityAttributes, Flags);
}

LSTATUS APIENTRY RegSaveKeyExHookW(
	HKEY hKey,
	LPCWSTR lpFile,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD Flags
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegSaveKeyExW(hKey, lpFile, lpSecurityAttributes, Flags);
		}
		Tls->ourcall = TRUE;
	}

	LogSaveKeyW(hKey, lpFile, L"RegSaveKeyEx");

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegSaveKeyExW(hKey, lpFile, lpSecurityAttributes, Flags);
}

LSTATUS APIENTRY RegLoadKeyHookA(
	HKEY    hKey,
	LPCSTR  lpSubKey,
	LPCSTR  lpFile
	)
{
	PTLS Tls;
	LPSTR pRootKey;
	CHAR tBuff[LOGBUFFERSIZEEXTRA];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegLoadKeyA(hKey, lpSubKey, lpFile);
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyA(tBuff, "RegLoadKey(");

	//get hkey value
	pRootKey = LogGetHiveKeyA(hKey);
	if ( pRootKey != NULL ) {
		_strcatA(tBuff, pRootKey);
	} else {
		//query hkey value name, put hex value on error
		if ( QueryKeyName(hKey, (PVOID)_strendA(tBuff), LOGBUFFERSIZELONG, FALSE) == FALSE) {
			_strcatA(tBuff, HexPrepA);
			utohexA((ULONG_PTR)hKey, _strendA(tBuff));
		}
	}

	//put lpSubKey
	if ( ARGUMENT_PRESENT(lpSubKey) ) {
		__try {
			_strcatA(tBuff, SlashA);
			_strncpyA(_strendA(tBuff), LOGBUFFERSIZELONG, lpSubKey, LOGBUFFERSIZELONG);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatA(tBuff, ADVAPI32_EXCEPTION_A);
			utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
		}
	}

	//put lpFile
	_strcatA(tBuff, CommaExA);
	if ( ARGUMENT_PRESENT(lpFile) ) {
		__try {
			_strncpyA(_strendA(tBuff), LOGBUFFERSIZELONG, lpFile, LOGBUFFERSIZELONG);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatA(tBuff, ADVAPI32_EXCEPTION_A);
			utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
		}
	} else {
		_strcatA(tBuff, NullStrA);
	}
	/* result = RegLoadKey(\RegistryPath\lpSubKey, FileName); */

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZEEXTRA, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegLoadKeyA(hKey, lpSubKey, lpFile);
}

LSTATUS APIENTRY RegLoadKeyHookW(
	HKEY    hKey,
	LPCWSTR  lpSubKey,
	LPCWSTR  lpFile
	)
{
	PTLS Tls;
	LPWSTR pRootKey;
	WCHAR tBuff[LOGBUFFERSIZEEXTRA];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegLoadKeyW(hKey, lpSubKey, lpFile);
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"RegLoadKey(");

	//get hkey value
	pRootKey = LogGetHiveKeyW(hKey);
	if ( pRootKey != NULL ) {
		_strcatW(tBuff, pRootKey);
	} else {
		//query hkey value name, put hex value on error
		if ( QueryKeyName(hKey, (PVOID)_strendW(tBuff), LOGBUFFERSIZELONG, TRUE) == FALSE) {
			_strcatW(tBuff, HexPrepW);
			utohexW((ULONG_PTR)hKey, _strendW(tBuff));
		}
	}

	//put lpSubKey
	if ( ARGUMENT_PRESENT(lpSubKey) ) {
		__try {
			_strcatW(tBuff, SlashW);
			_strncpyW(_strendW(tBuff), LOGBUFFERSIZELONG, lpSubKey, LOGBUFFERSIZELONG);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, ADVAPI32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	}

	//put lpFile
	_strcatW(tBuff, CommaExW);
	if ( ARGUMENT_PRESENT(lpFile) ) {
		__try {
			_strncpyW(_strendW(tBuff), LOGBUFFERSIZELONG, lpFile, LOGBUFFERSIZELONG);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, ADVAPI32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}
	/* result = RegLoadKey(\RegistryPath\lpSubKey, FileName); */

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZEEXTRA, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegLoadKeyW(hKey, lpSubKey, lpFile);
}

VOID LogFileSecurityA(
	LPCSTR ApiName,
	LPCSTR lpFileName
	)
{
	CHAR tBuff[LOGBUFFERSIZELONG];
	
	if (!ARGUMENT_PRESENT(ApiName))
		return;

	//put prolog
	_strcpyA(tBuff, ApiName);
	_strcatA(tBuff, OpenBracketA);

	//put lpFileName
	if ( ARGUMENT_PRESENT( lpFileName )) {	
		__try {
			_strncpyA(_strendA(tBuff), MAX_PATH * 2, lpFileName, MAX_PATH * 2);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatA(tBuff, ADVAPI32_EXCEPTION_A);
			utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
		}
	} else {
		_strcatA(tBuff, NullStrA);
	}

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);
}

VOID LogFileSecurityW(
	LPCWSTR ApiName,
	LPCWSTR lpFileName
	)
{
	WCHAR tBuff[LOGBUFFERSIZELONG];
	
	if (!ARGUMENT_PRESENT(ApiName))
		return;

	//put prolog
	_strcpyW(tBuff, ApiName);
	_strcatW(tBuff, OpenBracketW);

	//put lpFileName
	if ( ARGUMENT_PRESENT( lpFileName )) {	
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH * 2, lpFileName, MAX_PATH * 2);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, ADVAPI32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);
}

BOOL WINAPI SetFileSecurityHookW(
	LPCWSTR lpFileName,
	SECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR pSecurityDescriptor
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pSetFileSecurityW(lpFileName, SecurityInformation, pSecurityDescriptor);
		}
		Tls->ourcall = TRUE;
	}

	LogFileSecurityW(L"SetFileSecurity", lpFileName);

	if ( Tls ) Tls->ourcall = FALSE;
	return pSetFileSecurityW(lpFileName, SecurityInformation, pSecurityDescriptor);
}

DWORD WINAPI SetNamedSecurityInfoHookA(
    LPSTR pObjectName,
    SE_OBJECT_TYPE ObjectType,
    SECURITY_INFORMATION SecurityInfo,
    PSID psidOwner,
    PSID psidGroup,
    PACL pDacl,
    PACL pSacl
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pSetNamedSecurityInfoA(pObjectName, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl);
		}
		Tls->ourcall = TRUE;
	}

	switch ( ObjectType ) {
	case SE_FILE_OBJECT:
		LogFileSecurityA("SetNamedSecurityInfo", pObjectName);
		break;
	default:
		break;
	}

	if ( Tls ) Tls->ourcall = FALSE;
	return pSetNamedSecurityInfoA(pObjectName, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl);
}

DWORD WINAPI SetNamedSecurityInfoHookW(
    LPWSTR pObjectName,
    SE_OBJECT_TYPE ObjectType,
    SECURITY_INFORMATION SecurityInfo,
    PSID psidOwner,
    PSID psidGroup,
    PACL pDacl,
    PACL pSacl
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pSetNamedSecurityInfoW(pObjectName, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl);
		}
		Tls->ourcall = TRUE;
	}

	switch ( ObjectType ) {
	case SE_FILE_OBJECT:
		LogFileSecurityW(L"SetNamedSecurityInfo", pObjectName);
		break;
	default:
		break;
	}
	 
	if ( Tls ) Tls->ourcall = FALSE;
	return pSetNamedSecurityInfoW(pObjectName, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl);
}

DWORD WINAPI SetSecurityInfoHook(
    HANDLE handle,
    SE_OBJECT_TYPE ObjectType,
    SECURITY_INFORMATION SecurityInfo,
    PSID psidOwner,
    PSID psidGroup,
    PACL pDacl,
    PACL pSacl
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pSetSecurityInfo(handle, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl);
		}
		Tls->ourcall = TRUE;
	}

	switch ( ObjectType ) {
	case SE_FILE_OBJECT:
		LogAsCallA("SetSecurityInfo()", LOG_NORMAL);
		break;
	default:
		break;
	}
	 
	if ( Tls ) Tls->ourcall = FALSE;
	return pSetSecurityInfo(handle, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl);
}