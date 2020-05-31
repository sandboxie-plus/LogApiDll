/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	kernel32_hook.c

Abstract:

	Kernel32 API hook implementation.

	Last change 05.02.13

--*/

#include "..\global.h"
#include "kernel32_hook.h"

PlstrcmpA plstrcmpA = NULL;
PlstrcmpW plstrcmpW = NULL;
PlstrcmpiA plstrcmpiA = NULL;
PlstrcmpiW plstrcmpiW = NULL;
PIsDebuggerPresent pIsDebuggerPresent = NULL;
PCheckRemoteDebuggerPresent pCheckRemoteDebuggerPresent = NULL;
PGetSystemDefaultLangID pGetSystemDefaultLangID = NULL;
PFreeLibrary pFreeLibrary = NULL;
PExitProcess pExitProcess = NULL;
PGetSystemDEPPolicy pGetSystemDEPPolicy = NULL;
PGetFileAttributesW pGetFileAttributesW = NULL;
PCreatePipe pCreatePipe = NULL;
PConnectNamedPipe pConnectNamedPipe = NULL;
PCreateNamedPipeW pCreateNamedPipeW = NULL;
PCallNamedPipeW pCallNamedPipeW = NULL;
PGetModuleHandleW pGetModuleHandleW = NULL;
PGetVolumeInformationW pGetVolumeInformationW = NULL;
PGetComputerNameW pGetComputerNameW = NULL;
PSearchPathW pSearchPathW = NULL;
PDeleteFileW pDeleteFileW = NULL;
PRemoveDirectoryW pRemoveDirectoryW = NULL;
POpenMutexW pOpenMutexW = NULL;
PCreateMutexW pCreateMutexW = NULL;
PCreateEventW pCreateEventW = NULL;
PCreateProcessA pCreateProcessA = NULL;
PCreateProcessW pCreateProcessW = NULL;
PCreateFileW pCreateFileW = NULL;
PCreateFileMappingW pCreateFileMappingW = NULL;
PCreateRemoteThread pCreateRemoteThread = NULL;
PCreateRemoteThreadEx pCreateRemoteThreadEx = NULL;
PCreateToolhelp32Snapshot pCreateToolhelp32Snapshot = NULL;
PProcess32FirstW pProcess32FirstW = NULL;
PProcess32NextW pProcess32NextW = NULL;
PFindFirstFileExW pFindFirstFileExW = NULL;
PFindNextFileW pFindNextFileW = NULL;
PFindFirstFileNameW pFindFirstFileNameW = NULL;
PFindNextFileNameW pFindNextFileNameW = NULL;
PCreateDirectoryExW pCreateDirectoryExW = NULL;
PCreateDirectoryW pCreateDirectoryW = NULL;
PCopyFileA pCopyFileA = NULL;
PCopyFileW pCopyFileW = NULL;
PCopyFileExA pCopyFileExA = NULL;
PCopyFileExW pCopyFileExW = NULL;
PMoveFileA pMoveFileA = NULL;
PMoveFileW pMoveFileW = NULL;
PMoveFileExA pMoveFileExA = NULL;
PMoveFileExW pMoveFileExW = NULL;

int WINAPI CompareHandlerA(
	PFNstrcmpA pFunction,
	LPCSTR lpString1,
	LPCSTR lpString2
	)
{
	PTLS Tls;
	CHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		if ( Tls->ourcall ) 
			return pFunction(lpString1, lpString2);

		Tls->ourcall = TRUE;
		if ( Tls->showcomparision == TRUE ) {

			RtlSecureZeroMemory(tBuff, sizeof(tBuff));

			//put prolog
			if ( pFunction == plstrcmpA ) 
				_strcpyA(tBuff, "lstrcmp(");
			if ( pFunction == plstrcmpiA ) 
				_strcpyA(tBuff, "lstrcmpi(");

			__try {
				if ( ARGUMENT_PRESENT(lpString1) ) {
					_strncpyA(_strendA(tBuff), MAX_PATH * 2, lpString1, MAX_PATH * 2);
				} else {
					_strcatA(tBuff, NoStringA);
				}
				_strcatA(tBuff, CommaA);
				if ( ARGUMENT_PRESENT(lpString2) ) {
					_strncpyA(_strendA(tBuff), MAX_PATH * 2, lpString2, MAX_PATH * 2);
				} else {
					_strcatA(tBuff, NoStringA);
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				_strcatA(tBuff, KERNEL32_EXCEPTION_A);
				utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
			}
			//put epilog and log
			_strcatA(tBuff, CloseBracketA);
			PushToLogA(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);
		}
		Tls->ourcall = FALSE;
	}
	return pFunction(lpString1, lpString2);
}

int WINAPI CompareHandlerW(
	PFNstrcmpW pFunction,
	LPCWSTR lpString1,
	LPCWSTR lpString2
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		if ( Tls->ourcall ) 
			return pFunction(lpString1, lpString2);

		Tls->ourcall = TRUE;
		if ( Tls->showcomparision == TRUE ) {

			RtlSecureZeroMemory(tBuff, sizeof(tBuff));
			
			//put prolog
			if ( pFunction == plstrcmpW ) 
				_strcpyW(tBuff, L"lstrcmp(");
			if ( pFunction == plstrcmpiW ) 
				_strcpyW(tBuff, L"lstrcmpi(");

			__try {
				if ( ARGUMENT_PRESENT(lpString1) ) {
					_strncpyW(_strendW(tBuff), MAX_PATH * 2, lpString1, MAX_PATH * 2);
				} else {
					_strcatW(tBuff, NoStringW);
				}
				_strcatW(tBuff, CommaW);
				if ( ARGUMENT_PRESENT(lpString2) ) {
					_strncpyW(_strendW(tBuff), MAX_PATH * 2, lpString2, MAX_PATH * 2);
				} else {
					_strcatW(tBuff, NoStringW);
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				_strcatW(tBuff, KERNEL32_EXCEPTION);
				utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
			}
			//put epilog and log
			_strcatW(tBuff, CloseBracketW);
			PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);
		}
		Tls->ourcall = FALSE;
	}
	return pFunction(lpString1, lpString2);
}

int WINAPI lstrcmpHookA(
    LPCSTR lpString1,
    LPCSTR lpString2
	)
{
	return CompareHandlerA((PFNstrcmpA)plstrcmpA, lpString1, lpString2);
}

int WINAPI lstrcmpHookW(
    LPCWSTR lpString1,
    LPCWSTR lpString2
    )
{
	return CompareHandlerW((PFNstrcmpW)plstrcmpW, lpString1, lpString2);
}

int WINAPI lstrcmpiHookA(
	LPCSTR lpString1,
	LPCSTR lpString2
	)
{
	return CompareHandlerA((PFNstrcmpA)plstrcmpiA, lpString1, lpString2);
}

int WINAPI lstrcmpiHookW(
    LPCWSTR lpString1,
    LPCWSTR lpString2
    )
{
	return CompareHandlerW((PFNstrcmpW)plstrcmpiW, lpString1, lpString2);
}

VOID WINAPI OutputDebugStringHookA(
	LPCSTR lpOutputString
	)
{
	PTLS Tls;
	CHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			pOutputDebugStringA(lpOutputString);
			return;
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyA(tBuff, "OutputDebugString(");

	//put lpOutputString
	if ( ARGUMENT_PRESENT(lpOutputString) ) {
		__try {	 
			_strncpyA(_strendA(tBuff), MAX_PATH * 2, lpOutputString, MAX_PATH * 2);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatA(tBuff, KERNEL32_EXCEPTION_A);
			utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
		}
	} else {
		_strcatA(tBuff, NoStringA);
	}

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	pOutputDebugStringA(lpOutputString);
}

BOOL WINAPI IsDebuggerPresentHook(
	VOID
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pIsDebuggerPresent();
		}
		Tls->ourcall = TRUE;
	}

	//put prolog and log
	LogAsCall(L"IsDebuggerPresent()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pIsDebuggerPresent();
}

BOOL WINAPI CheckRemoteDebuggerPresentHook(
	HANDLE hProcess,
	PBOOL pbDebuggerPresent
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog and log
	LogAsCall(L"CheckRemoteDebuggerPresent()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent);
}

LANGID WINAPI GetSystemDefaultLangIDHook(
	VOID
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pGetSystemDefaultLangID();
		}
		Tls->ourcall = TRUE;
	}

	//put prolog and log
	LogAsCall(L"GetSystemDefaultLangID()", LOG_NORMAL); 

	if ( Tls ) Tls->ourcall = FALSE;
	return pGetSystemDefaultLangID();
}

BOOL WINAPI FreeLibraryHook(
	HMODULE hLibModule
	)
{
	PTLS Tls;
	NTSTATUS Status;
	PLDR_DATA_TABLE_ENTRY Entry;
	WCHAR tBuff[LOGBUFFERSIZE];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pFreeLibrary(hLibModule);
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"FreeLibrary(");

	//query dll loader entry and put dllname to the log
	Entry = NULL;
	Status = QueryLoaderEntryForDllHandle((PVOID)hLibModule, &Entry);
	if ( NT_SUCCESS(Status )) {
		__try {
			if ( Entry != NULL ) {
				if ( Entry->FullDllName.Buffer != NULL ) {			 
					_strncpyW(_strendW(tBuff), MAX_PATH, Entry->FullDllName.Buffer, MAX_PATH);
				} else _strcatW(tBuff, NullStrW);
			} else _strcatW(tBuff, NullStrW);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, KERNEL32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		//corresponding entry not found, log null
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pFreeLibrary(hLibModule);
}

VOID WINAPI ExitProcessHook(
	UINT uExitCode
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZESMALL];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			pExitProcess(uExitCode);
			return;
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"ExitProcess("); 

	//put exit code
	ultostrW(uExitCode, _strendW(tBuff));

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZESMALL, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	pExitProcess(uExitCode);
	return;
}

DEP_SYSTEM_POLICY_TYPE WINAPI GetSystemDEPPolicyHook(
	VOID
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pGetSystemDEPPolicy();
		}
		Tls->ourcall = TRUE;
	}	

	//put prolog and log
	LogAsCall(L"GetSystemDEPPolicy()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;	 
	return pGetSystemDEPPolicy();
}

DWORD WINAPI GetFileAttributesHookW(  //GetFileAttributesA GetFileAttributesW
	LPCWSTR lpFileName
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pGetFileAttributesW(lpFileName);
		}
		Tls->ourcall = TRUE;
	}	

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"GetFileAttributes(");

	//put lpFileName
	if (ARGUMENT_PRESENT(lpFileName)) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH * 2, lpFileName, MAX_PATH * 2);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, KERNEL32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;	 
	return pGetFileAttributesW(lpFileName);
}

BOOL WINAPI CreatePipeHook(
	PHANDLE hReadPipe,
	PHANDLE hWritePipe,
	LPSECURITY_ATTRIBUTES lpPipeAttributes,
	DWORD nSize
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCreatePipe(hReadPipe, hWritePipe, lpPipeAttributes, nSize);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog and log
	LogAsCall(L"CreatePipe()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCreatePipe(hReadPipe, hWritePipe, lpPipeAttributes, nSize);
}

BOOL WINAPI ConnectNamedPipeHook(
	HANDLE hNamedPipe,
	LPOVERLAPPED lpOverlapped
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pConnectNamedPipe(hNamedPipe, lpOverlapped);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog and log
	LogAsCall(L"ConnectNamedPipe()", LOG_NORMAL); 

	if ( Tls ) Tls->ourcall = FALSE;
	return pConnectNamedPipe(hNamedPipe, lpOverlapped);
}


HANDLE WINAPI CreateNamedPipeHookW(  //CreateNamedPipeA CreateNamedPipeW
	LPCWSTR lpName,
	DWORD dwOpenMode,
	DWORD dwPipeMode,
	DWORD nMaxInstances,
	DWORD nOutBufferSize,
	DWORD nInBufferSize,
	DWORD nDefaultTimeOut,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZE];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCreateNamedPipeW(
				lpName, 
				dwOpenMode, 
				dwPipeMode, 
				nMaxInstances, 
				nOutBufferSize, 
				nInBufferSize, 
				nDefaultTimeOut, 
				lpSecurityAttributes
				);
		}
		Tls->ourcall = TRUE;
	}	

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"CreateNamedPipe("); 

	//put lpName
	if ( ARGUMENT_PRESENT(lpName) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH, lpName, MAX_PATH);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, KERNEL32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;	 
	return pCreateNamedPipeW(
		lpName, 
		dwOpenMode, 
		dwPipeMode, 
		nMaxInstances, 
		nOutBufferSize, 
		nInBufferSize, 
		nDefaultTimeOut, 
		lpSecurityAttributes
		);
}

BOOL WINAPI CallNamedPipeHookW(  //CallNamedPipeA CallNamePipeW
	LPCWSTR lpNamedPipeName,
	LPVOID lpInBuffer,
	DWORD nInBufferSize,
	LPVOID lpOutBuffer,
	DWORD nOutBufferSize,
	LPDWORD lpBytesRead,
	DWORD nTimeOut
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZE];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCallNamedPipeW(
				lpNamedPipeName, 
				lpInBuffer, 
				nInBufferSize, 
				lpOutBuffer, 
				nOutBufferSize, 
				lpBytesRead, 
				nTimeOut
				);
		}
		Tls->ourcall = TRUE;
	}	

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"CallNamedPipe("); 

	//put lpNamedPipeName
	if ( ARGUMENT_PRESENT(lpNamedPipeName) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH, lpNamedPipeName, MAX_PATH);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, KERNEL32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;		
	return pCallNamedPipeW(
		lpNamedPipeName, 
		lpInBuffer, 
		nInBufferSize, 
		lpOutBuffer, 
		nOutBufferSize, 
		lpBytesRead, 
		nTimeOut
		);
}

HMODULE WINAPI GetModuleHandleHookW(  //GetModuleHandleA GetModuleHandleW
	LPCWSTR lpModuleName
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pGetModuleHandleW(lpModuleName);
		}
		Tls->ourcall = TRUE;
	}	

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"GetModuleHandle("); 

	//put lpModuleName
	if ( ARGUMENT_PRESENT(lpModuleName) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH * 2, lpModuleName, MAX_PATH * 2);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, KERNEL32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pGetModuleHandleW(lpModuleName);
}

BOOL WINAPI GetVolumeInformationHookW(   //GetVolumeInformationA GetVolumeInformationW
	LPCWSTR lpRootPathName,
	LPWSTR lpVolumeNameBuffer,
	DWORD nVolumeNameSize,
	LPDWORD lpVolumeSerialNumber,
	LPDWORD lpMaximumComponentLength,
	LPDWORD lpFileSystemFlags,
	LPWSTR lpFileSystemNameBuffer,
	DWORD nFileSystemNameSize
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZE];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pGetVolumeInformationW(
				lpRootPathName,
				lpVolumeNameBuffer,
				nVolumeNameSize,
				lpVolumeSerialNumber,
				lpMaximumComponentLength,
				lpFileSystemFlags,
				lpFileSystemNameBuffer,
				nFileSystemNameSize
				);
		}
		Tls->ourcall = TRUE;
	}	

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"GetVolumeInformation("); 

	//put lpRootPathName
	if ( ARGUMENT_PRESENT(lpRootPathName) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH, lpRootPathName, MAX_PATH);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, KERNEL32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pGetVolumeInformationW(
		lpRootPathName,
		lpVolumeNameBuffer,
		nVolumeNameSize,
		lpVolumeSerialNumber,
		lpMaximumComponentLength,
		lpFileSystemFlags,
		lpFileSystemNameBuffer,
		nFileSystemNameSize
		);
}

BOOL WINAPI GetComputerNameHookW(  //GetComputerNameA GetComputerNameW
	LPWSTR lpBuffer,
	LPDWORD nSize
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = TRUE;
		if ( Tls->ourcall ) {
			return pGetComputerNameW(lpBuffer, nSize);
		}
		Tls->ourcall = TRUE;
	}	

	LogAsCall(L"GetComputerName()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pGetComputerNameW(lpBuffer, nSize);
}

DWORD WINAPI SearchPathHookW( //SearchPathA SearchPathW
	LPCWSTR lpPath,
	LPCWSTR lpFileName,
	LPCWSTR lpExtension,
	DWORD nBufferLength,
	LPWSTR lpBuffer,
	LPWSTR *lpFilePart
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pSearchPathW(
				lpPath, 
				lpFileName, 
				lpExtension, 
				nBufferLength, 
				lpBuffer, 
				lpFilePart
				);
		}
		Tls->ourcall = TRUE;
	}	

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"SearchPath("); 

	__try {
		//put lpPath
		if ( ARGUMENT_PRESENT(lpPath) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH * 2, lpPath, MAX_PATH * 2);
		} else {
			_strcatW(tBuff, NullStrW);
		}
		_strcatW(tBuff, CommaExW);
		//put lpFileName
		if ( ARGUMENT_PRESENT(lpFileName) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH * 2, lpFileName, MAX_PATH * 2);
		} else {
			_strcatW(tBuff, NullStrW);
		}
		_strcatW(tBuff, CommaExW);
		//put lpExtension
		if ( ARGUMENT_PRESENT(lpExtension) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH * 2, lpExtension, MAX_PATH * 2);
		} else {
			_strcatW(tBuff, NullStrW);
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatW(tBuff, KERNEL32_EXCEPTION);
		utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pSearchPathW(
		lpPath, 
		lpFileName, 
		lpExtension, 
		nBufferLength, 
		lpBuffer, 
		lpFilePart
		);
}

BOOL WINAPI DeleteFileHookW( //DeleteFileA DeleteFileW
	LPCWSTR lpFileName
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pDeleteFileW(lpFileName);
		}
		Tls->ourcall = TRUE;
	}	

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"DeleteFile(");

	//put lpFileName
	if ( ARGUMENT_PRESENT(lpFileName) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH * 2, lpFileName, MAX_PATH * 2);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, KERNEL32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pDeleteFileW(lpFileName);
}

BOOL WINAPI RemoveDirectoryHookW(  //RemoveDirectoryA RemoveDirectoryW
	LPCWSTR lpPathName
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRemoveDirectoryW(lpPathName);
		}
		Tls->ourcall = TRUE;
	}	

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"RemoveDirectory(");

	//put lpPathName
	if ( ARGUMENT_PRESENT(lpPathName) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH * 2, lpPathName, MAX_PATH * 2);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, KERNEL32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);


	if ( Tls ) Tls->ourcall = FALSE;
	return pRemoveDirectoryW(lpPathName);
}

HANDLE WINAPI OpenMutexHookW(  //OpenMutexA OpenMutexW
	DWORD dwDesiredAccess,
	BOOL bInheritHandle,
	LPCWSTR lpName
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pOpenMutexW(dwDesiredAccess, bInheritHandle, lpName);
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"OpenMutex(");

	//put lpName
	if ( ARGUMENT_PRESENT(lpName) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH * 2, lpName, MAX_PATH * 2);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, KERNEL32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pOpenMutexW(dwDesiredAccess, bInheritHandle, lpName);
}

HANDLE WINAPI CreateMutexHookW(
	LPSECURITY_ATTRIBUTES lpMutexAttributes,
	BOOL bInitialOwner,
	LPCWSTR lpName
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCreateMutexW(lpMutexAttributes, bInitialOwner, lpName);
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"CreateMutex(");

	//put lpName
	if ( ARGUMENT_PRESENT(lpName) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH * 2, lpName, MAX_PATH * 2);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, KERNEL32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCreateMutexW(lpMutexAttributes, bInitialOwner, lpName);
}

HANDLE WINAPI CreateEventHookW(
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	BOOL bManualReset,
	BOOL bInitialState,
	LPCWSTR lpName
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCreateEventW(lpEventAttributes, bManualReset, bInitialState, lpName);
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"CreateEvent(");

	//put lpName
	if ( ARGUMENT_PRESENT(lpName) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH * 2, lpName, MAX_PATH * 2);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, KERNEL32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCreateEventW(lpEventAttributes, bManualReset, bInitialState, lpName);
}

BOOL WINAPI CreateProcessHookA(
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	)
{
	PTLS Tls;
	CHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCreateProcessA(
				lpApplicationName, 
				lpCommandLine, 
				lpProcessAttributes,
				lpThreadAttributes,
				bInheritHandles, 
				dwCreationFlags, 
				lpEnvironment, 
				lpCurrentDirectory, 
				lpStartupInfo, 
				lpProcessInformation
				);
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyA(tBuff, "CreateProcess(");

	__try {
		//put lpApplicationName
		if ( ARGUMENT_PRESENT(lpApplicationName) ) {
			_strncpyA(_strendA(tBuff), MAX_PATH * 2, lpApplicationName, MAX_PATH * 2);
		} else {
			_strcatA(tBuff, NullStrA);
		}
		_strcatA(tBuff, CommaExA);
		//put lpCommandLine
		if ( ARGUMENT_PRESENT(lpCommandLine) ) {
			_strncpyA(_strendA(tBuff), MAX_PATH * 2, lpCommandLine, MAX_PATH * 2);
		} else {
			_strcatA(tBuff, NullStrA);
		}
		_strcatA(tBuff, CommaExA);
		//put lpCurrentDirectory
		if ( ARGUMENT_PRESENT(lpCurrentDirectory) ) {
			_strncpyA(_strendA(tBuff), MAX_PATH * 2, lpCurrentDirectory, MAX_PATH * 2);
		} else {
			_strcatA(tBuff, NullStrA);
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatA(tBuff, KERNEL32_EXCEPTION_A);
		utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
	}

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCreateProcessA(
		lpApplicationName, 
		lpCommandLine, 
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles, 
		dwCreationFlags, 
		lpEnvironment, 
		lpCurrentDirectory, 
		lpStartupInfo, 
		lpProcessInformation
		);
}

BOOL WINAPI CreateProcessHookW(
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCreateProcessW(
				lpApplicationName, 
				lpCommandLine, 
				lpProcessAttributes,
				lpThreadAttributes,
				bInheritHandles, 
				dwCreationFlags, 
				lpEnvironment, 
				lpCurrentDirectory, 
				lpStartupInfo, 
				lpProcessInformation
				);
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"CreateProcess(");

	__try {
		//put lpApplicationName
		if ( ARGUMENT_PRESENT(lpApplicationName) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH * 2, lpApplicationName, MAX_PATH * 2);
		} else {
			_strcatW(tBuff, NullStrW);
		}
		_strcatW(tBuff, CommaExW);
		//put lpCommandLine
		if ( ARGUMENT_PRESENT(lpCommandLine) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH * 2, lpCommandLine, MAX_PATH * 2);
		} else {
			_strcatW(tBuff, NullStrW);
		}
		_strcatW(tBuff, CommaExW);
		//put lpCurrentDirectory
		if ( ARGUMENT_PRESENT(lpCurrentDirectory) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH * 2, lpCurrentDirectory, MAX_PATH * 2);
		} else {
			_strcatW(tBuff, NullStrW);
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatW(tBuff, KERNEL32_EXCEPTION);
		utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCreateProcessW(
		lpApplicationName, 
		lpCommandLine, 
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles, 
		dwCreationFlags, 
		lpEnvironment, 
		lpCurrentDirectory, 
		lpStartupInfo, 
		lpProcessInformation
		);
}

HANDLE WINAPI CreateFileHookW(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCreateFileW(
				lpFileName,
				dwDesiredAccess,
				dwShareMode,
				lpSecurityAttributes,
				dwCreationDisposition,
				dwFlagsAndAttributes,
				hTemplateFile
				);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog depending on flags
	switch ( dwCreationDisposition ) {
	case CREATE_NEW:
	case CREATE_ALWAYS:
	case OPEN_ALWAYS:
		RtlSecureZeroMemory(tBuff, sizeof(tBuff));
		_strcpyW(tBuff, L"CreateFile(");
		//put lpFileName
		if ( ARGUMENT_PRESENT(lpFileName) ) {
			__try {
				_strncpyW(_strendW(tBuff), MAX_PATH * 4, lpFileName, MAX_PATH * 4);
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				_strcatW(tBuff, KERNEL32_EXCEPTION);
				utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
			}

		} else {
			_strcatW(tBuff, NullStrW);
		}

		//put epilog and log
		_strcatW(tBuff, CloseBracketW);
		PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);
		break;	

	default:
		break;
	}

	if ( Tls ) Tls->ourcall = FALSE;
	return pCreateFileW(
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
		);
}

HANDLE WINAPI CreateFileHookVerboseW(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCreateFileW(
				lpFileName,
				dwDesiredAccess,
				dwShareMode,
				lpSecurityAttributes,
				dwCreationDisposition,
				dwFlagsAndAttributes,
				hTemplateFile
				);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog depending on flags
	switch ( dwCreationDisposition ) {
	case TRUNCATE_EXISTING:
	case OPEN_EXISTING:
		_strcpyW(tBuff, L"OpenFile(");
		break;
	default:
		_strcpyW(tBuff, L"CreateFile(");
		break;	
	}
	
	//put lpFileName
	if ( ARGUMENT_PRESENT(lpFileName) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH * 4, lpFileName, MAX_PATH * 4);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, KERNEL32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}

	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCreateFileW(
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
		);
}

HANDLE WINAPI CreateFileMappingHookW(
	HANDLE hFile,
	LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	DWORD flProtect,
	DWORD dwMaximumSizeHigh,
	DWORD dwMaximumSizeLow,
	LPCWSTR lpName
	)
{
	PTLS Tls;
	DWORD dwRet;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCreateFileMappingW(
				hFile,
				lpFileMappingAttributes,
				flProtect,
				dwMaximumSizeHigh,
				dwMaximumSizeLow,
				lpName
				);
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"CreateFileMapping(");

	__try {	 
		//check if mapping object backed by pagefile
		if ( hFile == INVALID_HANDLE_VALUE ) {
			_strcatW(tBuff, PageFileBackedW);
		} else {		 
			//otherwise try to put actual filename
			if ( shctx.osver.dwMajorVersion >= 6 ) {
				if ( pGetFinalPathNameByHandleW != NULL ) {
					dwRet = pGetFinalPathNameByHandleW(hFile, _strendW(tBuff), MAX_PATH, VOLUME_NAME_DOS);
					if ( dwRet == 0 ) {
						_strcatW(tBuff, NullStrW);
					}
				} else {
					_strcatW(tBuff, HexPrepW);
					utohexW((ULONG_PTR)hFile, _strendW(tBuff));
				}
			} else {
				_strcatW(tBuff, HexPrepW);
				utohexW((ULONG_PTR)hFile, _strendW(tBuff));
			}
		}
		_strcatW(tBuff, CommaExW);
		//put lpName
		if ( ARGUMENT_PRESENT(lpName) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH, lpName, MAX_PATH);
		} else {
			_strcatW(tBuff, NullStrW);
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatW(tBuff, KERNEL32_EXCEPTION);
		utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCreateFileMappingW(
		hFile,
		lpFileMappingAttributes,
		flProtect,
		dwMaximumSizeHigh,
		dwMaximumSizeLow,
		lpName
		);
}

HANDLE WINAPI CreateRemoteThreadHook(
	HANDLE hProcess,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	SIZE_T dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	DWORD dwCreationFlags,
	LPDWORD lpThreadId
	)
{
	PTLS Tls;
	DWORD dwProcessId;
	LPWSTR pApiName = NULL;
	BOOL CurrentProcess;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCreateRemoteThread(
				hProcess,
				lpThreadAttributes,
				dwStackSize,
				lpStartAddress,
				lpParameter,
				dwCreationFlags,
				lpThreadId
				);

		}
		Tls->ourcall = TRUE;
	}

	//put prolog
	CurrentProcess = (hProcess == NtCurrentProcess());
	if ( CurrentProcess ) {
		pApiName = L"CreateThread(";
	} else {
		pApiName = L"CreateRemoteThread(";
	}
	_strcpyW(tBuff, pApiName);

	//put process name if not current
	if ( CurrentProcess == FALSE ) {
		//put prolog
		dwProcessId = 0;		
		if (!QueryProcessName(hProcess, _strendW(tBuff), MAX_PATH * 2, &dwProcessId)) {
			//cannot be query name - put id instead
			if (!LogSystemProcess(dwProcessId, _strendW(tBuff))) {
				ultostrW((ULONG_PTR)dwProcessId, _strendW(tBuff));
			}
		}
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCreateRemoteThread(
		hProcess,
		lpThreadAttributes,
		dwStackSize,
		lpStartAddress,
		lpParameter,
		dwCreationFlags,
		lpThreadId
		);
}

HANDLE WINAPI CreateRemoteThreadExHook(
	HANDLE hProcess,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	SIZE_T dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	DWORD dwCreationFlags,
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	LPDWORD lpThreadId
	)
{
	PTLS Tls;
	DWORD dwProcessId;
	LPWSTR pApiName = NULL;
	BOOL CurrentProcess;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCreateRemoteThreadEx(hProcess,
				lpThreadAttributes,
				dwStackSize,
				lpStartAddress,
				lpParameter,
				dwCreationFlags,
				lpAttributeList,
				lpThreadId
				);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog
	CurrentProcess = (hProcess == NtCurrentProcess());
	if ( CurrentProcess ) {
		pApiName = L"CreateThread(";
	} else {
		pApiName = L"CreateRemoteThread(";
	}
	_strcpyW(tBuff, pApiName);

	//put process name if not current
	if ( CurrentProcess == FALSE ) {
		dwProcessId = 0;		
		if (!QueryProcessName(hProcess, _strendW(tBuff), MAX_PATH * 2, &dwProcessId)) {
			//cannot be query name - put id instead
			if (!LogSystemProcess(dwProcessId, _strendW(tBuff))) {
				ultostrW((ULONG_PTR)dwProcessId, _strendW(tBuff));
			}
		}
	} 

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCreateRemoteThreadEx(hProcess,
		lpThreadAttributes,
		dwStackSize,
		lpStartAddress,
		lpParameter,
		dwCreationFlags,
		lpAttributeList,
		lpThreadId
		);
}

HANDLE WINAPI CreateToolhelp32SnapshotHook(
	DWORD dwFlags,
	DWORD th32ProcessID
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZE];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCreateToolhelp32Snapshot(dwFlags, th32ProcessID);
		}
		Tls->ourcall = TRUE;
	}

	//refresh explorer id
	FindExplorerProcessId();

	//put prolog
	_strcpyW(tBuff, L"CreateToolhelp32Snapshot(");

	//put th32ProcessID 
	_ultostrW(th32ProcessID, _strendW(tBuff));
	_strcatW(tBuff, CommaExW);

	//put decoded dwFlags
	if ( dwFlags & TH32CS_SNAPALL ) {
		_strcatW(tBuff, L"TH32CS_SNAPALL");
	} else {
		if ( dwFlags & TH32CS_SNAPHEAPLIST ) _strcatW(tBuff, L" TH32CS_SNAPHEAPLIST");
		if ( dwFlags & TH32CS_SNAPPROCESS ) _strcatW(tBuff, L" TH32CS_SNAPPROCESS");
		if ( dwFlags & TH32CS_SNAPTHREAD ) _strcatW(tBuff, L" TH32CS_SNAPTHREAD");
		if ( dwFlags & TH32CS_SNAPMODULE ) _strcatW(tBuff, L" TH32CS_SNAPMODULE");
	}
	if ( dwFlags & TH32CS_SNAPMODULE32 ) _strcatW(tBuff, L" TH32CS_SNAPMODULE32");
	if ( dwFlags & TH32CS_INHERIT ) _strcatW(tBuff, L" TH32CS_INHERIT");

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCreateToolhelp32Snapshot(dwFlags, th32ProcessID);
}

BOOL WINAPI Process32FirstHookW(
	HANDLE hSnapshot,
	LPPROCESSENTRY32W lppe
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = TRUE;
	}
	return pProcess32FirstW(hSnapshot, lppe);
}

BOOL WINAPI Process32NextHookW(
	HANDLE hSnapshot,
	LPPROCESSENTRY32W lppe
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = TRUE;
	}
	return pProcess32NextW(hSnapshot, lppe);
}

HANDLE WINAPI FindFirstFileExHookW(
	LPCWSTR lpFileName,
	FINDEX_INFO_LEVELS fInfoLevelId,
	LPVOID lpFindFileData,
	FINDEX_SEARCH_OPS fSearchOp,
	LPVOID lpSearchFilter,
	DWORD dwAdditionalFlags
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = TRUE;
		if ( Tls->ourcall ) {
			return pFindFirstFileExW(
				lpFileName, 
				fInfoLevelId, 
				lpFindFileData, 
				fSearchOp, 
				lpSearchFilter, 
				dwAdditionalFlags
				);
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"FindFirstFile(");

	//put lpFileName
	if ( ARGUMENT_PRESENT(lpFileName) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH * 4, lpFileName, MAX_PATH * 4);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, KERNEL32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pFindFirstFileExW(
		lpFileName, 
		fInfoLevelId, 
		lpFindFileData, 
		fSearchOp, 
		lpSearchFilter, 
		dwAdditionalFlags
		);
}

BOOL WINAPI FindNextFileHookW(
	HANDLE hFindFile,
	LPWIN32_FIND_DATAW lpFindFileData
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = TRUE;
		if ( Tls->ourcall ) {
			return pFindNextFileW(hFindFile, lpFindFileData);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCall(L"FindNextFile()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pFindNextFileW(hFindFile, lpFindFileData);
}

HANDLE WINAPI FindFirstFileNameHookW(
	LPCWSTR lpFileName,
	DWORD dwFlags,
	LPDWORD StringLength,
	PWCHAR LinkName
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = TRUE;
		if ( Tls->ourcall ) {
			return pFindFirstFileNameW(lpFileName, dwFlags, StringLength, LinkName);
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"FindFirstFileName(");

	//put lpFileName
	if ( ARGUMENT_PRESENT(lpFileName) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH * 4, lpFileName, MAX_PATH * 4);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, KERNEL32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pFindFirstFileNameW(lpFileName, dwFlags, StringLength, LinkName);
}

BOOL WINAPI FindNextFileNameHookW(
	HANDLE hFindStream,
	LPDWORD StringLength,
	PWCHAR LinkName
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = TRUE;
		if ( Tls->ourcall ) {
			return pFindNextFileNameW(hFindStream, StringLength, LinkName);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCall(L"FindNextFileName()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pFindNextFileNameW(hFindStream, StringLength, LinkName);
}

BOOL WINAPI CreateDirectoryExHookW(
	LPCWSTR lpTemplateDirectory,
	LPCWSTR lpNewDirectory,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCreateDirectoryExW(lpTemplateDirectory, lpNewDirectory, lpSecurityAttributes);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog
	_strcpyW(tBuff, L"CreateDirectoryEx(");

	__try {
		//put lpTemplateDirectory
		if ( ARGUMENT_PRESENT(lpTemplateDirectory) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH * 4, lpTemplateDirectory, MAX_PATH * 4);
		} else {
			_strcatW(tBuff, NullStrW);
		}
		_strcatW(tBuff, CommaExW);
		//put lpNewDirectory
		if ( ARGUMENT_PRESENT(lpNewDirectory) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH * 4, lpNewDirectory, MAX_PATH * 4);
		} else {
			_strcatW(tBuff, NullStrW);
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatW(tBuff, KERNEL32_EXCEPTION);
		utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCreateDirectoryExW(lpTemplateDirectory, lpNewDirectory, lpSecurityAttributes);
}

BOOL WINAPI CreateDirectoryHookW(
	LPCWSTR lpPathName,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCreateDirectoryW(lpPathName, lpSecurityAttributes);
		}
		Tls->ourcall = TRUE;
	}

	//put prolog
	_strcpyW(tBuff, L"CreateDirectory(");

	//put lpPathName
	if ( ARGUMENT_PRESENT(lpPathName) ) {
		__try {
			_strncpyW(_strendW(tBuff), MAX_PATH * 4, lpPathName, MAX_PATH * 4);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, KERNEL32_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCreateDirectoryW(lpPathName, lpSecurityAttributes);
}

VOID CopyMoveFileHandlerA(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName,
	BOOL bMove
	)
{
	CHAR tBuff[LOGBUFFERSIZELONG];
	CHAR *p;

	//put prolog
	if ( bMove ) {
		p = "Move(";
	} else {
		p = "Copy(";
	}
	_strcpyA(tBuff, p);

	__try {
		//put lpExistingFileName
		if ( ARGUMENT_PRESENT(lpExistingFileName) ) {
			_strncpyA(_strendA(tBuff), MAX_PATH * 4, lpExistingFileName, MAX_PATH * 4);
		} else {
			_strcatA(tBuff, NullStrA);
		}
		//put ->
		_strcatA(tBuff, ArrowA);
		//put lpNewFileName
		if ( ARGUMENT_PRESENT(lpNewFileName) ) {
			_strncpyA(_strendA(tBuff), MAX_PATH * 4, lpNewFileName, MAX_PATH * 4);
		} else {
			_strcatA(tBuff, NullStrA);
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatA(tBuff, KERNEL32_EXCEPTION_A);
		utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
	}

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);
}

VOID CopyMoveFileHandlerW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName,
	BOOL bMove
	)
{
	WCHAR tBuff[LOGBUFFERSIZELONG];
	WCHAR *p;

	//put prolog
	if ( bMove ) {
		p = L"Move(";
	} else {
		p = L"Copy(";
	}
	_strcpyW(tBuff, p);

	__try {
		//put lpExistingFileName
		if ( ARGUMENT_PRESENT(lpExistingFileName) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH * 4, lpExistingFileName, MAX_PATH * 4);
		} else {
			_strcatW(tBuff, NullStrW);
		}
		//put ->
		_strcatW(tBuff, ArrowW);
		//put lpNewFileName
		if ( ARGUMENT_PRESENT(lpNewFileName) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH * 4, lpNewFileName, MAX_PATH * 4);
		} else {
			_strcatW(tBuff, NullStrW);
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatW(tBuff, KERNEL32_EXCEPTION);
		utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);
}

BOOL WINAPI CopyFileHookA(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName,
	BOOL bFailIfExists
	)
{
	PTLS Tls;
	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCopyFileA(lpExistingFileName, lpNewFileName, bFailIfExists);
		}
		Tls->ourcall = TRUE;
	}

	//log call
	CopyMoveFileHandlerA(lpExistingFileName, lpNewFileName, FALSE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCopyFileA(lpExistingFileName, lpNewFileName, bFailIfExists);
}

BOOL WINAPI CopyFileHookW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName,
	BOOL bFailIfExists
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCopyFileW(lpExistingFileName, lpNewFileName, bFailIfExists);
		}
		Tls->ourcall = TRUE;
	}

	//log call
	CopyMoveFileHandlerW(lpExistingFileName, lpNewFileName, FALSE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCopyFileW(lpExistingFileName, lpNewFileName, bFailIfExists);
}

BOOL WINAPI CopyFileExHookA(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName,
	LPPROGRESS_ROUTINE lpProgressRoutine,
	LPVOID lpData,
	LPBOOL pbCancel,
	DWORD dwCopyFlags
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCopyFileExA(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel, dwCopyFlags);
		}
		Tls->ourcall = TRUE;
	}

	//log call
	CopyMoveFileHandlerA(lpExistingFileName, lpNewFileName, FALSE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCopyFileExA(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel, dwCopyFlags);
}

BOOL WINAPI CopyFileExHookW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName,
	LPPROGRESS_ROUTINE lpProgressRoutine,
	LPVOID lpData,
	LPBOOL pbCancel,
	DWORD dwCopyFlags
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pCopyFileExW(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel, dwCopyFlags);
		}
		Tls->ourcall = TRUE;
	}

	//log call
	CopyMoveFileHandlerW(lpExistingFileName, lpNewFileName, FALSE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pCopyFileExW(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel, dwCopyFlags);
}

BOOL WINAPI MoveFileHookA(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pMoveFileA(lpExistingFileName, lpNewFileName);
		}
		Tls->ourcall = TRUE;
	}

	//log call
	CopyMoveFileHandlerA(lpExistingFileName, lpNewFileName, TRUE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pMoveFileA(lpExistingFileName, lpNewFileName);
}

BOOL WINAPI MoveFileHookW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pMoveFileW(lpExistingFileName, lpNewFileName);
		}
		Tls->ourcall = TRUE;
	}

	//log call
	CopyMoveFileHandlerW(lpExistingFileName, lpNewFileName, TRUE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pMoveFileW(lpExistingFileName, lpNewFileName);
}

BOOL WINAPI MoveFileExHookA(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName,
	DWORD    dwFlags
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pMoveFileExA(lpExistingFileName, lpNewFileName, dwFlags);
		}
		Tls->ourcall = TRUE;
	}

	//log call
	CopyMoveFileHandlerA(lpExistingFileName, lpNewFileName, TRUE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pMoveFileExA(lpExistingFileName, lpNewFileName, dwFlags);
}

BOOL WINAPI MoveFileExHookW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName,
	DWORD    dwFlags
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pMoveFileExW(lpExistingFileName, lpNewFileName, dwFlags);
		}
		Tls->ourcall = TRUE;
	}

	//log call
	CopyMoveFileHandlerW(lpExistingFileName, lpNewFileName, TRUE);

	if ( Tls ) Tls->ourcall = FALSE;
	return pMoveFileExW(lpExistingFileName, lpNewFileName, dwFlags);
}