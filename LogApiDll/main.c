/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	main.c

Abstract:

	Dll entry-point code and exports.

	Created:       10.01.13
	Last change:   27.02.13

--*/

#include "global.h"

/* global variables declared here and forwarded in global.h */
SHCONTEXT				    shctx;
PNtAllocateVirtualMemory    pNtAllocateVirtualMemory   = NULL;
PNtOpenProcess			    pNtOpenProcess             = NULL;
PNtQuerySystemInformation   pNtQuerySystemInformation  = NULL;
PNtReadVirtualMemory	    pNtReadVirtualMemory       = NULL;
PNtQueryInformationProcess  pNtQueryInformationProcess = NULL;
POutputDebugStringA			pOutputDebugStringA		   = NULL;
PGetFinalPathNameByHandleW  pGetFinalPathNameByHandleW = NULL;
PGetWindowThreadProcessId   pGetWindowThreadProcessId  = NULL;

VOID CALLBACK DllCallback(
	LPWSTR lpLibraryName, 
	HMODULE ImageBase
	)

/*++

Routine Description:

    This is Sandboxie loader callback. 
	Sandboxie calls it every time when new loader event occurs.

Arguments:

    lpLibraryName - name of loading library.

	ImageBase - dll memory address.


Return Value:

    None.

--*/

{
	PTLS pTls = NULL;
	WCHAR tBuff[LOGBUFFERSIZE];

	//dll unloading, no action taken
	if ( !ARGUMENT_PRESENT(ImageBase) ) {
		return;
	}

	if ( !ARGUMENT_PRESENT(lpLibraryName) ) {
		return;
	}

	__try {

		pTls = GetTls();
		if ( pTls ) {		
			pTls->msgflag = FALSE;
			pTls->ourcall = TRUE;
		}

		InstallHooksCallback(lpLibraryName);

	} __finally {

		if ( pTls != NULL ) {
			pTls->msgflag = TRUE;
		}

		RtlSecureZeroMemory( tBuff, sizeof (tBuff) );
		_strcpyW(tBuff, L"LoadLibrary(");
		_strncpyW(_strendW(tBuff), MAX_PATH, lpLibraryName, MAX_PATH);
		_strcatW(tBuff, CloseBracketW);
		PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

		if ( pTls != NULL ) {
			pTls->ourcall = FALSE;
		}
	}
}

VOID WINAPI InjectDllMain(
	HINSTANCE SbieDll, 
	ULONG_PTR UnusedParameter
	)

/*++

Routine Description:

    This is exported entry to be called by Sandboxie.

Arguments:

    SbieDll - address of SbieDll.dll sandboxie helper dll.

	UnusedParameter - reserved by Sandboxie use, probably optional data.


Return Value:

    None.

--*/

{
	PTLS pTls;
#ifndef ServerPipeName
	PCHAR pClassName, pWindowTitle;
#endif
	WCHAR tBuff[LOGBUFFERSIZE];

	UNREFERENCED_PARAMETER(UnusedParameter);

	if ( SbieDll == NULL ) {
		return;
	}

	/* check if we are inside sandbox process */
	if ( shctx.SandboxieProcess == TRUE ) {
		return;
	}

	pTls = GetTls();
	if ( pTls == NULL ) 
		return;

	/* turn off logging */
	pTls->msgflag = FALSE;

#ifndef ServerPipeName
	/*	find BSA window if not already found
		DO NOT MOVE anywhere */
	if ( shctx.hwndServer == NULL ) {
		pClassName = ServerClassName;
		pWindowTitle = ServerWindowName;
		shctx.hwndServer = FindWindowA(pClassName, pWindowTitle);
	}
#else
	/*	connect to api log server pipe
		DO NOT MOVE anywhere */
	if (shctx.hServerPipe == NULL) {

		/*wchar_t serverPipeName[64];
		_strcpyW(serverPipeName, ServerPipeName);
		wchar_t* sufix = ExtractSufixW_S(shctx.szDllName, L'_', NULL, MAX_PATH);
		if (sufix && sufix != shctx.szDllName){
			_strncpyW(_strendW(serverPipeName), 64 - _strlenW(serverPipeName), sufix - 1, _strlenW(sufix - 1) - 4);
		}
		shctx.hServerPipe = CreateFileW(serverPipeName, GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);*/

		shctx.hServerPipe = CreateFileW(ServerPipeName, GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (shctx.hServerPipe == INVALID_HANDLE_VALUE) {
			shctx.hServerPipe = NULL;
			//return;
		}
	}
#endif
	_strcpyA(shctx.szDLLVersion, LOGAPIVERSIONSTRING);

	shctx.SbieDll.BaseAddress = SbieDll;
	shctx.SbieDll.SizeOfImage = GetModuleSize((PVOID)SbieDll);

	shctx.SboxHook = (PFNHook) GetProcAddress(SbieDll, SBIEHOOK);
	shctx.SboxDllCallback = (PFNDllCallback) GetProcAddress(SbieDll, SBIEDLLCALLBACK);
	if ( (shctx.SboxHook == NULL) || (shctx.SboxDllCallback == NULL) ) {
		return;
	}

	_WARNING_OFF(4152);
	shctx.SboxDllCallback(DllCallback);
	_WARNING_ON(4152);
	InstallHooks();

//#ifdef USE_MINI_HOOK
//	MH_EnableHook(MH_ALL_HOOKS);
//	shctx.initDone = TRUE;
//#endif

#ifndef _DEBUG
	HideDllFromPEB(shctx.SbieDll.BaseAddress, DLL_RENAME_MEMORYORDERENTRY);
	HideDllFromPEB(shctx.ThisDll.BaseAddress, DLL_UNLINK_NORMAL);
#endif

	if ( pTls ) {
		pTls->msgflag = TRUE;
	}

	_strcpyW(tBuff, L"Executing(");
	ultostrW(shctx.dwCurrentProcessId, _strendW(tBuff));
	_strcatW(tBuff, L"): ");
	_strcatW(tBuff, shctx.szAppName);
	PushToLogW(tBuff, LOGBUFFERSIZE, LOG_EXECUTING);
}

BOOL SpyHookDllProcessAttach(
	HINSTANCE hinstDLL
	)
{
	SIZE_T Length;
	WCHAR tBuff[MAX_PATH];

	RtlSecureZeroMemory(&shctx, sizeof(SHCONTEXT));

	/* query current process name */
	RtlSecureZeroMemory(tBuff, sizeof (tBuff) );
	if ( GetModuleFileNameW(GetModuleHandleW(NULL), shctx.szAppName, MAX_PATH) ) {
	
		_strcpyW(tBuff, shctx.szAppName);
		CharLowerW(tBuff);
		
		Length = _strlenW(tBuff);
		WideCharToMultiByte(CP_ACP, 0, tBuff, (INT)Length, shctx.szLogApp, MAX_PATH, 0, 0);

		ExtractFileNameW_S(tBuff, tBuff, MAX_PATH);	

		shctx.SandboxieProcess = IsSandboxieProcessW(tBuff);	
		if ( shctx.SandboxieProcess )
			return TRUE;
	}

	/* fill own use pointers from IAT */
	pNtAllocateVirtualMemory = &NtAllocateVirtualMemory;
	pNtOpenProcess = &NtOpenProcess;
	pNtQuerySystemInformation = &NtQuerySystemInformation;
	pNtReadVirtualMemory = &NtReadVirtualMemory;
	pNtQueryInformationProcess = &NtQueryInformationProcess;
	pOutputDebugStringA = &OutputDebugStringA;
	pGetFinalPathNameByHandleW = NULL;
	pGetWindowThreadProcessId = &GetWindowThreadProcessId;

	/* create list of PID's */
	PsCreateList();

	/* initialize tls msgflag */
	shctx.dwTlsIndex = TlsAlloc();
	if ( shctx.dwTlsIndex == TLS_OUT_OF_INDEXES ) {
		return FALSE;
	}

	shctx.dwSystemProcessId = 4;
	shctx.ProcessAllAccess = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF);

	shctx.osver.dwOSVersionInfoSize = sizeof (OSVERSIONINFOW);
#pragma warning( disable : 4996 )
	if ( GetVersionExW(&shctx.osver) ) {
		if ( shctx.osver.dwMajorVersion < 6 ) 
			shctx.ProcessAllAccess = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF);
		if ( shctx.osver.dwBuildNumber < 2600 )
			shctx.dwSystemProcessId = 8;
	}
#pragma warning( default : 4996 )

	/* save current process id and address of our dll */
	shctx.dwCurrentProcessId = GetCurrentProcessId();
		
	shctx.ThisDll.BaseAddress = hinstDLL;
	shctx.ThisDll.SizeOfImage = GetModuleSize(hinstDLL);

	/* query self dll name */
	RtlSecureZeroMemory(tBuff, sizeof (tBuff) );
	if ( GetModuleFileNameW(hinstDLL, tBuff, MAX_PATH) ) {
		ExtractFileNameW_S(tBuff, tBuff, MAX_PATH);
		_strcpyW(shctx.szDllName, tBuff);
	}

	/* do not move anywhere else or ParentId protection will screw up */
	FindExplorerProcessId();	
	
	return TRUE;
}

BOOL SpyHookDllProcessDetach(
	VOID
	)
{
	FreeTls();
	TlsFree(shctx.dwTlsIndex);
	PsFreeList();
	return TRUE;
}

int(*sprintfP)(char *_Buffer, const char * fmt, ...) = NULL;
int(*swprintfP)(wchar_t *_Buffer, const wchar_t * fmt, ...) = NULL;

BOOL WINAPI DllMain(
  HINSTANCE hinstDLL,
  DWORD fdwReason,
  LPVOID lpvReserved

/*++

Routine Description:

    Dll entry-point.

Arguments:

    hinstDLL - A handle to the DLL module.

	fdwReason - The reason code that indicates why the DLL entry-point function is being called.

	lpvReserved - Reversed for system use.


Return Value:

    TRUE on success, FALSE if anything failed.

--*/

  )
{
	BOOL bResult = TRUE;

	UNREFERENCED_PARAMETER(lpvReserved);

	switch ( fdwReason ) {
	case DLL_PROCESS_ATTACH: 
		{
			HMODULE hModule = GetModuleHandleW(L"ntdll");
			*(FARPROC*)&sprintfP = GetProcAddress(hModule, "sprintf");
			*(FARPROC*)&swprintfP = GetProcAddress(hModule, "swprintf");
		}
#ifdef USE_MINI_HOOK
		MH_Initialize();
#endif
		bResult = SpyHookDllProcessAttach(hinstDLL);
		break;
	case DLL_PROCESS_DETACH:
		bResult = SpyHookDllProcessDetach();
#ifdef USE_MINI_HOOK
		MH_Uninitialize();
#endif
		break;
	case DLL_THREAD_ATTACH:
		GetTls();
		break;
	case DLL_THREAD_DETACH:
		FreeTls();
		break;
	default:
		break;
	}

	return bResult;
}

#ifdef USE_PRIVATE_HDRS
#include "rtls\prtl.c"
#endif