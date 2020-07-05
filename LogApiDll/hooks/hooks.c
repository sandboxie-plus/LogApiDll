/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	hooks.c

Abstract:

	Hook install and support routines.

	Last change 28.02.13

--*/

#include "..\global.h"
#include "sfc_os_hook.h"
#include "shell32_hook.h"
#include "srclient_hook.h"
#include "gdi32_hook.h"
#include "rasapi32_hook.h"
#include "mpr_hook.h"
#include "ntdll_hook.h"
#include "psapi_hook.h"
#include "kernel32_hook.h"
#include "ws2_32_hook.h"
#include "urlmon_hook.h"
#include "advapi32_hook.h"
#include "wininet_hook.h"
#include "netapi32_hook.h"
#include "user32_hook.h"
#include "ole32_hook.h"
#include "winscard_hook.h"

#pragma warning(disable:4055)
#pragma warning(disable:4152)

PVOID HookCode(
	HMODULE hLibrary,
	LPSTR RoutineName,
	PVOID DetourHandler,
	PVOID DetourRoutine //<- ordinal case
	)
{
	PVOID pfn = NULL;
	
	if ( ARGUMENT_PRESENT(DetourRoutine) ) {
		pfn = DetourRoutine;
	} else {
		pfn = GetProcAddress(hLibrary, RoutineName);
	}
	if ( pfn != NULL ) {
#ifdef USE_MINI_HOOK
		PVOID pOriginal = NULL;
		if (MH_CreateHook(pfn, DetourHandler, &pOriginal) != MH_OK)
			return pfn;
		//if (MH_EnableHook(pfn) == MH_OK)
		return pOriginal;
#else
		return shctx.SboxHook(RoutineName, pfn, DetourHandler);
#endif
	}
	return pfn;
}

VOID InstallHooks(
	VOID
	)
{	
	static BOOLEAN AlreadyInstalledHooks = FALSE;
	if ( AlreadyInstalledHooks )
		return;

	HookNTDLL();    /*+*/   
	HookKernel32(); /*+*/
	HookAdvapi32(); /*+*/
	HookUser32();	/*+*/
	HookWs2_32();   /*+*/
	HookUrlmon();   /*+*/
	HookWininet();  /*+*/
	HookNetapi32(); /*+*/
	HookMpr();      /*+*/ 
	HookPsapi();    /*+*/
	HookRasapi32(); /*+*/ 
	HookGdi32();    /*+*/
	HookSrclient(); /*+*/
	HookShell32();  /*+*/ 
	HookSfc_os();   /*+*/
	HookOle32();    /*R*/
	HookWinscard(); /*+*/
#ifdef USE_MINI_HOOK
	MH_EnableHook(MH_ALL_HOOKS);
#endif

	AlreadyInstalledHooks = TRUE;
}

VOID InstallHooksCallback(
	LPWSTR lpLibraryName
	)
{
	if ( !ARGUMENT_PRESENT(lpLibraryName) ) {
		return;
	}

	if (_strcmpiW(lpLibraryName, dllname_advapi32) == 0) {
		HookAdvapi32();
		ENDCALL(fn_end);
	}
	if (_strcmpiW(lpLibraryName, dllname_user32) == 0) {
		HookUser32();
		ENDCALL(fn_end);
	}
	if (_strcmpiW(lpLibraryName, dllname_ws_32) == 0) {
		HookWs2_32();
		ENDCALL(fn_end);
	}
	if (_strcmpiW(lpLibraryName, dllname_urlmon) == 0) {
		HookUrlmon();
		ENDCALL(fn_end);
	}
	if (_strcmpiW(lpLibraryName, dllname_wininet) == 0) {
		HookWininet();
		ENDCALL(fn_end);
	}
	if (_strcmpiW(lpLibraryName, dllname_netapi32) == 0) {
		HookNetapi32();
		ENDCALL(fn_end);
	}
	if (_strcmpiW(lpLibraryName, dllname_mpr) == 0) {
		HookMpr();
		ENDCALL(fn_end);
	}
	if (_strcmpiW(lpLibraryName, dllname_psapi) == 0) {
		HookPsapi();
		ENDCALL(fn_end);
	}
	if (_strcmpiW(lpLibraryName, dllname_rasapi32) == 0) {
		HookRasapi32();
		ENDCALL(fn_end);
	}
	if (_strcmpiW(lpLibraryName, dllname_gdi32) == 0) {
		HookGdi32();
		ENDCALL(fn_end);
	}
	if (_strcmpiW(lpLibraryName, dllname_srclient) == 0) {
		HookSrclient();
		ENDCALL(fn_end);
	}
	if (_strcmpiW(lpLibraryName, dllname_shell32) == 0) {
		HookShell32();
		ENDCALL(fn_end);
	}
	if (_strcmpiW(lpLibraryName, dllname_sfc_os) == 0) {
		HookSfc_os();
		ENDCALL(fn_end);
	}
	if (_strcmpiW(lpLibraryName, dllname_ole32) == 0) {
		HookOle32();
		ENDCALL(fn_end);
	}
	if (_strcmpiW(lpLibraryName, dllname_winscard) == 0) {
		HookWinscard();
		ENDCALL(fn_end);
	}

fn_end:
#ifdef USE_MINI_HOOK
	MH_EnableHook(MH_ALL_HOOKS);
#endif
	return;
}

VOID HookKernel32(
	VOID
	)
{
	static BOOLEAN AlreadyInstalledHooks = FALSE;
	if ( AlreadyInstalledHooks )
		return;

	shctx.hmKernel32 = GetModuleHandleW(dllname_kernel32);
	if ( shctx.hmKernel32 == NULL )
		return;

	/* internal use, do not remove */
	pGetFinalPathNameByHandleW = (PGetFinalPathNameByHandleW)GetProcAddress(shctx.hmKernel32, "GetFinalPathNameByHandleW");

	/* kernel32 hooks */
	plstrcmpA = (PlstrcmpA)HookCode(shctx.hmKernel32, "lstrcmpA", lstrcmpHookA, NULL);
	plstrcmpW = (PlstrcmpW)HookCode(shctx.hmKernel32, "lstrcmpW", lstrcmpHookW, NULL);
	plstrcmpiA = (PlstrcmpiA)HookCode(shctx.hmKernel32, "lstrcmpiA", lstrcmpiHookA, NULL);
	plstrcmpiW = (PlstrcmpiW)HookCode(shctx.hmKernel32, "lstrcmpiW", lstrcmpiHookW, NULL);
	pOutputDebugStringA = (POutputDebugStringA)HookCode(shctx.hmKernel32, "OutputDebugStringA", OutputDebugStringHookA, NULL);
	pIsDebuggerPresent = (PIsDebuggerPresent)HookCode(shctx.hmKernel32, "IsDebuggerPresent", IsDebuggerPresentHook, NULL);
	pCheckRemoteDebuggerPresent = (PCheckRemoteDebuggerPresent)HookCode(shctx.hmKernel32, "CheckRemoteDebuggerPresent", CheckRemoteDebuggerPresentHook, NULL);
	pGetSystemDefaultLangID = (PGetSystemDefaultLangID)HookCode(shctx.hmKernel32, "GetSystemDefaultLangID", GetSystemDefaultLangIDHook, NULL);
	pCreatePipe = (PCreatePipe)HookCode(shctx.hmKernel32, "CreatePipe", CreatePipeHook, NULL);
	pConnectNamedPipe = (PConnectNamedPipe)HookCode(shctx.hmKernel32, "ConnectNamedPipe", ConnectNamedPipeHook, NULL);
	pFreeLibrary = (PFreeLibrary)HookCode(shctx.hmKernel32, "FreeLibrary", FreeLibraryHook, NULL);
	pExitProcess = (PExitProcess)HookCode(shctx.hmKernel32, "ExitProcess", ExitProcessHook, NULL);
	pGetSystemDEPPolicy = (PGetSystemDEPPolicy)HookCode(shctx.hmKernel32, "GetSystemDEPPolicy", GetSystemDEPPolicyHook, NULL);
	pCreateNamedPipeW = (PCreateNamedPipeW)HookCode(shctx.hmKernel32, "CreateNamedPipeW", CreateNamedPipeHookW, NULL);
	pCallNamedPipeW = (PCallNamedPipeW)HookCode(shctx.hmKernel32, "CallNamedPipeW", CallNamedPipeHookW, NULL);
	pGetVolumeInformationW = (PGetVolumeInformationW)HookCode(shctx.hmKernel32, "GetVolumeInformationW", GetVolumeInformationHookW, NULL);
	pGetComputerNameW = (PGetComputerNameW)HookCode(shctx.hmKernel32, "GetComputerNameW", GetComputerNameHookW, NULL);
	pDeleteFileW = (PDeleteFileW)HookCode(shctx.hmKernel32, "DeleteFileW", DeleteFileHookW, NULL);
	pOpenMutexW = (POpenMutexW)HookCode(shctx.hmKernel32, "OpenMutexW", OpenMutexHookW, NULL);
	pCreateMutexW = (PCreateMutexW)HookCode(shctx.hmKernel32, "CreateMutexW", CreateMutexHookW, NULL);
	pCreateEventW = (PCreateEventW)HookCode(shctx.hmKernel32, "CreateEventW", CreateEventHookW, NULL);
	pCreateProcessA = (PCreateProcessA)HookCode(shctx.hmKernel32, "CreateProcessA", CreateProcessHookA, NULL);
	pCreateProcessW = (PCreateProcessW)HookCode(shctx.hmKernel32, "CreateProcessW", CreateProcessHookW, NULL);
#ifdef VERBOSE_BUILD
	pCreateFileW = (PCreateFileW)HookCode(shctx.hmKernel32, "CreateFileW", CreateFileHookVerboseW, NULL);
#else
	pCreateFileW = (PCreateFileW)HookCode(shctx.hmKernel32, "CreateFileW", CreateFileHookW, NULL);
#endif
	if ( shctx.osver.dwBuildNumber < 7600 ) {
		pCreateRemoteThread = (PCreateRemoteThread)HookCode(shctx.hmKernel32, "CreateRemoteThread", CreateRemoteThreadHook, NULL);
	} else {
		pCreateRemoteThreadEx = (PCreateRemoteThreadEx)HookCode(shctx.hmKernel32, "CreateRemoteThreadEx", CreateRemoteThreadExHook, NULL);
	}
	/* Hook ToolHelp */
	pCreateToolhelp32Snapshot = (PCreateToolhelp32Snapshot)HookCode(shctx.hmKernel32, "CreateToolhelp32Snapshot", CreateToolhelp32SnapshotHook, NULL);
	pProcess32FirstW = (PProcess32FirstW)HookCode(shctx.hmKernel32, "Process32FirstW", Process32FirstHookW, NULL);
	pProcess32NextW = (PProcess32NextW)HookCode(shctx.hmKernel32, "Process32NextW", Process32NextHookW, NULL);

	/* ODS warning API */
	pGetModuleHandleW = (PGetModuleHandleW)HookCode(shctx.hmKernel32, "GetModuleHandleW", GetModuleHandleHookW, NULL);
	
#ifdef VERBOSE_BUILD
	pRemoveDirectoryW = (PRemoveDirectoryW)HookCode(shctx.hmKernel32, "RemoveDirectoryW", RemoveDirectoryHookW, NULL);
	pGetFileAttributesW = (PGetFileAttributesW)HookCode(shctx.hmKernel32, "GetFileAttributesW", GetFileAttributesHookW, NULL);
	pSearchPathW = (PSearchPathW)HookCode(shctx.hmKernel32, "SearchPathW", SearchPathHookW, NULL);
	pCreateFileMappingW = (PCreateFileMappingW)HookCode(shctx.hmKernel32, "CreateFileMappingW", CreateFileMappingHookW, NULL);
	pFindFirstFileExW = (PFindFirstFileExW)HookCode(shctx.hmKernel32, "FindFirstFileExW", FindFirstFileExHookW, NULL);
	pFindNextFileW = (PFindNextFileW)HookCode(shctx.hmKernel32, "FindNextFileW", FindNextFileHookW, NULL);
	pFindFirstFileNameW = (PFindFirstFileNameW)HookCode(shctx.hmKernel32, "FindFirstFileNameW", FindFirstFileNameHookW, NULL);
	pFindNextFileNameW = (PFindNextFileNameW)HookCode(shctx.hmKernel32, "FindNextFileNameW", FindNextFileNameHookW, NULL);
	pCreateDirectoryExW = (PCreateDirectoryExW)HookCode(shctx.hmKernel32, "CreateDirectoryExW", CreateDirectoryExHookW, NULL);
	pCreateDirectoryW  = (PCreateDirectoryW)HookCode(shctx.hmKernel32, "CreateDirectoryW", CreateDirectoryHookW, NULL);
	pCopyFileA = (PCopyFileA)HookCode(shctx.hmKernel32, "CopyFileA", CopyFileHookA, NULL);
	pCopyFileW = (PCopyFileW)HookCode(shctx.hmKernel32, "CopyFileW", CopyFileHookW, NULL);
	pCopyFileExA = (PCopyFileExA)HookCode(shctx.hmKernel32, "CopyFileExA", CopyFileExHookA, NULL);
	pCopyFileExW = (PCopyFileExW)HookCode(shctx.hmKernel32, "CopyFileExW", CopyFileExHookW, NULL);
	pMoveFileA = (PMoveFileA)HookCode(shctx.hmKernel32, "MoveFileA", MoveFileHookA, NULL);
	pMoveFileW = (PMoveFileW)HookCode(shctx.hmKernel32, "MoveFileW", MoveFileHookW, NULL);
	pMoveFileExA = (PMoveFileExA)HookCode(shctx.hmKernel32, "MoveFileExA", MoveFileExHookA, NULL);
	pMoveFileExW = (PMoveFileExW)HookCode(shctx.hmKernel32, "MoveFileExW", MoveFileExHookW, NULL);
#endif
	AlreadyInstalledHooks = TRUE;
}

VOID HookNTDLL(
	VOID
	)
{
	static BOOLEAN AlreadyInstalledHooks = FALSE;
	if ( AlreadyInstalledHooks )
		return;

	shctx.hmNTDLL = GetModuleHandleW(dllname_ntdll);
	if ( shctx.hmNTDLL == NULL )
		return;
	/*

	Nt hooks

	*/
	pNtSetInformationThread = (PNtSetInformationThread)HookCode(shctx.hmNTDLL, "NtSetInformationThread", NtSetInformationThreadHook, NULL);
	pNtLoadDriver = (PNtLoadDriver)HookCode(shctx.hmNTDLL, "NtLoadDriver", NtLoadDriverHook, NULL);
	pNtTerminateProcess = (PNtTerminateProcess)HookCode(shctx.hmNTDLL, "NtTerminateProcess", NtTerminateProcessHook, NULL);
	pNtAllocateVirtualMemory = (PNtAllocateVirtualMemory)HookCode(shctx.hmNTDLL, "NtAllocateVirtualMemory", NtAllocateVirtualMemoryHook, NULL);
	pNtWriteVirtualMemory = (PNtWriteVirtualMemory)HookCode(shctx.hmNTDLL, "NtWriteVirtualMemory", NtWriteVirtualMemoryHook, NULL);
	pNtResumeThread = (PNtResumeThread)HookCode(shctx.hmNTDLL, "NtResumeThread", NtResumeThreadHook, NULL);
	pNtSuspendThread = (PNtSuspendThread)HookCode(shctx.hmNTDLL, "NtSuspendThread", NtSuspendThreadHook, NULL);
	pNtQueueApcThread = (PNtQueueApcThread)HookCode(shctx.hmNTDLL, "NtQueueApcThread", NtQueueApcThreadHook, NULL);
	pNtOpenProcess = (PNtOpenProcess)HookCode(shctx.hmNTDLL, "NtOpenProcess", NtOpenProcessHook, NULL);
	pNtQuerySystemInformation = (PNtQuerySystemInformation)HookCode(shctx.hmNTDLL, "NtQuerySystemInformation", NtQuerySystemInformationHook, NULL);
	pNtDelayExecution = (PNtDelayExecution)HookCode(shctx.hmNTDLL, "NtDelayExecution", NtDelayExecutionHook, NULL);
#ifdef VERBOSE_BUILD
	pNtReadVirtualMemory = (PNtReadVirtualMemory)HookCode(shctx.hmNTDLL, "NtReadVirtualMemory", NtReadVirtualMemoryHook, NULL);
#endif
	pNtQueryVirtualMemory = (PNtQueryVirtualMemory)HookCode(shctx.hmNTDLL, "NtQueryVirtualMemory", NtQueryVirtualMemoryHook, NULL);
	pNtQueryInformationProcess = (PNtQueryInformationProcess)HookCode(shctx.hmNTDLL, "NtQueryInformationProcess", NtQueryInformationProcessHook, NULL);
	pNtSetInformationProcess = (PNtSetInformationProcess)HookCode(shctx.hmNTDLL, "NtSetInformationProcess", NtSetInformationProcessHook, NULL);
	pNtAdjustPrivilegesToken = (PNtAdjustPrivilegesToken)HookCode(shctx.hmNTDLL, "NtAdjustPrivilegesToken", NtAdjustPrivilegesTokenHook, NULL);
	pNtOpenProcessToken = (PNtOpenProcessToken)HookCode(shctx.hmNTDLL, "NtOpenProcessToken", NtOpenProcessTokenHook, NULL);
	pNtOpenProcessTokenEx = (PNtOpenProcessTokenEx)HookCode(shctx.hmNTDLL, "NtOpenProcessTokenEx", NtOpenProcessTokenExHook, NULL);
	pNtDeviceIoControlFile = (PNtDeviceIoControlFile)HookCode(shctx.hmNTDLL, "NtDeviceIoControlFile", NtDeviceIoControlFileHook, NULL);
	pNtSetEaFile = (PNtSetEaFile)HookCode(shctx.hmNTDLL, "NtSetEaFile", NtSetEaFileHook, NULL);
	pNtCreateFile = (PNtCreateFile)HookCode(shctx.hmNTDLL, "NtCreateFile", NtCreateFileHook, NULL);

	/*

	Ldr hooks

	*/
	pLdrFindEntryForAddress = (PLdrFindEntryForAddress)HookCode(shctx.hmNTDLL, "LdrFindEntryForAddress", LdrFindEntryForAddressHook, NULL);
	
	AlreadyInstalledHooks = TRUE;
}

VOID HookWininet(
	VOID
	)
{
	static BOOLEAN AlreadyInstalledHooks = FALSE;
	if ( AlreadyInstalledHooks )
		return;

	shctx.hmWininet = GetModuleHandleW(dllname_wininet);
	if ( shctx.hmWininet == NULL )
		return;

	pInternetGetConnectedStateExW = (PInternetGetConnectedStateExW)HookCode(shctx.hmWininet, "InternetGetConnectedStateExW", InternetGetConnectedStateExHookW, NULL);
	pInternetConnectA = (PInternetConnectA)HookCode(shctx.hmWininet, "InternetConnectA", InternetConnectHookA, NULL);
	pInternetConnectW = (PInternetConnectW)HookCode(shctx.hmWininet, "InternetConnectW", InternetConnectHookW, NULL);
	pInternetOpenA = (PInternetOpenA)HookCode(shctx.hmWininet, "InternetOpenA", InternetOpenHookA, NULL);
	pInternetOpenW = (PInternetOpenW)HookCode(shctx.hmWininet, "InternetOpenW", InternetOpenHookW, NULL);
	pInternetOpenUrlA = (PInternetOpenUrlA)HookCode(shctx.hmWininet, "InternetOpenUrlA", InternetOpenUrlHookA, NULL);
	pInternetOpenUrlW = (PInternetOpenUrlW)HookCode(shctx.hmWininet, "InternetOpenUrlW", InternetOpenUrlHookW, NULL);
	pInternetReadFile = (PInternetReadFile)HookCode(shctx.hmWininet, "InternetReadFile", InternetReadFileHook, NULL);
	pInternetWriteFile = (PInternetWriteFile)HookCode(shctx.hmWininet, "InternetWriteFile", InternetWriteFileHook, NULL);
	pDeleteUrlCacheEntryA = (PDeleteUrlCacheEntryA)HookCode(shctx.hmWininet, "DeleteUrlCacheEntryA", DeleteUrlCacheEntryHookA, NULL);
	pDeleteUrlCacheEntryW = (PDeleteUrlCacheEntryW)HookCode(shctx.hmWininet, "DeleteUrlCacheEntryW", DeleteUrlCacheEntryHookW, NULL);
	pInternetSetOptionA = (PInternetSetOptionA)HookCode(shctx.hmWininet, "InternetSetOptionA", InternetSetOptionHookA, NULL);
	pInternetSetOptionW = (PInternetSetOptionW)HookCode(shctx.hmWininet, "InternetSetOptionW", InternetSetOptionHookW, NULL);
	pFtpFindFirstFileA = (PFtpFindFirstFileA)HookCode(shctx.hmWininet, "FtpFindFirstFileA", FtpFindFirstFileHookA, NULL);
	pFtpFindFirstFileW = (PFtpFindFirstFileW)HookCode(shctx.hmWininet, "FtpFindFirstFileW", FtpFindFirstFileHookW, NULL);
	pFtpOpenFileA = (PFtpOpenFileA)HookCode(shctx.hmWininet, "FtpOpenFileA", FtpOpenFileHookA, NULL);
	pFtpOpenFileW = (PFtpOpenFileW)HookCode(shctx.hmWininet, "FtpOpenFileW", FtpOpenFileHookW, NULL);
	pFtpGetFileA = (PFtpGetFileA)HookCode(shctx.hmWininet, "FtpGetFileA", FtpGetFileHookA, NULL);
	pFtpGetFileW = (PFtpGetFileW)HookCode(shctx.hmWininet, "FtpGetFileW", FtpGetFileHookW, NULL);
	pFtpPutFileA = (PFtpPutFileA)HookCode(shctx.hmWininet, "FtpPutFileA", FtpPutFileHookA, NULL);
	pFtpPutFileW = (PFtpPutFileW)HookCode(shctx.hmWininet, "FtpPutFileW", FtpPutFileHookW, NULL);
	pHttpOpenRequestA = (PHttpOpenRequestA)HookCode(shctx.hmWininet, "HttpOpenRequestA", HttpOpenRequestHookA, NULL);
	pHttpOpenRequestW = (PHttpOpenRequestW)HookCode(shctx.hmWininet, "HttpOpenRequestW", HttpOpenRequestHookW, NULL);
	pHttpSendRequestA = (PHttpSendRequestA)HookCode(shctx.hmWininet, "HttpSendRequestA", HttpSendRequestHookA, NULL);
	pHttpSendRequestW = (PHttpSendRequestW)HookCode(shctx.hmWininet, "HttpSendRequestW", HttpSendRequestHookW, NULL);
	pHttpSendRequestExA = (PHttpSendRequestExA)HookCode(shctx.hmWininet, "HttpSendRequestExA", HttpSendRequestExHookA, NULL);
	pHttpSendRequestExW = (PHttpSendRequestExW)HookCode(shctx.hmWininet, "HttpSendRequestExW", HttpSendRequestExHookW, NULL);

	AlreadyInstalledHooks = TRUE;
}

VOID HookNetapi32(
	VOID
	)
{
	static BOOLEAN AlreadyInstalledHooks = FALSE;
	if ( AlreadyInstalledHooks )
		return;

	shctx.hmNetapi32 = GetModuleHandleW(dllname_netapi32);
	if ( shctx.hmNetapi32 == NULL )
		return;

	pNetServerEnum = (PNetServerEnum)HookCode(shctx.hmNetapi32, "NetServerEnum", NetServerEnumHook, NULL);
	pNetShareEnum = (PNetShareEnum)HookCode(shctx.hmNetapi32, "NetShareEnum", NetShareEnumHook, NULL);
	pNetShareEnumSticky = (PNetShareEnumSticky)HookCode(shctx.hmNetapi32, "NetShareEnumSticky", NetShareEnumStickyHook, NULL);
	pNetShareAdd = (PNetShareAdd)HookCode(shctx.hmNetapi32, "NetShareAdd", NetShareAddHook, NULL);
	pNetShareDel = (PNetShareDel)HookCode(shctx.hmNetapi32, "NetShareDel", NetShareDelHook, NULL);
	pNetShareDelSticky = (PNetShareDelSticky)HookCode(shctx.hmNetapi32, "NetShareDelSticky", NetShareDelStickyHook, NULL);
	pNetScheduleJobAdd = (PNetScheduleJobAdd)HookCode(shctx.hmNetapi32, "NetScheduleJobAdd", NetScheduleJobAddHook, NULL);
	pNetUserAdd = (PNetUserAdd)HookCode(shctx.hmNetapi32, "NetUserAdd", NetUserAddHook, NULL);
	pNetUserDel = (PNetUserDel)HookCode(shctx.hmNetapi32, "NetUserDel", NetUserDelHook, NULL);
	pNetUserEnum = (PNetUserEnum)HookCode(shctx.hmNetapi32, "NetUserEnum", NetUserEnumHook, NULL);
	pNetUserChangePassword = (PNetUserChangePassword)HookCode(shctx.hmNetapi32, "NetUserChangePassword", NetUserChangePasswordHook, NULL);
	pNetUserGetGroups = (PNetUserGetGroups)HookCode(shctx.hmNetapi32, "NetUserGetGroups", NetUserGetGroupsHook, NULL);
	pNetUserSetGroups = (PNetUserSetGroups)HookCode(shctx.hmNetapi32, "NetUserSetGroups", NetUserSetGroupsHook, NULL);
	pNetUserGetInfo = (PNetUserGetInfo)HookCode(shctx.hmNetapi32, "NetUserGetInfo", NetUserGetInfoHook, NULL);
	pNetUserSetInfo = (PNetUserSetInfo)HookCode(shctx.hmNetapi32, "NetUserSetInfo", NetUserSetInfoHook, NULL);
	pNetUserGetLocalGroups = (PNetUserGetLocalGroups)HookCode(shctx.hmNetapi32, "NetUserGetLocalGroups", NetUserGetLocalGroupsHook, NULL);
	pNetUseAdd = (PNetUseAdd)HookCode(shctx.hmNetapi32, "NetUseAdd", NetUseAddHook, NULL);
	pNetUseDel = (PNetUseDel)HookCode(shctx.hmNetapi32, "NetUseDel", NetUseDelHook, NULL);
	pNetUseEnum = (PNetUseEnum)HookCode(shctx.hmNetapi32, "NetUseEnum", NetUseEnumHook, NULL);
	pNetLocalGroupAdd = (PNetLocalGroupAdd)HookCode(shctx.hmNetapi32, "NetLocalGroupAdd", NetLocalGroupAddHook, NULL);
	pNetLocalGroupAddMembers = (PNetLocalGroupAddMembers)HookCode(shctx.hmNetapi32, "NetLocalGroupAddMembers", NetLocalGroupAddMembersHook, NULL);
	pNetLocalGroupDel = (PNetLocalGroupDel)HookCode(shctx.hmNetapi32, "NetLocalGroupDel", NetLocalGroupDelHook, NULL);
	pNetLocalGroupDelMembers = (PNetLocalGroupDelMembers)HookCode(shctx.hmNetapi32, "NetLocalGroupDelMembers", NetLocalGroupDelMembersHook, NULL);
	pNetGroupAdd = (PNetGroupAdd)HookCode(shctx.hmNetapi32, "NetGroupAdd", NetGroupAddHook, NULL);
	pNetGroupAddUser = (PNetGroupAddUser)HookCode(shctx.hmNetapi32, "NetGroupAddUser", NetGroupAddUserHook, NULL);
	pNetGroupDel = (PNetGroupDel)HookCode(shctx.hmNetapi32, "NetGroupDel", NetGroupDelHook, NULL);
	pNetGroupDelUser = (PNetGroupDelUser)HookCode(shctx.hmNetapi32, "NetGroupDelUser", NetGroupDelUserHook, NULL);

	AlreadyInstalledHooks = TRUE;
}

VOID HookAdvapi32(
	VOID
	)
{
	static BOOLEAN AlreadyInstalledHooks = FALSE;
	if ( AlreadyInstalledHooks )
		return;

	shctx.hmAdvapi32 = GetModuleHandleW(dllname_advapi32);
	if ( shctx.hmAdvapi32 == NULL )
		return;

	pOpenSCManagerA = (POpenSCManagerA)HookCode(shctx.hmAdvapi32, "OpenSCManagerA", OpenSCManagerHookA, NULL);
	pOpenSCManagerW = (POpenSCManagerW)HookCode(shctx.hmAdvapi32, "OpenSCManagerW", OpenSCManagerHookW, NULL);
	pOpenServiceA = (POpenServiceA)HookCode(shctx.hmAdvapi32, "OpenServiceA", OpenServiceHookA, NULL);
	pOpenServiceW = (POpenServiceW)HookCode(shctx.hmAdvapi32, "OpenServiceW", OpenServiceHookW, NULL);
	pCreateServiceA = (PCreateServiceA)HookCode(shctx.hmAdvapi32, "CreateServiceA", CreateServiceHookA, NULL);
	pCreateServiceW = (PCreateServiceW)HookCode(shctx.hmAdvapi32, "CreateServiceW", CreateServiceHookW, NULL);
	pStartServiceA = (PStartServiceA)HookCode(shctx.hmAdvapi32, "StartServiceA", StartServiceHookA, NULL);
	pStartServiceW = (PStartServiceW)HookCode(shctx.hmAdvapi32, "StartServiceW", StartServiceHookW, NULL);
	pControlService = (PControlService)HookCode(shctx.hmAdvapi32, "ControlService", ControlServiceHook, NULL);
	pDeleteService = (PDeleteService)HookCode(shctx.hmAdvapi32, "DeleteService", DeleteServiceHook, NULL);
	pChangeServiceConfigA = (PChangeServiceConfigA)HookCode(shctx.hmAdvapi32, "ChangeServiceConfigA", ChangeServiceConfigHookA, NULL);
	pChangeServiceConfigW = (PChangeServiceConfigW)HookCode(shctx.hmAdvapi32, "ChangeServiceConfigW", ChangeServiceConfigHookW, NULL);
	pAreAnyAccessesGranted = (PAreAnyAccessesGranted)HookCode(shctx.hmAdvapi32, "AreAnyAccessesGranted", AreAnyAccessesGrantedHook, NULL);
	pGetUserNameA = (PGetUserNameA)HookCode(shctx.hmAdvapi32, "GetUserNameA", GetUserNameHookA, NULL);
	pGetUserNameW = (PGetUserNameW)HookCode(shctx.hmAdvapi32, "GetUserNameW", GetUserNameHookW, NULL);
	pGetCurrentHwProfileW = (PGetCurrentHwProfileW)HookCode(shctx.hmAdvapi32, "GetCurrentHwProfileW", GetCurrentHwProfileHookW, NULL);
	pOpenEventLogA = (POpenEventLogA)HookCode(shctx.hmAdvapi32, "OpenEventLogA", OpenEventLogHookA, NULL);
	pOpenEventLogW = (POpenEventLogW)HookCode(shctx.hmAdvapi32, "OpenEventLogW", OpenEventLogHookW, NULL);
	pClearEventLogA = (PClearEventLogA)HookCode(shctx.hmAdvapi32, "ClearEventLogA", ClearEventLogHookA, NULL);
	pClearEventLogW = (PClearEventLogW)HookCode(shctx.hmAdvapi32, "ClearEventLogW", ClearEventLogHookW, NULL);
	pCryptEncrypt = (PCryptEncrypt)HookCode(shctx.hmAdvapi32, "CryptEncrypt", CryptEncryptHook, NULL);
	pCryptDecrypt = (PCryptDecrypt)HookCode(shctx.hmAdvapi32, "CryptDecrypt", CryptDecryptHook, NULL);
	pCryptHashData = (PCryptHashData)HookCode(shctx.hmAdvapi32, "CryptHashData", CryptHashDataHook, NULL);
	pSetFileSecurityW = (PSetFileSecurityW)HookCode(shctx.hmAdvapi32, "SetFileSecurityW", SetFileSecurityHookW, NULL);
	pSetNamedSecurityInfoA = (PSetNamedSecurityInfoA)HookCode(shctx.hmAdvapi32, "SetNamedSecurityInfoA", SetNamedSecurityInfoHookA, NULL);
	pSetNamedSecurityInfoW = (PSetNamedSecurityInfoW)HookCode(shctx.hmAdvapi32, "SetNamedSecurityInfoW", SetNamedSecurityInfoHookW, NULL);
	pSetSecurityInfo = (PSetSecurityInfo)HookCode(shctx.hmAdvapi32, "SetSecurityInfo", SetSecurityInfoHook, NULL);
	pCreateProcessAsUserA = (PCreateProcessAsUserA)HookCode(shctx.hmAdvapi32, "CreateProcessAsUserA", CreateProcessAsUserHookW, NULL);
	pCreateProcessAsUserW = (PCreateProcessAsUserW)HookCode(shctx.hmAdvapi32, "CreateProcessAsUserW", CreateProcessAsUserHookW, NULL);
#ifdef VERBOSE_BUILD
	pRegCreateKeyExA = (PRegCreateKeyExA)HookCode(shctx.hmAdvapi32, "RegCreateKeyExA", RegCreateKeyExHookA, NULL);
	pRegCreateKeyExW = (PRegCreateKeyExW)HookCode(shctx.hmAdvapi32, "RegCreateKeyExW", RegCreateKeyExHookW, NULL);
	pRegOpenKeyExA = (PRegOpenKeyExA)HookCode(shctx.hmAdvapi32, "RegOpenKeyExA", RegOpenKeyExHookA, NULL);
	pRegOpenKeyExW = (PRegOpenKeyExW)HookCode(shctx.hmAdvapi32, "RegOpenKeyExW", RegOpenKeyExHookW, NULL);
	pRegDeleteKeyA = (PRegDeleteKeyA)HookCode(shctx.hmAdvapi32, "RegDeleteKeyA", RegDeleteKeyHookA, NULL);
	pRegDeleteKeyW = (PRegDeleteKeyW)HookCode(shctx.hmAdvapi32, "RegDeleteKeyW", RegDeleteKeyHookW, NULL);
	pRegDeleteValueA = (PRegDeleteValueA)HookCode(shctx.hmAdvapi32, "RegDeleteValueA", RegDeleteValueHookA, NULL);
	pRegDeleteValueW = (PRegDeleteValueW)HookCode(shctx.hmAdvapi32, "RegDeleteValueW", RegDeleteValueHookW, NULL);
	pRegEnumKeyExA = (PRegEnumKeyExA)HookCode(shctx.hmAdvapi32, "RegEnumKeyExA", RegEnumKeyExHookA, NULL);
	pRegEnumKeyExW = (PRegEnumKeyExW)HookCode(shctx.hmAdvapi32, "RegEnumKeyExW", RegEnumKeyExHookW, NULL);
	pRegEnumValueA = (PRegEnumValueA)HookCode(shctx.hmAdvapi32, "RegEnumValueA", RegEnumValueHookA, NULL);
	pRegEnumValueW = (PRegEnumValueW)HookCode(shctx.hmAdvapi32, "RegEnumValueW", RegEnumValueHookW, NULL);
	pRegSetValueA = (PRegSetValueA)HookCode(shctx.hmAdvapi32, "RegSetValueA", RegSetValueHookA, NULL);
	pRegSetValueW = (PRegSetValueW)HookCode(shctx.hmAdvapi32, "RegSetValueW", RegSetValueHookW, NULL);
	pRegSetValueExA = (PRegSetValueExA)HookCode(shctx.hmAdvapi32, "RegSetValueExA", RegSetValueExHookA, NULL);
	pRegSetValueExW = (PRegSetValueExW)HookCode(shctx.hmAdvapi32, "RegSetValueExW", RegSetValueExHookW, NULL);
	pRegSaveKeyA = (PRegSaveKeyA)HookCode(shctx.hmAdvapi32, "RegSaveKeyA", RegSaveKeyHookA, NULL);
	pRegSaveKeyW = (PRegSaveKeyW)HookCode(shctx.hmAdvapi32, "RegSaveKeyW", RegSaveKeyHookW, NULL);
	pRegSaveKeyExA = (PRegSaveKeyExA)HookCode(shctx.hmAdvapi32, "RegSaveKeyExA", RegSaveKeyExHookA, NULL);
	pRegSaveKeyExW = (PRegSaveKeyExW)HookCode(shctx.hmAdvapi32, "RegSaveKeyExW", RegSaveKeyExHookW, NULL);
	pRegLoadKeyA = (PRegLoadKeyA)HookCode(shctx.hmAdvapi32, "RegLoadKeyA", RegLoadKeyHookA, NULL);
	pRegLoadKeyW = (PRegLoadKeyW)HookCode(shctx.hmAdvapi32, "RegLoadKeyW", RegLoadKeyHookW, NULL);
	pRegCloseKey = (PRegCloseKey)HookCode(shctx.hmAdvapi32, "RegCloseKey", RegCloseKeyHook, NULL);
#endif
	 
	AlreadyInstalledHooks = TRUE;
}

VOID HookUser32(
	VOID
	)
{
	static BOOLEAN AlreadyInstalledHooks = FALSE;
	if ( AlreadyInstalledHooks )
		return;

	shctx.hmUser32 = GetModuleHandleW(dllname_user32);
	if ( shctx.hmUser32 == NULL )
		return;

	pGetWindowThreadProcessId = (PGetWindowThreadProcessId)HookCode(shctx.hmUser32, "GetWindowThreadProcessId", GetWindowThreadProcessIdHook, NULL);
	pSystemParametersInfoA = (PSystemParametersInfoA)HookCode(shctx.hmUser32, "SystemParametersInfoA", SystemParametersInfoHookA, NULL);
	pSystemParametersInfoW = (PSystemParametersInfoW)HookCode(shctx.hmUser32, "SystemParametersInfoW", SystemParametersInfoHookW, NULL);
	pSetWindowsHookExA = (PSetWindowsHookExA)HookCode(shctx.hmUser32, "SetWindowsHookExA", SetWindowsHookExHookA, NULL);
	pSetWindowsHookExW = (PSetWindowsHookExW)HookCode(shctx.hmUser32, "SetWindowsHookExW", SetWindowsHookExHookW, NULL);
	pkeybd_event = (Pkeybd_event)HookCode(shctx.hmUser32, "keybd_event", keybd_eventHook, NULL);
	pGetAsyncKeyState = (PGetAsyncKeyState)HookCode(shctx.hmUser32, "GetAsyncKeyState", GetAsyncKeyStateHook, NULL);
	pGetKeyState = (PGetKeyState)HookCode(shctx.hmUser32, "GetKeyState", GetKeyStateHook, NULL);
	pGetKeyboardState = (PGetKeyboardState)HookCode(shctx.hmUser32, "GetKeyboardState", GetKeyboardStateHook, NULL);
	pGetRawInputData = (PGetRawInputData)HookCode(shctx.hmUser32, "GetRawInputData", GetRawInputDataHook, NULL);
	pPrintWindow = (PPrintWindow)HookCode(shctx.hmUser32, "PrintWindow", PrintWindowHook, NULL);
	pGetWindowTextLengthA = (PGetWindowTextLengthA)HookCode(shctx.hmUser32, "GetWindowTextLengthA", GetWindowTextLengthHookA, NULL);
	pGetWindowTextLengthW = (PGetWindowTextLengthW)HookCode(shctx.hmUser32, "GetWindowTextLengthW", GetWindowTextLengthHookW, NULL);
	pGetForegroundWindow = (PGetForegroundWindow)HookCode(shctx.hmUser32, "GetForegroundWindow", GetForegroundWindowHook, NULL);
#if defined(_M_X86)
	pAttachThreadInput = (PAttachThreadInput)HookCode(shctx.hmUser32, "AttachThreadInput", AttachThreadInputHook, NULL);
#endif	
	pLockWorkStation = (PLockWorkStation)HookCode(shctx.hmUser32, "LockWorkStation", LockWorkStationHook, NULL);
	pSetClipboardViewer = (PSetClipboardViewer)HookCode(shctx.hmUser32, "SetClipboardViewer", SetClipboardViewerHook, NULL);
	pAddClipboardFormatListener = (PAddClipboardFormatListener)HookCode(shctx.hmUser32, "AddClipboardFormatListener", AddClipboardFormatListenerHook, NULL);
	pSetWindowPos = (PSetWindowPos)HookCode(shctx.hmUser32, "SetWindowPos", SetWindowPosHook, NULL);
	pSetTimer = (PSetTimer)HookCode(shctx.hmUser32, "SetTimer", SetTimerHook, NULL);
	pRegisterHotKey = (PRegisterHotKey)HookCode(shctx.hmUser32, "RegisterHotKey", RegisterHotKeyHook, NULL);
	pClipCursor = (PClipCursor)HookCode(shctx.hmUser32, "ClipCursor", ClipCursorHook, NULL);
	pSwitchDesktop = (PSwitchDesktop)HookCode(shctx.hmUser32, "SwitchDesktop", SwitchDesktopHook, NULL);
	pGetKeyboardLayoutList = (PGetKeyboardLayoutList)HookCode(shctx.hmUser32, "GetKeyboardLayoutList", GetKeyboardLayoutListHook, NULL);

	if (shctx.osver.dwMajorVersion >= 6) {
		pCreateDesktopExA = (PCreateDesktopExA)HookCode(shctx.hmUser32, "CreateDesktopExA", CreateDesktopExHookA, NULL);
		pCreateDesktopExW = (PCreateDesktopExW)HookCode(shctx.hmUser32, "CreateDesktopExW", CreateDesktopExHookW, NULL);
	} else {
		pCreateDesktopA = (PCreateDesktopA)HookCode(shctx.hmUser32, "CreateDesktopA", CreateDesktopHookA, NULL);
		pCreateDesktopW = (PCreateDesktopW)HookCode(shctx.hmUser32, "CreateDesktopW", CreateDesktopHookW, NULL);
	}

	/* protection */
	pFindWindowA = (PFindWindowA)HookCode(shctx.hmUser32, "FindWindowA", FindWindowHookA, NULL);
	pFindWindowW = (PFindWindowW)HookCode(shctx.hmUser32, "FindWindowW", FindWindowHookW, NULL);
	pFindWindowExA = (PFindWindowExA)HookCode(shctx.hmUser32, "FindWindowExA", FindWindowExHookA, NULL);
	pFindWindowExW = (PFindWindowExW)HookCode(shctx.hmUser32, "FindWindowExW", FindWindowExHookW, NULL);
	pGetWindowTextA = (PGetWindowTextA)HookCode(shctx.hmUser32, "GetWindowTextA", GetWindowTextHookA, NULL);
	pGetWindowTextW = (PGetWindowTextW)HookCode(shctx.hmUser32, "GetWindowTextW", GetWindowTextHookW, NULL);
	pGetClassNameA = (PGetClassNameA)HookCode(shctx.hmUser32, "GetClassNameA", GetClassNameHookA, NULL);
	pGetClassNameW = (PGetClassNameW)HookCode(shctx.hmUser32, "GetClassNameW", GetClassNameHookW, NULL);
	pSendMessageA = (PSendMessageA)HookCode(shctx.hmUser32, "SendMessageA", SendMessageHookA, NULL);
	pSendMessageW = (PSendMessageW)HookCode(shctx.hmUser32, "SendMessageW", SendMessageHookW, NULL);
	pSendMessageTimeoutA = (PSendMessageTimeoutA)HookCode(shctx.hmUser32, "SendMessageTimeoutA", SendMessageTimeoutHookA, NULL);
	pSendMessageTimeoutW = (PSendMessageTimeoutW)HookCode(shctx.hmUser32, "SendMessageTimeoutW", SendMessageTimeoutHookW, NULL);
	pInternalGetWindowText = (PInternalGetWindowText)HookCode(shctx.hmUser32, "InternalGetWindowText", InternalGetWindowTextHook, NULL);

	AlreadyInstalledHooks = TRUE;
}

VOID HookWs2_32(
	VOID
	)
{
	static BOOLEAN AlreadyInstalledHooks = FALSE;
	if ( AlreadyInstalledHooks )
		return;

	shctx.hmWs2_32 = GetModuleHandleW(dllname_ws_32);
	if ( shctx.hmWs2_32 == NULL )
		return;

	pbind = (pfnbind)HookCode(shctx.hmWs2_32, "bind", bindHook, NULL);
	pconnect = (pfnconnect)HookCode(shctx.hmWs2_32, "connect", connectHook, NULL);

	AlreadyInstalledHooks = TRUE;
}

VOID HookUrlmon(
	VOID
	)
{
	static BOOLEAN AlreadyInstalledHooks = FALSE;
	if ( AlreadyInstalledHooks )
		return;

	shctx.hmUrlmon = GetModuleHandleW(dllname_urlmon);
	if ( shctx.hmUrlmon == NULL )
		return;

	pURLDownloadToFileW = (PURLDownloadToFileW)HookCode(shctx.hmUrlmon, "URLDownloadToFileW", URLDownloadToFileHookW, NULL);
	pURLDownloadToCacheFileW = (PURLDownloadToCacheFileW)HookCode(shctx.hmUrlmon, "URLDownloadToCacheFileW", URLDownloadToCacheFileHookW, NULL);
	pURLOpenStreamW = (PURLOpenStreamW)HookCode(shctx.hmUrlmon, "URLOpenStreamW", URLOpenStreamHookW, NULL);
	pURLOpenBlockingStreamW = (PURLOpenBlockingStreamW)HookCode(shctx.hmUrlmon, "URLOpenBlockingStreamW", URLOpenBlockingStreamHookW, NULL);
	
	AlreadyInstalledHooks = TRUE;
}

VOID HookMpr(
	VOID
	)
{
	static BOOLEAN AlreadyInstalledHooks = FALSE;
	if ( AlreadyInstalledHooks )
		return;

	shctx.hmMpr = GetModuleHandleW(dllname_mpr);
	if ( shctx.hmMpr == NULL )
		return;

	pWNetOpenEnumA = (PWNetOpenEnumA)HookCode(shctx.hmMpr, "WNetOpenEnumA", WNetOpenEnumHookA, NULL);
	pWNetOpenEnumW = (PWNetOpenEnumW)HookCode(shctx.hmMpr, "WNetOpenEnumW", WNetOpenEnumHookW, NULL);
	
	AlreadyInstalledHooks = TRUE;
}

VOID HookPsapi(
	VOID
	)
{
	static BOOLEAN AlreadyInstalledHooks = FALSE;

	HMODULE hLib = NULL;

	CHAR *EnumProcessStr;
	CHAR *EnumProcessModulesStr;
	CHAR *EnumProcessModulesExStr;

	if ( AlreadyInstalledHooks )
		return;

	if ( shctx.osver.dwBuildNumber < 7600) {	
		hLib = GetModuleHandleW(dllname_psapi);
		shctx.hmPsapi = hLib;
		EnumProcessStr = "EnumProcesses";
		EnumProcessModulesStr = "EnumProcessModules";
		EnumProcessModulesExStr = "EnumProcessModulesEx";
	} else {
		if ( shctx.hmKernel32 == NULL ) shctx.hmKernel32 = GetModuleHandleW(dllname_kernel32);
		hLib = shctx.hmKernel32;
		EnumProcessStr = "K32EnumProcesses";
		EnumProcessModulesStr = "K32EnumProcessModules";
		EnumProcessModulesExStr = "K32EnumProcessModulesEx";
	}

	if ( hLib == NULL )
		return;

	pEnumProcesses = (PEnumProcesses)HookCode(hLib, EnumProcessStr, EnumProcessesHook, NULL);
	pEnumProcessModules = (PEnumProcessModules)(hLib, EnumProcessModulesStr, EnumProcessModulesHook, NULL);
	pEnumProcessModulesEx = (PEnumProcessModulesEx)(hLib, EnumProcessModulesExStr, EnumProcessModulesExHook, NULL);
	
	AlreadyInstalledHooks = TRUE;
}

VOID HookRasapi32(
	VOID
	)
{
	static BOOLEAN AlreadyInstalledHooks = FALSE;
	if ( AlreadyInstalledHooks )
		return;

	shctx.hmRasapi32 = GetModuleHandleW(dllname_rasapi32);
	if ( shctx.hmRasapi32 == NULL )
		return;
	
	pRasEnumEntriesA = (PRasEnumEntriesA)HookCode(shctx.hmRasapi32, "RasEnumEntriesA", RasEnumEntriesHookA, NULL);
	pRasEnumEntriesW = (PRasEnumEntriesW)HookCode(shctx.hmRasapi32, "RasEnumEntriesW", RasEnumEntriesHookW, NULL);

	AlreadyInstalledHooks = TRUE;
}

VOID HookGdi32(
	VOID
	)
{
	static BOOLEAN AlreadyInstalledHooks = FALSE;
	if ( AlreadyInstalledHooks )
		return;

	shctx.hmGdi32 = GetModuleHandleW(dllname_gdi32);
	if ( shctx.hmGdi32 == NULL )
		return;

	pCreateDCA = (PCreateDCA)HookCode(shctx.hmGdi32, "CreateDCA", CreateDCHookA, NULL);
	pCreateDCW = (PCreateDCW)HookCode(shctx.hmGdi32, "CreateDCW", CreateDCHookW, NULL);
	
	AlreadyInstalledHooks = TRUE;
}

VOID HookSrclient(
	VOID
	)
{
	static BOOLEAN AlreadyInstalledHooks = FALSE;
	if ( AlreadyInstalledHooks )
		return;

	shctx.hmSrclient = GetModuleHandleW(dllname_srclient);
	if ( shctx.hmSrclient == NULL )
		return;

	pSRRemoveRestorePoint = (PSRRemoveRestorePoint)HookCode(shctx.hmSrclient, "SRRemoveRestorePoint", SRRemoveRestorePointHook, NULL);
	pSRSetRestorePointA = (PSRSetRestorePointA)HookCode(shctx.hmSrclient, "SRSetRestorePointA", SRSetRestorePointHookA, NULL);
	pSRSetRestorePointW = (PSRSetRestorePointW)HookCode(shctx.hmSrclient, "SRSetRestorePointW", SRSetRestorePointHookW, NULL);

	AlreadyInstalledHooks = TRUE;
}

VOID HookShell32(
	VOID
	)
{
	static BOOLEAN AlreadyInstalledHooks = FALSE;
	if ( AlreadyInstalledHooks )
		return;

	shctx.hmShell32 = GetModuleHandleW(dllname_shell32);
	if ( shctx.hmShell32 == NULL )
		return;

	pIsUserAnAdmin = (PIsUserAnAdmin)HookCode(shctx.hmShell32, "IsUserAnAdmin", IsUserAnAdminHook, NULL);

	AlreadyInstalledHooks = TRUE;
}

VOID HookSfc_os(
	VOID
	)
{
	static BOOLEAN AlreadyInstalledHooks = FALSE;
	if ( AlreadyInstalledHooks )
		return;
	
	shctx.hmSfc_os = GetModuleHandleW(dllname_sfc_os);
	if ( shctx.hmSfc_os == NULL )
		return;

	pSfcFileOperation = (PSfcFileException)GetProcAddress(shctx.hmSfc_os, MAKEINTRESOURCEA(5));
	if ( pSfcFileOperation != NULL ) 
		pSfcFileOperation = (PSfcFileException)HookCode(shctx.hmSfc_os, "SfcFileException", SfcFileExceptionHook,  pSfcFileOperation);

	AlreadyInstalledHooks = TRUE;
}

VOID HookOle32(
	VOID
	)
{
	static BOOLEAN AlreadyInstalledHooks = FALSE;
	if ( AlreadyInstalledHooks )
		return;
	
	shctx.hmOle32 = GetModuleHandleW(dllname_ole32);
	if ( shctx.hmOle32 == NULL )
		return;

	pCoCreateInstance = (PCoCreateInstance)HookCode(shctx.hmOle32, "CoCreateInstance", CoCreateInstanceHook, NULL);

	AlreadyInstalledHooks = TRUE;
}

VOID HookWinscard(
	VOID
	)
{
	static BOOLEAN AlreadyInstalledHooks = FALSE;
	if ( AlreadyInstalledHooks )
		return;
	
	shctx.hmWinscard = GetModuleHandleW(dllname_winscard);
	if ( shctx.hmWinscard == NULL )
		return;

	pSCardListReadersA = (PSCardListReadersA)HookCode(shctx.hmWinscard, "SCardListReadersA", SCardListReadersHookA, NULL);
	pSCardListReadersW = (PSCardListReadersW)HookCode(shctx.hmWinscard, "SCardListReadersW", SCardListReadersHookW, NULL);
	pSCardEstablishContext = (PSCardEstablishContext)HookCode(shctx.hmWinscard, "SCardEstablishContext", SCardEstablishContextHook, NULL);

	AlreadyInstalledHooks = TRUE;
}

#pragma warning(default:4055)
#pragma warning(default:4152)
