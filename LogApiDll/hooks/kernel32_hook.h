/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	kernel32_hook.h

Abstract:

	Kernel32 API hook interface.

	Last change 25.01.13

--*/

#ifndef _SHKERNEL32HOOK_
#define _SHKERNEL32HOOK_

#define KERNEL32_EXCEPTION   L" kernel32!exception 0x"
#define KERNEL32_EXCEPTION_A " kernel32!exception 0x"

/*
typedefs
*/
typedef int (WINAPI *PlstrcmpA)(
	LPCSTR lpString1,
	LPCSTR lpString2
	);

typedef int (WINAPI *PlstrcmpW)(
	LPCWSTR lpString1,
	LPCWSTR lpString2
	);

typedef int (WINAPI *PlstrcmpiA)(
	LPCSTR lpString1,
	LPCSTR lpString2
	);

typedef int (WINAPI *PlstrcmpiW)(
	LPCWSTR lpString1,
	LPCWSTR lpString2
	);

/*++++
internal use, do not change
++++*/
typedef int (WINAPI *PFNstrcmpA)(
	LPCSTR lpString1,
	LPCSTR lpString2
	);

typedef int (WINAPI *PFNstrcmpW)(
	LPCWSTR lpString1,
	LPCWSTR lpString2
	);
/*----
---*/

typedef BOOL (WINAPI *PIsDebuggerPresent)(
	VOID
	);

typedef BOOL (WINAPI *PCheckRemoteDebuggerPresent)(
	HANDLE hProcess,
	PBOOL pbDebuggerPresent
	);

typedef LANGID (WINAPI *PGetSystemDefaultLangID)(VOID);

typedef BOOL (WINAPI *PCreatePipe)(
	PHANDLE hReadPipe,
	PHANDLE hWritePipe,
	LPSECURITY_ATTRIBUTES lpPipeAttributes,
	DWORD nSize
	);

typedef BOOL (WINAPI *PConnectNamedPipe)(
	HANDLE hNamedPipe,
	LPOVERLAPPED lpOverlapped
	);

typedef BOOL (WINAPI *PFreeLibrary) (
	HMODULE hLibModule
	);

typedef VOID (WINAPI *PExitProcess)(
	UINT uExitCode
	);

typedef DEP_SYSTEM_POLICY_TYPE (WINAPI *PGetSystemDEPPolicy)(
	VOID
	);

typedef DWORD (WINAPI *PGetFileAttributesW)(
	LPCWSTR lpFileName
	);

typedef HANDLE (WINAPI *PCreateNamedPipeW)(
	LPCWSTR lpName,
	DWORD dwOpenMode,
	DWORD dwPipeMode,
	DWORD nMaxInstances,
	DWORD nOutBufferSize,
	DWORD nInBufferSize,
	DWORD nDefaultTimeOut,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes
	);

typedef BOOL (WINAPI *PCallNamedPipeW)(
	LPCWSTR lpNamedPipeName,
	LPVOID lpInBuffer,
	DWORD nInBufferSize,
	LPVOID lpOutBuffer,
	DWORD nOutBufferSize,
	LPDWORD lpBytesRead,
	DWORD nTimeOut
	);

typedef HMODULE (WINAPI *PGetModuleHandleW)(
	LPCWSTR lpModuleName
	);

typedef BOOL (WINAPI *PGetVolumeInformationW)(
	LPCWSTR lpRootPathName,
	LPWSTR lpVolumeNameBuffer,
	DWORD nVolumeNameSize,
	LPDWORD lpVolumeSerialNumber,
	LPDWORD lpMaximumComponentLength,
	LPDWORD lpFileSystemFlags,
	LPWSTR lpFileSystemNameBuffer,
	DWORD nFileSystemNameSize
	);

typedef BOOL (WINAPI *PGetComputerNameW)(
	LPWSTR lpBuffer,
	LPDWORD nSize
	);

typedef DWORD (WINAPI *PSearchPathW)(
	LPCWSTR lpPath,
	LPCWSTR lpFileName,
	LPCWSTR lpExtension,
	DWORD nBufferLength,
	LPWSTR lpBuffer,
	LPWSTR *lpFilePart
	);

typedef BOOL (WINAPI *PDeleteFileW)(
	LPCWSTR lpFileName
	);

typedef BOOL (WINAPI *PRemoveDirectoryW)(
	LPCWSTR lpPathName
	);

typedef HANDLE (WINAPI *POpenMutexW)(
	DWORD dwDesiredAccess,
	BOOL bInheritHandle,
	LPCWSTR lpName
	);

typedef HANDLE (WINAPI *PCreateMutexW)(
	LPSECURITY_ATTRIBUTES lpMutexAttributes,
	BOOL bInitialOwner,
	LPCWSTR lpName
	);

typedef HANDLE (WINAPI *PCreateEventW)(
    LPSECURITY_ATTRIBUTES lpEventAttributes,
    BOOL bManualReset,
    BOOL bInitialState,
    LPCWSTR lpName
    );

typedef BOOL (WINAPI *PCreateProcessA)(
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
	);

typedef BOOL (WINAPI *PCreateProcessW)(
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
	);

typedef HANDLE (WINAPI *PCreateFileW)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
    );

typedef HANDLE (WINAPI *PCreateFileMappingW)(
    HANDLE hFile,
    LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    DWORD flProtect,
    DWORD dwMaximumSizeHigh,
    DWORD dwMaximumSizeLow,
    LPCWSTR lpName
    );

typedef HANDLE (WINAPI *PCreateRemoteThread)(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
    );

typedef HANDLE (WINAPI *PCreateRemoteThreadEx)(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    LPDWORD lpThreadId
    );

typedef HANDLE (WINAPI *PCreateToolhelp32Snapshot)(
    DWORD dwFlags,
    DWORD th32ProcessID
    );

typedef BOOL (WINAPI *PProcess32FirstW)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32W lppe
    );

typedef BOOL (WINAPI *PProcess32NextW)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32W lppe
    );

typedef HANDLE (WINAPI *PFindFirstFileExW)(
    LPCWSTR lpFileName,
    FINDEX_INFO_LEVELS fInfoLevelId,
    LPVOID lpFindFileData,
    FINDEX_SEARCH_OPS fSearchOp,
    LPVOID lpSearchFilter,
    DWORD dwAdditionalFlags
    );

typedef BOOL (WINAPI *PFindNextFileW)(
    HANDLE hFindFile,
    LPWIN32_FIND_DATAW lpFindFileData
    );

typedef HANDLE (WINAPI *PFindFirstFileNameW)(
    LPCWSTR lpFileName,
    DWORD dwFlags,
    LPDWORD StringLength,
    PWCHAR LinkName
    );

typedef BOOL (WINAPI *PFindNextFileNameW)(
    HANDLE hFindStream,
    LPDWORD StringLength,
    PWCHAR LinkName
    );

typedef BOOL (WINAPI *PCreateDirectoryExW)(
    LPCWSTR lpTemplateDirectory,
    LPCWSTR lpNewDirectory,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes
    );

typedef BOOL (WINAPI *PCreateDirectoryW)(
    LPCWSTR lpPathName,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes
    );

typedef BOOL (WINAPI *PCopyFileA)(
    LPCSTR lpExistingFileName,
    LPCSTR lpNewFileName,
    BOOL bFailIfExists
    );

typedef BOOL (WINAPI *PCopyFileW)(
    LPCWSTR lpExistingFileName,
    LPCWSTR lpNewFileName,
    BOOL bFailIfExists
    );

typedef BOOL (WINAPI *PCopyFileExA)(
    LPCSTR lpExistingFileName,
    LPCSTR lpNewFileName,
    LPPROGRESS_ROUTINE lpProgressRoutine,
    LPVOID lpData,
    LPBOOL pbCancel,
    DWORD dwCopyFlags
    );

typedef BOOL (WINAPI *PCopyFileExW)(
    LPCWSTR lpExistingFileName,
    LPCWSTR lpNewFileName,
    LPPROGRESS_ROUTINE lpProgressRoutine,
    LPVOID lpData,
    LPBOOL pbCancel,
    DWORD dwCopyFlags
    );

typedef BOOL (WINAPI *PMoveFileA)(
    LPCSTR lpExistingFileName,
    LPCSTR lpNewFileName
    );

typedef BOOL (WINAPI *PMoveFileW)(
    LPCWSTR lpExistingFileName,
    LPCWSTR lpNewFileName
    );

typedef BOOL (WINAPI *PMoveFileExA)(
    LPCSTR lpExistingFileName,
    LPCSTR lpNewFileName,
    DWORD    dwFlags
    );

typedef BOOL (WINAPI *PMoveFileExW)(
    LPCWSTR lpExistingFileName,
    LPCWSTR lpNewFileName,
    DWORD    dwFlags
    );

/*
forwards
*/
extern PlstrcmpA plstrcmpA;
extern PlstrcmpW plstrcmpW;
extern PlstrcmpiA plstrcmpiA;
extern PlstrcmpiW plstrcmpiW;
extern PIsDebuggerPresent pIsDebuggerPresent;
extern PCheckRemoteDebuggerPresent pCheckRemoteDebuggerPresent;
extern PGetSystemDefaultLangID pGetSystemDefaultLangID;
extern PCreatePipe pCreatePipe;
extern PConnectNamedPipe pConnectNamedPipe;
extern PFreeLibrary pFreeLibrary;
extern PExitProcess pExitProcess;
extern PGetSystemDEPPolicy pGetSystemDEPPolicy;
extern PGetFileAttributesW pGetFileAttributesW;
extern PCreateNamedPipeW pCreateNamedPipeW;
extern PCallNamedPipeW pCallNamedPipeW;
extern PGetModuleHandleW pGetModuleHandleW;
extern PGetVolumeInformationW pGetVolumeInformationW;
extern PGetComputerNameW pGetComputerNameW;
extern PSearchPathW pSearchPathW;
extern PDeleteFileW pDeleteFileW;
extern PRemoveDirectoryW pRemoveDirectoryW;
extern POpenMutexW pOpenMutexW;
extern PCreateMutexW pCreateMutexW;
extern PCreateEventW pCreateEventW;
extern PCreateProcessA pCreateProcessA;
extern PCreateProcessW pCreateProcessW;
extern PCreateFileW pCreateFileW;
extern PCreateFileMappingW pCreateFileMappingW;
extern PCreateRemoteThread pCreateRemoteThread;
extern PCreateRemoteThreadEx pCreateRemoteThreadEx;
extern PCreateToolhelp32Snapshot pCreateToolhelp32Snapshot;
extern PProcess32FirstW pProcess32FirstW;
extern PProcess32NextW pProcess32NextW;
extern PFindFirstFileExW pFindFirstFileExW;
extern PFindNextFileW pFindNextFileW;
extern PFindFirstFileNameW pFindFirstFileNameW;
extern PFindNextFileNameW pFindNextFileNameW;
extern PCreateDirectoryExW pCreateDirectoryExW;
extern PCreateDirectoryW pCreateDirectoryW;
extern PCopyFileA pCopyFileA;
extern PCopyFileW pCopyFileW;
extern PCopyFileExA pCopyFileExA;
extern PCopyFileExW pCopyFileExW;
extern PMoveFileA pMoveFileA;
extern PMoveFileW pMoveFileW;
extern PMoveFileExA pMoveFileExA;
extern PMoveFileExW pMoveFileExW;

/*
Handlers 
*/
int WINAPI lstrcmpHookA(
	LPCSTR lpString1,
	LPCSTR lpString2
	);

int WINAPI lstrcmpHookW(
	LPCWSTR lpString1,
	LPCWSTR lpString2
	);

int WINAPI lstrcmpiHookA(
	LPCSTR lpString1,
	LPCSTR lpString2
	);

int WINAPI lstrcmpiHookW(
	LPCWSTR lpString1,
	LPCWSTR lpString2
	);

VOID WINAPI OutputDebugStringHookA(
	LPCSTR lpOutputString
	);

BOOL WINAPI IsDebuggerPresentHook(
	VOID
	);

BOOL WINAPI CheckRemoteDebuggerPresentHook(
	HANDLE hProcess,
	PBOOL pbDebuggerPresent
	);

LANGID WINAPI GetSystemDefaultLangIDHook(
	VOID
	);

BOOL WINAPI CreatePipeHook(
	PHANDLE hReadPipe,
	PHANDLE hWritePipe,
	LPSECURITY_ATTRIBUTES lpPipeAttributes,
	DWORD nSize
	);

BOOL WINAPI ConnectNamedPipeHook(
	HANDLE hNamedPipe,
	LPOVERLAPPED lpOverlapped
	);

BOOL WINAPI FreeLibraryHook(
	HMODULE hLibModule
	);

VOID WINAPI ExitProcessHook(
	UINT uExitCode
	);

DEP_SYSTEM_POLICY_TYPE WINAPI GetSystemDEPPolicyHook(
	VOID
	);

DWORD WINAPI GetFileAttributesHookW(
	LPCWSTR lpFileName
	);

HANDLE WINAPI CreateNamedPipeHookW(
	LPCWSTR lpName,
	DWORD dwOpenMode,
	DWORD dwPipeMode,
	DWORD nMaxInstances,
	DWORD nOutBufferSize,
	DWORD nInBufferSize,
	DWORD nDefaultTimeOut,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes
	);

BOOL WINAPI CallNamedPipeHookW(
	LPCWSTR lpNamedPipeName,
	LPVOID lpInBuffer,
	DWORD nInBufferSize,
	LPVOID lpOutBuffer,
	DWORD nOutBufferSize,
	LPDWORD lpBytesRead,
	DWORD nTimeOut
	);

HMODULE WINAPI GetModuleHandleHookW(
	LPCWSTR lpModuleName
	);

BOOL WINAPI GetVolumeInformationHookW(
	LPCWSTR lpRootPathName,
	LPWSTR lpVolumeNameBuffer,
	DWORD nVolumeNameSize,
	LPDWORD lpVolumeSerialNumber,
	LPDWORD lpMaximumComponentLength,
	LPDWORD lpFileSystemFlags,
	LPWSTR lpFileSystemNameBuffer,
	DWORD nFileSystemNameSize
	);

BOOL WINAPI GetComputerNameHookW(
	LPWSTR lpBuffer,
	LPDWORD nSize
	);

DWORD WINAPI SearchPathHookW(
	LPCWSTR lpPath,
	LPCWSTR lpFileName,
	LPCWSTR lpExtension,
	DWORD nBufferLength,
	LPWSTR lpBuffer,
	LPWSTR *lpFilePart
	);

BOOL WINAPI DeleteFileHookW(
	LPCWSTR lpFileName
	);

BOOL WINAPI RemoveDirectoryHookW(
	LPCWSTR lpPathName
	);

HANDLE WINAPI OpenMutexHookW(
	DWORD dwDesiredAccess,
	BOOL bInheritHandle,
	LPCWSTR lpName
	);

HANDLE WINAPI CreateMutexHookW(
	LPSECURITY_ATTRIBUTES lpMutexAttributes,
	BOOL bInitialOwner,
	LPCWSTR lpName
	);

HANDLE WINAPI CreateEventHookW(
    LPSECURITY_ATTRIBUTES lpEventAttributes,
    BOOL bManualReset,
    BOOL bInitialState,
    LPCWSTR lpName
	);

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
	);

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
	);

HANDLE WINAPI CreateFileHookW(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
	);

HANDLE WINAPI CreateFileHookVerboseW(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
	);

HANDLE WINAPI CreateFileMappingHookW(
	HANDLE hFile,
	LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	DWORD flProtect,
	DWORD dwMaximumSizeHigh,
	DWORD dwMaximumSizeLow,
	LPCWSTR lpName
	);

HANDLE WINAPI CreateRemoteThreadHook(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
    );

HANDLE WINAPI CreateRemoteThreadExHook(
	HANDLE hProcess,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	SIZE_T dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	DWORD dwCreationFlags,
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	LPDWORD lpThreadId
	);

HANDLE WINAPI CreateToolhelp32SnapshotHook(
    DWORD dwFlags,
    DWORD th32ProcessID
    );

BOOL WINAPI Process32FirstHookW(
	HANDLE hSnapshot,
	LPPROCESSENTRY32W lppe
	);

BOOL WINAPI Process32NextHookW(
	HANDLE hSnapshot,
	LPPROCESSENTRY32W lppe
	);

HANDLE WINAPI FindFirstFileExHookW(
	  LPCWSTR lpFileName,
	  FINDEX_INFO_LEVELS fInfoLevelId,
	  LPVOID lpFindFileData,
	  FINDEX_SEARCH_OPS fSearchOp,
	  LPVOID lpSearchFilter,
	  DWORD dwAdditionalFlags
	  );

BOOL WINAPI FindNextFileHookW(
	  HANDLE hFindFile,
	  LPWIN32_FIND_DATAW lpFindFileData
	  );

HANDLE WINAPI FindFirstFileNameHookW(
	LPCWSTR lpFileName,
	DWORD dwFlags,
	LPDWORD StringLength,
	PWCHAR LinkName
	);

BOOL WINAPI FindNextFileNameHookW(
	HANDLE hFindStream,
	LPDWORD StringLength,
	PWCHAR LinkName
	);

BOOL WINAPI CreateDirectoryExHookW(
	LPCWSTR lpTemplateDirectory,
	LPCWSTR lpNewDirectory,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes
	);

BOOL WINAPI CreateDirectoryHookW(
	LPCWSTR lpPathName,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes
	);

BOOL WINAPI CopyFileHookA(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName,
	BOOL bFailIfExists
	);

BOOL WINAPI CopyFileHookW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName,
	BOOL bFailIfExists
	);

BOOL WINAPI CopyFileExHookA(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName,
	LPPROGRESS_ROUTINE lpProgressRoutine,
	LPVOID lpData,
	LPBOOL pbCancel,
	DWORD dwCopyFlags
	);

BOOL WINAPI CopyFileExHookW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName,
	LPPROGRESS_ROUTINE lpProgressRoutine,
	LPVOID lpData,
	LPBOOL pbCancel,
	DWORD dwCopyFlags
	);

BOOL WINAPI MoveFileHookA(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName
	);

BOOL WINAPI MoveFileHookW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName
	);

BOOL WINAPI MoveFileExHookA(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName,
	DWORD    dwFlags
	);

BOOL WINAPI MoveFileExHookW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName,
	DWORD    dwFlags
	);

#endif /* _SHKERNEL32HOOK_ */