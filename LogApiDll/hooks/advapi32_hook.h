/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	advapi32_hook.h

Abstract:

	Advanced Windows 32 Base API hook interface.

	Last change 26.01.13

--*/

#ifndef _SHADVAPI32HOOK_
#define _SHADVAPI32HOOK_

#include <AclAPI.h>

#define ADVAPI32_EXCEPTION   L" advapi32!exception 0x"
#define ADVAPI32_EXCEPTION_A " advapi32!exception 0x"

/* SCM constants */

#define STR_SERVICE_TYPE_UNKNOWN_A "Unknown type"
#define STR_SERVICE_TYPE_UNKNOWN L"Unknown type"
#define STR_SERVICE_START_TYPE_UNKNOWN_A "Unknown start type"
#define STR_SERVICE_START_TYPE_UNKNOWN L"Unknown start type"
#define STR_SERVICE_ERRORCONTROL_UNKNOWN_A "Unknown error control"
#define STR_SERVICE_ERRORCONTROL_UNKNOWN L"Unknown error control"
#define STR_SERVICE_NO_CHANGE_A  "SERVICE_NO_CHANGE"
#define STR_SERVICE_NO_CHANGE	L"SERVICE_NO_CHANGE"
#define STR_SERVICE_KERNEL_DRIVER_A "SERVICE_KERNEL_DRIVER"
#define STR_SERVICE_KERNEL_DRIVER   L"SERVICE_KERNEL_DRIVER"
#define STR_SERVICE_FILE_SYSTEM_DRIVER_A "SERVICE_FILE_SYSTEM_DRIVER"
#define STR_SERVICE_FILE_SYSTEM_DRIVER  L"SERVICE_FILE_SYSTEM_DRIVER"
#define STR_SERVICE_WIN32_OWN_PROCESS_A "SERVICE_WIN32_OWN_PROCESS"
#define STR_SERVICE_WIN32_OWN_PROCESS   L"SERVICE_WIN32_OWN_PROCESS"
#define STR_SERVICE_WIN32_SHARE_PROCESS_A "SERVICE_WIN32_SHARE_PROCESS"
#define STR_SERVICE_WIN32_SHARE_PROCESS L"SERVICE_WIN32_SHARE_PROCESS"
#define STR_SERVICE_INTERACTIVE_PROCESS_A "SERVICE_INTERACTIVE_PROCESS"
#define STR_SERVICE_INTERACTIVE_PROCESS L"SERVICE_INTERACTIVE_PROCESS"
#define STR_SERVICE_BOOT_START_A "SERVICE_BOOT_START"
#define STR_SERVICE_BOOT_START L"SERVICE_BOOT_START"
#define STR_SERVICE_SYSTEM_START_A "SERVICE_SYSTEM_START"
#define STR_SERVICE_SYSTEM_START L"SERVICE_SYSTEM_START"
#define STR_SERVICE_AUTO_START_A "SERVICE_AUTO_START"
#define STR_SERVICE_AUTO_START L"SERVICE_AUTO_START"
#define STR_SERVICE_DEMAND_START_A "SERVICE_DEMAND_START"
#define STR_SERVICE_DEMAND_START   L"SERVICE_DEMAND_START"
#define STR_SERVICE_DISABLED_A "SERVICE_DISABLED"
#define STR_SERVICE_DISABLED L"SERVICE_DISABLED"
#define STR_SERVICE_ERROR_IGNORE_A "SERVICE_ERROR_IGNORE"
#define STR_SERVICE_ERROR_IGNORE L"SERVICE_ERROR_IGNORE"  
#define STR_SERVICE_ERROR_NORMAL_A "SERVICE_ERROR_NORMAL"
#define STR_SERVICE_ERROR_NORMAL L"SERVICE_ERROR_NORMAL"
#define STR_SERVICE_ERROR_SEVERE_A "SERVICE_ERROR_SEVERE"
#define STR_SERVICE_ERROR_SEVERE L"SERVICE_ERROR_SEVERE"
#define STR_SERVICE_ERROR_CRITICAL_A "SERVICE_ERROR_CRITICAL"
#define STR_SERVICE_ERROR_CRITICAL L"SERVICE_ERROR_CRITICAL"

/* Hive constants */
#define STR_HKEY_CURRENT_USER_A        "\\HKCU"
#define STR_HKEY_CURRENT_USER          L"\\HKCU"
#define STR_HKEY_CLASSES_ROOT_A        "\\HKCR"
#define STR_HKEY_CLASSES_ROOT          L"\\HKCR"
#define STR_HKEY_LOCAL_MACHINE_A       "\\HKLM"
#define STR_HKEY_LOCAL_MACHINE         L"\\HKLM"
#define STR_HKEY_USERS_A		       "\\HKU"
#define STR_HKEY_USERS			       L"\\HKU"
#define STR_HKEY_PERFORMANCE_DATA_A    "\\HKPD"
#define STR_HKEY_PERFORMANCE_DATA      L"\\HKPD"
#define STR_HKEY_PERFORMANCE_TEXT_A    "\\HKPT"
#define STR_HKEY_PERFORMANCE_TEXT      L"\\HKPT"
#define STR_HKEY_CURRENT_CONFIG_A	   "\\HKCC"
#define STR_HKEY_CURRENT_CONFIG		   L"\\HKCC"

#define RegNoValueA  "<No value>"
#define RegNoValueW L"<No value>"
#define RegNoKeyA    "<No key>"
#define RegNoKeyW    L"<No key">

#define RegTypeUnknownA  "Unknown type"
#define RegTypeUnknownW L"Unknown type"

LPSTR LogGetHiveKeyA(
	HKEY hRootKey
	);

LPWSTR LogGetHiveKeyW(
	HKEY hRootKey
	);

VOID LogRegCreateOpenExA(
	HKEY hKey,
	LPCSTR lpSubKey,
	REGSAM samDesired,
	LPSTR ApiName
	);

VOID LogRegCreateOpenExW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	REGSAM samDesired,
	LPWSTR ApiName
	);

VOID LogRegDeleteKeyValueA(
	HKEY hKey,
	LPCSTR lpSubKeyValueName,
	LPSTR ApiName
	);

VOID LogRegDeleteKeyValueW(
	HKEY hKey,
	LPCWSTR lpSubKeyValueName,
	LPWSTR ApiName
	);

typedef SC_HANDLE (WINAPI *POpenSCManagerA)(
	LPCSTR lpMachineName,
	LPCSTR lpDatabaseName,
	DWORD dwDesiredAccess
	);

typedef SC_HANDLE (WINAPI *POpenSCManagerW)(
	LPCWSTR lpMachineName,
	LPCWSTR lpDatabaseName,
	DWORD dwDesiredAccess
	);

typedef SC_HANDLE (WINAPI *POpenServiceA)(
	SC_HANDLE hSCManager,
	LPCSTR lpServiceName,
	DWORD dwDesiredAccess
	);

typedef SC_HANDLE (WINAPI *POpenServiceW)(
	SC_HANDLE hSCManager,
	LPCWSTR lpServiceName,
	DWORD dwDesiredAccess
	);

typedef SC_HANDLE (WINAPI *PCreateServiceA)(
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
	);

typedef SC_HANDLE (WINAPI *PCreateServiceW)(
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
	);

typedef BOOL (WINAPI *PStartServiceA)(
	SC_HANDLE hService,
	DWORD dwNumServiceArgs,
	LPCSTR *lpServiceArgVectors
	);

typedef BOOL (WINAPI *PStartServiceW)(
	SC_HANDLE hService,
	DWORD dwNumServiceArgs,
	LPCWSTR *lpServiceArgVectors
	);

typedef BOOL (WINAPI *PControlService)(
	SC_HANDLE hService,
	DWORD dwControl,
	LPSERVICE_STATUS lpServiceStatus
	);

typedef BOOL (WINAPI *PDeleteService)(
	SC_HANDLE hService
	);

typedef BOOL (WINAPI *PChangeServiceConfigA)(
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
	);

typedef BOOL (WINAPI *PChangeServiceConfigW)(
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
	);

typedef BOOL (WINAPI *PAreAnyAccessesGranted)(
	DWORD GrantedAccess,
	DWORD DesiredAccess
	);

typedef BOOL (WINAPI *PGetUserNameA) (
	LPSTR lpBuffer,
	LPDWORD pcbBuffer
	);

typedef BOOL (WINAPI *PGetUserNameW) (
	LPWSTR lpBuffer,
	LPDWORD pcbBuffer
	);

typedef BOOL (WINAPI *PGetCurrentHwProfileW)(
	LPHW_PROFILE_INFOW  lpHwProfileInfo
	);

typedef HANDLE (WINAPI *POpenEventLogA) (
	LPCSTR lpUNCServerName,
	LPCSTR lpSourceName
	);

typedef HANDLE (WINAPI *POpenEventLogW) (
	LPCWSTR lpUNCServerName,
	LPCWSTR lpSourceName
	);

typedef BOOL (WINAPI *PClearEventLogA)(
	HANDLE hEventLog,
	LPCSTR lpBackupFileName
	);

typedef BOOL (WINAPI *PClearEventLogW)(
	HANDLE hEventLog,
	LPCWSTR lpBackupFileName
	);

typedef BOOL (WINAPI *PCryptEncrypt)(
	HCRYPTKEY hKey,
	HCRYPTHASH hHash,
	BOOL Final,
	DWORD dwFlags,
	BYTE *pbData,
	DWORD *pdwDataLen,
	DWORD dwBufLen
	);

typedef BOOL (WINAPI *PCryptDecrypt)(
	HCRYPTKEY hKey,
	HCRYPTHASH hHash,
	BOOL Final,
	DWORD dwFlags,
	BYTE *pbData,
	DWORD *pdwDataLen
	);

typedef BOOL (WINAPI *PCryptHashData)(
	HCRYPTHASH hHash,
	CONST BYTE *pbData,
	DWORD dwDataLen,
	DWORD dwFlags
	);

typedef BOOL (WINAPI *PSetFileSecurityW)(
    LPCWSTR lpFileName,
    SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR pSecurityDescriptor
    );

typedef DWORD (WINAPI *PSetNamedSecurityInfoA)(
    LPSTR pObjectName,
    SE_OBJECT_TYPE ObjectType,
    SECURITY_INFORMATION SecurityInfo,
    PSID psidOwner,
    PSID psidGroup,
    PACL pDacl,
    PACL pSacl
    );

typedef DWORD (WINAPI *PSetNamedSecurityInfoW)(
    LPWSTR pObjectName,
    SE_OBJECT_TYPE ObjectType,
    SECURITY_INFORMATION SecurityInfo,
    PSID psidOwner,
    PSID psidGroup,
    PACL pDacl,
    PACL pSacl
    );

typedef DWORD (WINAPI *PSetSecurityInfo)(
    HANDLE handle,
    SE_OBJECT_TYPE ObjectType,
    SECURITY_INFORMATION SecurityInfo,
    PSID psidOwner,
    PSID psidGroup,
    PACL pDacl,
    PACL pSacl
    );

typedef BOOL(WINAPI *PCreateProcessAsUserA)(
	HANDLE hToken,
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

typedef BOOL(WINAPI *PCreateProcessAsUserW)(
	HANDLE hToken,
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

typedef LSTATUS (APIENTRY *PRegCreateKeyExA) (
	HKEY hKey,
	LPCSTR lpSubKey,
	DWORD Reserved,
	LPSTR lpClass,
	DWORD dwOptions,
	REGSAM samDesired,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PHKEY phkResult,
	LPDWORD lpdwDisposition
	);

typedef LSTATUS (APIENTRY *PRegCreateKeyExW) (
	HKEY hKey,
	LPCWSTR lpSubKey,
	DWORD Reserved,
	LPWSTR lpClass,
	DWORD dwOptions,
	REGSAM samDesired,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PHKEY phkResult,
	LPDWORD lpdwDisposition
	);

typedef LSTATUS (APIENTRY *PRegOpenKeyExA) (
	HKEY hKey,
	LPCSTR lpSubKey,
	DWORD ulOptions,
	REGSAM samDesired,
	PHKEY phkResult
	);

typedef LSTATUS (APIENTRY *PRegOpenKeyExW) (
	HKEY hKey,
	LPCWSTR lpSubKey,
	DWORD ulOptions,
	REGSAM samDesired,
	PHKEY phkResult
	);

typedef LSTATUS (APIENTRY *PRegDeleteKeyA) (
	HKEY hKey,
	LPCSTR lpSubKey
	);

typedef LSTATUS (APIENTRY *PRegDeleteKeyW) (
	HKEY hKey,
	LPCWSTR lpSubKey
	);

typedef LSTATUS (APIENTRY *PRegDeleteValueA) (
	HKEY hKey,
	LPCSTR lpValueName
	);

typedef LSTATUS (APIENTRY *PRegDeleteValueW) (
	HKEY hKey,
	LPCWSTR lpValueName
	);

typedef LSTATUS (APIENTRY *PRegEnumKeyExA) (
	HKEY hKey,
	DWORD dwIndex,
	LPSTR lpName,
	LPDWORD lpcchName,
	LPDWORD lpReserved,
	LPSTR lpClass,
	LPDWORD lpcchClass,
	PFILETIME lpftLastWriteTime
	);

typedef LSTATUS (APIENTRY *PRegEnumKeyExW) (
	HKEY hKey,
	DWORD dwIndex,
	LPWSTR lpName,
	LPDWORD lpcchName,
	LPDWORD lpReserved,
	LPWSTR lpClass,
	LPDWORD lpcchClass,
	PFILETIME lpftLastWriteTime
	);

typedef LSTATUS (APIENTRY *PRegEnumValueA) (
	HKEY hKey,
	DWORD dwIndex,
	LPSTR lpValueName,
	LPDWORD lpcchValueName,
	LPDWORD lpReserved,
	LPDWORD lpType,
	LPBYTE lpData,
	LPDWORD lpcbData
	);

typedef LSTATUS (APIENTRY *PRegEnumValueW) (
	HKEY hKey,
	DWORD dwIndex,
	LPWSTR lpValueName,
	LPDWORD lpcchValueName,
	LPDWORD lpReserved,
	LPDWORD lpType,
	LPBYTE lpData,
	LPDWORD lpcbData
	);

typedef LSTATUS (APIENTRY *PRegSetValueA) (
	HKEY hKey,
	LPCSTR lpSubKey,
	DWORD dwType,
	LPCSTR lpData,
	DWORD cbData
	);

typedef LSTATUS (APIENTRY *PRegSetValueW) (
	HKEY hKey,
	LPCWSTR lpSubKey,
	DWORD dwType,
	LPCWSTR lpData,
	DWORD cbData
	);

typedef LSTATUS (APIENTRY *PRegSetValueExA) (
	HKEY hKey,
	LPCSTR lpValueName,
	DWORD Reserved,
	DWORD dwType,
	CONST BYTE* lpData,
	DWORD cbData
	);

typedef LSTATUS (APIENTRY *PRegSetValueExW) (
	HKEY hKey,
	LPCWSTR lpValueName,
	DWORD Reserved,
	DWORD dwType,
	CONST BYTE* lpData,
	DWORD cbData
	);

typedef LSTATUS (APIENTRY *PRegSaveKeyA) (
	HKEY hKey,
	LPCSTR lpFile,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes
	);

typedef LSTATUS (APIENTRY *PRegSaveKeyW) (
	HKEY hKey,
	LPCWSTR lpFile,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes
	);

typedef LSTATUS (APIENTRY *PRegSaveKeyExA) (
	HKEY hKey,
	LPCSTR lpFile,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD Flags
	);

typedef LSTATUS (APIENTRY *PRegSaveKeyExW) (
	HKEY hKey,
	LPCWSTR lpFile,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD Flags
	);

typedef LSTATUS (APIENTRY *PRegLoadKeyA) (
	HKEY    hKey,
	LPCSTR  lpSubKey,
	LPCSTR  lpFile
	);

typedef LSTATUS (APIENTRY *PRegLoadKeyW) (
	HKEY    hKey,
	LPCWSTR  lpSubKey,
	LPCWSTR  lpFile
	);

typedef LSTATUS (APIENTRY *PRegCloseKey) (
	HKEY hKey
	);

extern POpenSCManagerA pOpenSCManagerA;
extern POpenSCManagerW pOpenSCManagerW;
extern POpenServiceA pOpenServiceA;
extern POpenServiceW pOpenServiceW;
extern PCreateServiceA pCreateServiceA;
extern PCreateServiceW pCreateServiceW;
extern PStartServiceA pStartServiceA;
extern PStartServiceW pStartServiceW;
extern PControlService pControlService;
extern PDeleteService pDeleteService;
extern PChangeServiceConfigA pChangeServiceConfigA;
extern PChangeServiceConfigW pChangeServiceConfigW;
extern PAreAnyAccessesGranted pAreAnyAccessesGranted;
extern PGetUserNameA pGetUserNameA;
extern PGetUserNameW pGetUserNameW;
extern PGetCurrentHwProfileW pGetCurrentHwProfileW;
extern POpenEventLogA pOpenEventLogA;
extern POpenEventLogW pOpenEventLogW;
extern PClearEventLogA pClearEventLogA;
extern PClearEventLogW pClearEventLogW;
extern PCryptEncrypt pCryptEncrypt;
extern PCryptDecrypt pCryptDecrypt;
extern PCryptHashData pCryptHashData;
extern PSetFileSecurityW pSetFileSecurityW;
extern PSetNamedSecurityInfoA pSetNamedSecurityInfoA;
extern PSetNamedSecurityInfoW pSetNamedSecurityInfoW;
extern PSetSecurityInfo pSetSecurityInfo;
extern PCreateProcessAsUserA pCreateProcessAsUserA;
extern PCreateProcessAsUserW pCreateProcessAsUserW;

//verbose mode items
extern PRegCreateKeyExA pRegCreateKeyExA;
extern PRegCreateKeyExW pRegCreateKeyExW;
extern PRegOpenKeyExA pRegOpenKeyExA;
extern PRegOpenKeyExW pRegOpenKeyExW;
extern PRegDeleteKeyA pRegDeleteKeyA;
extern PRegDeleteKeyW pRegDeleteKeyW;
extern PRegDeleteValueA pRegDeleteValueA;
extern PRegDeleteValueW pRegDeleteValueW;
extern PRegEnumKeyExA pRegEnumKeyExA;
extern PRegEnumKeyExW pRegEnumKeyExW;
extern PRegEnumValueA pRegEnumValueA;
extern PRegEnumValueW pRegEnumValueW;
extern PRegSetValueA pRegSetValueA;
extern PRegSetValueW pRegSetValueW;
extern PRegSetValueExA pRegSetValueExA;
extern PRegSetValueExW pRegSetValueExW;
extern PRegSaveKeyA pRegSaveKeyA;
extern PRegSaveKeyW pRegSaveKeyW;
extern PRegSaveKeyExA pRegSaveKeyExA;
extern PRegSaveKeyExW pRegSaveKeyExW;
extern PRegLoadKeyA pRegLoadKeyA;
extern PRegLoadKeyW pRegLoadKeyW;
extern PRegCloseKey pRegCloseKey;

SC_HANDLE WINAPI OpenSCManagerHookA(
	LPCSTR lpMachineName,
	LPCSTR lpDatabaseName,
	DWORD dwDesiredAccess
	);

SC_HANDLE WINAPI OpenSCManagerHookW(
	LPCWSTR lpMachineName,
	LPCWSTR lpDatabaseName,
	DWORD dwDesiredAccess
	);

SC_HANDLE WINAPI OpenServiceHookA(
	SC_HANDLE hSCManager,
	LPCSTR lpServiceName,
	DWORD dwDesiredAccess
	);

SC_HANDLE WINAPI OpenServiceHookW(
	SC_HANDLE hSCManager,
	LPCWSTR lpServiceName,
	DWORD dwDesiredAccess
	);

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
	);

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
	);

BOOL WINAPI StartServiceHookA(
	SC_HANDLE hService,
	DWORD dwNumServiceArgs,
	LPCSTR *lpServiceArgVectors
	);

BOOL WINAPI StartServiceHookW(
	SC_HANDLE hService,
	DWORD dwNumServiceArgs,
	LPCWSTR *lpServiceArgVectors
	);

BOOL WINAPI ControlServiceHook(
	SC_HANDLE hService,
	DWORD dwControl,
	LPSERVICE_STATUS lpServiceStatus
	);

BOOL WINAPI DeleteServiceHook(
	SC_HANDLE hService
	);

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
	);

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
	);

BOOL WINAPI AreAnyAccessesGrantedHook(
	DWORD GrantedAccess,
	DWORD DesiredAccess
	);

BOOL WINAPI GetUserNameHookA(
	LPSTR lpBuffer,
	LPDWORD pcbBuffer
	);

BOOL WINAPI GetUserNameHookW(
	LPWSTR lpBuffer,
	LPDWORD pcbBuffer
	);

BOOL WINAPI GetCurrentHwProfileHookW(
	LPHW_PROFILE_INFOW lpHwProfileInfo
	);

HANDLE WINAPI OpenEventLogHookA(
	LPCSTR lpUNCServerName,
	LPCSTR lpSourceName
	);

HANDLE WINAPI OpenEventLogHookW(
	LPCWSTR lpUNCServerName,
	LPCWSTR lpSourceName
	);

BOOL WINAPI ClearEventLogHookA(
	HANDLE hEventLog,
	LPCSTR lpBackupFileName
	);

BOOL WINAPI ClearEventLogHookW(
	HANDLE hEventLog,
	LPCWSTR lpBackupFileName
	);

BOOL WINAPI CryptEncryptHook(
	HCRYPTKEY hKey,
	HCRYPTHASH hHash,
	BOOL Final,
	DWORD dwFlags,
	BYTE *pbData,
	DWORD *pdwDataLen,
	DWORD dwBufLen
	);

BOOL WINAPI CryptDecryptHook(
	HCRYPTKEY hKey,
	HCRYPTHASH hHash,
	BOOL Final,
	DWORD dwFlags,
	BYTE *pbData,
	DWORD *pdwDataLen
	);

BOOL WINAPI CryptHashDataHook(
	HCRYPTHASH hHash,
	CONST BYTE *pbData,
	DWORD dwDataLen,
	DWORD dwFlags
	);

BOOL WINAPI SetFileSecurityHookW(
    LPCWSTR lpFileName,
    SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR pSecurityDescriptor
    );

DWORD WINAPI SetNamedSecurityInfoHookA(
    LPSTR pObjectName,
    SE_OBJECT_TYPE ObjectType,
    SECURITY_INFORMATION SecurityInfo,
    PSID psidOwner,
    PSID psidGroup,
    PACL pDacl,
    PACL pSacl
    );

DWORD WINAPI SetNamedSecurityInfoHookW(
    LPWSTR pObjectName,
    SE_OBJECT_TYPE ObjectType,
    SECURITY_INFORMATION SecurityInfo,
    PSID psidOwner,
    PSID psidGroup,
    PACL pDacl,
    PACL pSacl
    );

DWORD WINAPI SetSecurityInfoHook(
    HANDLE handle,
    SE_OBJECT_TYPE ObjectType,
    SECURITY_INFORMATION SecurityInfo,
    PSID psidOwner,
    PSID psidGroup,
    PACL pDacl,
    PACL pSacl
    );

BOOL WINAPI CreateProcessAsUserHookA(
	HANDLE hToken,
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

BOOL WINAPI CreateProcessAsUserHookW(
	HANDLE hToken,
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
	);

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
	);

LSTATUS APIENTRY RegOpenKeyExHookA(
	HKEY hKey,
	LPCSTR lpSubKey,
	DWORD ulOptions,
	REGSAM samDesired,
	PHKEY phkResult
	);

LSTATUS APIENTRY RegOpenKeyExHookW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	DWORD ulOptions,
	REGSAM samDesired,
	PHKEY phkResult
	);

LSTATUS APIENTRY RegDeleteKeyHookA(
	HKEY hKey,
	LPCSTR lpSubKey
	);

LSTATUS APIENTRY RegDeleteKeyHookW(
	HKEY hKey,
	LPCWSTR lpSubKey
	);

LSTATUS APIENTRY RegDeleteValueHookA(
	HKEY hKey,
	LPCSTR lpValueName
	);

LSTATUS APIENTRY RegDeleteValueHookW(
	HKEY hKey,
	LPCWSTR lpValueName
	);

LSTATUS APIENTRY RegEnumKeyExHookA(
	HKEY hKey,
	DWORD dwIndex,
	LPSTR lpName,
	LPDWORD lpcchName,
	LPDWORD lpReserved,
	LPSTR lpClass,
	LPDWORD lpcchClass,
	PFILETIME lpftLastWriteTime
	);

LSTATUS APIENTRY RegEnumKeyExHookW(
	HKEY hKey,
	DWORD dwIndex,
	LPWSTR lpName,
	LPDWORD lpcchName,
	LPDWORD lpReserved,
	LPWSTR lpClass,
	LPDWORD lpcchClass,
	PFILETIME lpftLastWriteTime
	);

LSTATUS APIENTRY RegEnumValueHookA(
	HKEY hKey,
	DWORD dwIndex,
	LPSTR lpValueName,
	LPDWORD lpcchValueName,
	LPDWORD lpReserved,
	LPDWORD lpType,
	LPBYTE lpData,
	LPDWORD lpcbData
	);

LSTATUS APIENTRY RegEnumValueHookW(
	HKEY hKey,
	DWORD dwIndex,
	LPWSTR lpValueName,
	LPDWORD lpcchValueName,
	LPDWORD lpReserved,
	LPDWORD lpType,
	LPBYTE lpData,
	LPDWORD lpcbData
	);

LSTATUS APIENTRY RegSetValueHookA(
	HKEY hKey,
	LPCSTR lpSubKey,
	DWORD dwType,
	LPCSTR lpData,
	DWORD cbData
	);

LSTATUS APIENTRY RegSetValueHookW(
	HKEY hKey,
	LPCWSTR lpSubKey,
	DWORD dwType,
	LPCWSTR lpData,
	DWORD cbData
	);

LSTATUS APIENTRY RegSetValueExHookA(
	HKEY hKey,
	LPCSTR lpValueName,
	DWORD Reserved,
	DWORD dwType,
	CONST BYTE* lpData,
	DWORD cbData
	);

LSTATUS APIENTRY RegSetValueExHookW(
	HKEY hKey,
	LPCWSTR lpValueName,
	DWORD Reserved,
	DWORD dwType,
	CONST BYTE* lpData,
	DWORD cbData
	);

LSTATUS APIENTRY RegSaveKeyHookA(
	HKEY hKey,
	LPCSTR lpFile,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes
	);

LSTATUS APIENTRY RegSaveKeyHookW(
	HKEY hKey,
	LPCWSTR lpFile,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes
	);

LSTATUS APIENTRY RegSaveKeyExHookA(
	HKEY hKey,
	LPCSTR lpFile,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD Flags
	);

LSTATUS APIENTRY RegSaveKeyExHookW(
	HKEY hKey,
	LPCWSTR lpFile,
	CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD Flags
	);

LSTATUS APIENTRY RegLoadKeyHookA(
	HKEY    hKey,
	LPCSTR  lpSubKey,
	LPCSTR  lpFile
	);

LSTATUS APIENTRY RegLoadKeyHookW(
	HKEY    hKey,
	LPCWSTR  lpSubKey,
	LPCWSTR  lpFile
	);

LSTATUS APIENTRY RegCloseKeyHook(
	HKEY hKey
	);

#endif /* _SHADVAPI32HOOK_ */