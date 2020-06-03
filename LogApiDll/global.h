/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	global.h

Abstract:

	Global definitions.

	Last change 25.02.13

--*/

#ifndef _SHGLOBAL_
#define _SHGLOBAL_

//#define USE_SBIE_HDRS // we can use sandboxie headers in stead of the process hacker once
#define USE_MINI_HOOK // don't use sbie hook it seams buggy

#ifdef USE_PRIVATE_HDRS

#include <windows.h>
#pragma warning(push)
#pragma warning(disable : 4005)
#include "ntdll\ntstatus.h" 
#include "ntdll\ntdll.h"
#pragma warning(pop)

#else
#ifndef USE_SBIE_HDRS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#endif

#include <windows.h>
#include <windowsx.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winioctl.h>

typedef double DOUBLE;
typedef GUID *PGUID;

#include <phnt.h>

#define PSYSTEM_PROCESSES_INFORMATION PSYSTEM_PROCESS_INFORMATION
#define NextEntryDelta NextEntryOffset

#define PAGE_SIZE 0x1000

#include <winsock.h>
#include <wincrypt.h>

#else

#include <windows.h>
#pragma warning(push)
#pragma warning(disable : 4005) 
#include "../Sandboxie/common/win32_ntddk.h"
#pragma warning(pop)

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus
	NTSYSAPI NTSTATUS NTAPI RtlEnterCriticalSection(_Inout_ PRTL_CRITICAL_SECTION CriticalSection);
	NTSYSAPI NTSTATUS NTAPI RtlLeaveCriticalSection(_Inout_ PRTL_CRITICAL_SECTION CriticalSection);
	NTSYSCALLAPI NTSTATUS NTAPI NtFreeVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress, _Inout_ PSIZE_T RegionSize, _In_ ULONG FreeType);
#ifdef __cplusplus
}
#endif //__cplusplus

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
	PVOID ContextInformation;
	ULONG_PTR OriginalBase;
	LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// SystemProcessesAndThreadsInformation
typedef struct _SYSTEM_PROCESSES_INFORMATION {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	/*KPRIORITY*/ LONG BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	//VM_COUNTERS VmCounters;
	//IO_COUNTERS IoCounters;
	//SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESSES_INFORMATION, *PSYSTEM_PROCESSES_INFORMATION;

#define PPS_APC_ROUTINE PVOID

#undef NtCurrentPeb
#include "xeb.h"

#define RemoveEntryList(Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_Flink;\
    _EX_Flink = (Entry)->Flink;\
    _EX_Blink = (Entry)->Blink;\
    _EX_Blink->Flink = _EX_Flink;\
    _EX_Flink->Blink = _EX_Blink;\
    }

#endif // USE_SBIE_HDRS

#define ARGUMENT_PRESENT(ArgumentPointer)    (\
	(CHAR *)((ULONG_PTR)(ArgumentPointer)) != (CHAR *)(NULL) )

#define IN_REGION(x, Base, Size) (((ULONG_PTR)x >= (ULONG_PTR)Base) && ((ULONG_PTR)x <= (ULONG_PTR)Base + (ULONG_PTR)Size))

#endif // USE_PRIVATE_HDRS

#include <TlHelp32.h>
#include "types.h"
#include "subroutines.h"
#include "hidedll.h"
#include "logger.h"
#include "protect.h"
#ifdef USE_MINI_HOOK
#include "..\libMinHook\include\MinHook.h"
#endif
#include "hooks\hooks.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus
	// Note: these functions are present in the ntdll but not exported, wen can acces them using runtime dynamic linking.
	extern int(*sprintfP)(char *_Buffer, const char * fmt, ...);
	extern int(*swprintfP)(wchar_t *_Buffer, const wchar_t * fmt, ...);
#ifdef __cplusplus
}
#endif //__cplusplus


#ifdef USE_PRIVATE_HDRS
#include "rtls\prtl.h"
#else

#define _strlenA(s) strlen(s)
#define _strlenW(s) wcslen(s)
#define _strcpyA(dest, src) strcpy(dest, src)
#define _strcpyW(dest, src) wcscpy(dest, src)
#define _strcatA(dest, src) strcat(dest, src)
#define _strcatW(dest, src) wcscat(dest, src)
__inline char *_strendA(char *s)									{ return s + strlen(s); }
__inline wchar_t *_strendW(wchar_t *s)								{ return s + wcslen(s); }
__inline char *_strncpyA(char *dest, size_t ccdest, const char *src, size_t ccsrc)			
																	{ return strncpy(dest, src, (ccdest <= ccsrc) ? ccdest - 1 : ccsrc); }
__inline wchar_t *_strncpyW(wchar_t *dest, size_t ccdest, const wchar_t *src, size_t ccsrc) 
																	{ return wcsncpy(dest, src, (ccdest <= ccsrc) ? ccdest - 1 : ccsrc); }
#define _strcmpiA(s1, s2) _stricmp(s1, s2)
#define _strcmpiW(s1, s2) _wcsicmp(s1, s2)

__inline void ultostrA(unsigned long x, char *s)					{ sprintfP(s, "%u", x); }
__inline void ultostrW(unsigned long x, wchar_t *s)					{ swprintfP(s, L"%u", x); }
__inline void u64tostrA(unsigned __int64 x, char *s)				{ sprintfP(s, "%llu", x); }
__inline void u64tostrW(unsigned __int64 x, wchar_t *s)				{ swprintfP(s, L"llu", x); }
#if defined(_M_X64) || defined(_WIN64)
#define _ultostrA u64tostrA
#define _ultostrW u64tostrW
#else
#define _ultostrA ultostrA
#define _ultostrW ultostrW
#endif

__inline void itostrA(int x, char *s)								{ sprintfP(s, "%d", x); }
__inline void itostrW(int x, wchar_t *s)							{ swprintfP(s, L"%d", x); }
__inline void i64tostrA(signed long long int x, char *s) 			{ sprintfP(s, "%lld", x); }
__inline void i64tostrW(signed long long int x, wchar_t *s) 		{ swprintfP(s, L"%lld", x); }
#if defined(_M_X64) || defined(_WIN64)
#define ltostrA i64tostrA
#define ltostrW i64tostrW
#else
#define ltostrA itostrA
#define ltostrW itostrW
#endif

__inline void ultohexA(unsigned long x, char *s) 					{ sprintfP(s, "%08X", x); }
__inline void ultohexW(unsigned long x, wchar_t *s) 				{ swprintfP(s, L"%08X", x); }
__inline void u64tohexA(unsigned __int64 x, char *s)				{ sprintfP(s, "%016X", x); }
__inline void u64tohexW(unsigned __int64 x, wchar_t *s) 			{ swprintfP(s, L"%016X", x); }
#if defined(_M_X64) || defined(_WIN64)
#define utohexA u64tohexA
#define utohexW u64tohexW
#else
#define utohexA ultohexA
#define utohexW ultohexW
#endif

__inline ULONG_PTR align(ULONG_PTR x, ULONG_PTR base)
{
	ULONG_PTR y = x % base;
	if (y == 0) return x;
	y = (x - y);
	return y + base;
}

#define ExtractFileNameW_S(f, buf, sz) ExtractSufixW_S(f, L'\\', buf, sz)

#endif // USE_SBIE_HDRS

#define _WARNING_OFF(x) __pragma(warning(disable:x))
#define _WARNING_ON(x) __pragma(warning(default:x))

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#define SBIEHOOK			"SbieDll_Hook"
#define SBIEDLLCALLBACK		"SbieDll_RegisterDllCallback"

#define _htons(x)        ((((x) >> 8) & 0x00FF) | (((x) << 8) & 0xFF00))
#define PageFileBackedW		L"<Pagefile Backed>"
#define PageFileBackedA		"<Pagefile Backed>"
#define NullStrW			L"null"	 
#define NullStrA			"null"
#define CommaW				L","
#define CommaA				","
#define CommaExW			L", "
#define CommaExA			", "
#define OpenBracketW		L"("
#define CloseBracketW		L")"
#define OpenBracketA		"("
#define CloseBracketA		")"
#define OpenBracketExW     L" ["
#define OpenBracketExA		" ["
#define OpenBracketEx2A		"["
#define OpenBracketEx2W		L"["
#define CloseBracketExW    L"]"
#define CloseBracketExA     "]"
#define EmptyStrA			"empty"
#define EmptyStrW           L"empty"
#define NoStringW			L""
#define NoStringA			 ""
#define SlashA				 "\\"
#define SlashW				L"\\"
#define HexPrepA			"0x"
#define HexPrepW			L"0x"
#define ArrowA				"->"
#define ArrowW				L"->"
#define DotA				"."
#define DotW				L"."
#define ColonA				":"
#define ColonW				L":"
#define UnknownA			"Unknown"
#define UnknownW			L"Unknown"

#define ServerClassName		"TFormBSA"
#define ServerWindowName	"Buster Sandbox Analyzer"

#define ServerPipeName		L"\\\\.\\pipe\\LogAPI"

#define dllname_sbiedll		L"sbiedll.dll"
#define dllname_kernel32	L"kernel32.dll"
#define dllname_ntdll		L"ntdll.dll"
#define dllname_advapi32	L"advapi32.dll"
#define dllname_user32		L"user32.dll"
#define dllname_ws_32		L"ws2_32.dll"
#define dllname_urlmon		L"urlmon.dll"
#define dllname_wininet		L"wininet.dll"
#define dllname_netapi32	L"netapi32.dll"
#define dllname_mpr			L"mpr.dll"
#define dllname_psapi		L"psapi.dll"
#define dllname_rasapi32	L"rasapi32.dll"
#define dllname_gdi32		L"gdi32.dll"
#define dllname_srclient	L"srclient.dll"
#define dllname_shell32		L"shell32.dll"
#define dllname_sfc_os		L"sfc_os.dll"
#define dllname_ole32		L"ole32.dll"
#define dllname_winscard    L"winscard.dll"

/* global spyhook variables */
extern SHCONTEXT shctx;

/* kernel32 own use API forwarded pointers */
extern POutputDebugStringA pOutputDebugStringA;

/* own use API forwarded pointers */
extern PNtAllocateVirtualMemory			pNtAllocateVirtualMemory;
extern PNtOpenProcess					pNtOpenProcess;
extern PNtQuerySystemInformation	    pNtQuerySystemInformation;
extern PNtReadVirtualMemory				pNtReadVirtualMemory;
extern PNtQueryInformationProcess		pNtQueryInformationProcess;
extern PGetFinalPathNameByHandleW		pGetFinalPathNameByHandleW;
extern PGetWindowThreadProcessId		pGetWindowThreadProcessId;

#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* _SHGLOBAL_ */