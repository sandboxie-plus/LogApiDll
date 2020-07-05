/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	ntdll_hook.c

Abstract:

	NT DLL hook implementation.

	Last change 25.02.13

--*/

#include "..\global.h"
#include "ntdll_hook.h"

#define PRIVILEGE_COUNT 36

WCHAR *pwszPrivileges[PRIVILEGE_COUNT] = {
	L"InvalidPrivilege1", //0
	L"InvalidPrivilege2", //1
	L"SeCreateTokenPrivilege", //2
	L"SeAssignPrimaryTokenPrivilege",//3
	L"SeLockMemoryPrivilege",//4
	L"SeIncreaseQuotaPrivilege",//5
	L"SeMachineAccountPrivilege",//6
	L"SeTcbPrivilege",//7
	L"SeSecurityPrivilege",//8
	L"SeTakeOwnershipPrivilege",//9
	L"SeLoadDriverPrivilege",//10
	L"SeSystemProfilePrivilege",//11
	L"SeSystemtimePrivilege",//12
	L"SeProfileSingleProcessPrivilege",//13
	L"SeIncreaseBasePriorityPrivilege",//14
	L"SeCreatePagefilePrivilege",//15
	L"SeCreatePermanentPrivilege",//16
	L"SeBackupPrivilege",//17
	L"SeRestorePrivilege",//18
	L"SeShutdownPrivilege",//19
	L"SeDebugPrivilege",//20
	L"SeAuditPrivilege",//21
	L"SeSystemEnvironmentPrivilege",//22
	L"SeChangeNotifyPrivilege",//23
	L"SeRemoteShutdownPrivilege",//24
	L"SeUndockPrivilege",//25
	L"SeSyncAgentPrivilege",//26
	L"SeEnableDelegationPrivilege",//27
	L"SeManageVolumePrivilege",//28
	L"SeImpersonatePrivilege",//29
	L"SeCreateGlobalPrivilege",//30
	L"SeTrustedCredmanAccessPrivilege",//31
	L"SeReLabelPrivilege",//32
	L"SeCreateSymbolicLinkPrivilege",//33
	L"SeTimeZonePrivilege",//34
	L"SeUnsolicitedInputPrivilege"//35
};

PNtSetInformationThread pNtSetInformationThread = NULL;
PNtLoadDriver pNtLoadDriver = NULL;
PNtTerminateProcess pNtTerminateProcess = NULL;
PNtWriteVirtualMemory pNtWriteVirtualMemory = NULL;
PNtResumeThread pNtResumeThread = NULL;
PNtSuspendThread pNtSuspendThread = NULL;
PNtQueueApcThread pNtQueueApcThread = NULL;
PNtDelayExecution pNtDelayExecution = NULL;
PNtQueryVirtualMemory pNtQueryVirtualMemory = NULL;
PNtSetInformationProcess pNtSetInformationProcess = NULL;
PNtAdjustPrivilegesToken pNtAdjustPrivilegesToken = NULL;
PNtOpenProcessToken pNtOpenProcessToken = NULL;
PNtOpenProcessTokenEx pNtOpenProcessTokenEx = NULL;
PNtDeviceIoControlFile pNtDeviceIoControlFile = NULL;
PNtSetEaFile pNtSetEaFile = NULL;
PNtCreateFile pNtCreateFile = NULL;

PLdrFindEntryForAddress pLdrFindEntryForAddress = NULL;

NTSTATUS NTAPI NtSetInformationThreadHook(
	HANDLE ThreadHandle, 
	THREADINFOCLASS ThreadInformationClass, 
	PVOID ThreadInformation, 
	ULONG ThreadInformationLength
	)
{
	NTSTATUS Status;
	WCHAR tBuff[LOGBUFFERSIZESMALL];
	
	Status = pNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
	switch ( ThreadInformationClass ) {
	case ThreadHideFromDebugger:		
		_strcpyW(tBuff, L"NtSetInformationThread(ThreadHideFromDebugger)");
		PushToLogW(tBuff, LOGBUFFERSIZESMALL, LOG_NORMAL);	
		break;
	default:
		break;
	}
	return Status;
}

NTSTATUS NTAPI NtLoadDriverHook(
	PUNICODE_STRING DriverServiceName
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZE];
	
	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pNtLoadDriver(DriverServiceName);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"NtLoadDriver(");

	//put driverservicename
	if ( ARGUMENT_PRESENT(DriverServiceName) ) {
		__try {
			if ( DriverServiceName->Buffer != NULL ) {
				_strncpyW(_strendW(tBuff), MAX_PATH, DriverServiceName->Buffer, MAX_PATH);
			} else {
				_strcatW(tBuff, NullStrW);
			}
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatW(tBuff, NTDLL_EXCEPTION);
			utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		}
	} else {
		_strcatW(tBuff, NullStrW);
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);	

	if ( Tls ) Tls->ourcall = FALSE;
	return pNtLoadDriver(DriverServiceName);
}

NTSTATUS NTAPI NtTerminateProcessHook(
	HANDLE ProcessHandle, 
	NTSTATUS ExitStatus
	)
{
	PTLS Tls;
	DWORD dwProcessId;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pNtTerminateProcess(ProcessHandle, ExitStatus);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	if ( ProcessHandle == NULL ) {	

		dwProcessId = shctx.dwCurrentProcessId;
		_strcpyW(tBuff, L"DumpProcess(");
		ultostrW(dwProcessId, _strendW(tBuff));
		_strcatW(tBuff, CloseBracketW);
		PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL); //"DumpProcess(ProcessId)"	

	} else {

		//put prolog
		_strcpyW(tBuff, L"TerminateProcess(");

		if ( ProcessHandle == NtCurrentProcess() ) {
			_strcatW(tBuff, CloseBracketW);
			PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL); //"TerminateProcess()"
		} else {
		
			dwProcessId = 0;		
			if (!QueryProcessName(ProcessHandle, _strendW(tBuff), MAX_PATH * 2, &dwProcessId)) {
				//cannot be query name - put id instead
				if (!LogSystemProcess(dwProcessId, _strendW(tBuff))) {
					ultostrW((ULONG_PTR)dwProcessId, _strendW(tBuff));
				}
			}
			_strcatW(tBuff, CloseBracketW);
			PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL); //"TerminateProcess(Name)"

			_strcpyW(tBuff, L"DumpProcess(");
			ultostrW(dwProcessId, _strendW(tBuff));
			_strcatW(tBuff, CloseBracketW);
			PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL); //"DumpProcess(ProcessId)"
		}  
	}
	if ( Tls ) Tls->ourcall = FALSE;
	return pNtTerminateProcess(ProcessHandle, ExitStatus);
}

NTSTATUS NTAPI NtAllocateVirtualMemoryHook(
	HANDLE ProcessHandle, 
	PVOID *BaseAddress, 
	ULONG_PTR ZeroBits, 
	PSIZE_T RegionSize, 
	ULONG AllocationType, 
	ULONG Protect
	)
{
	PTLS Tls;
	SIZE_T Size;
	DWORD dwProcessId;
	WCHAR tBuff[LOGBUFFERSIZELONG];
	
	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;	
		if ( Tls->ourcall ) {		
			return pNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
		} 
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));
	
	//put prolog
	_strcpyW(tBuff, L"VirtualAllocEx(");

	//put filename 
	dwProcessId = 0;
	if (!QueryProcessName(ProcessHandle, _strendW(tBuff), MAX_PATH * 2, &dwProcessId)) {
		if (!LogSystemProcess(dwProcessId, _strendW(tBuff))) {
			ultostrW((ULONG_PTR)dwProcessId, _strendW(tBuff));
		}
	}
	_strcatW(tBuff, CommaW);
	
	//put allocationtype
	if ( AllocationType & MEM_COMMIT ) _strcatW(tBuff, L" MEM_COMMIT");
	if ( AllocationType & MEM_RESERVE ) _strcatW(tBuff, L" MEM_RESERVE");
	if ( AllocationType & MEM_PHYSICAL ) _strcatW(tBuff, L" MEM_PHYSICAL");
	if ( AllocationType & MEM_RESET ) _strcatW(tBuff, L" MEM_RESET");
	if ( AllocationType & MEM_TOP_DOWN ) _strcatW(tBuff, L" MEM_TOP_DOWN");
	if ( AllocationType & MEM_LARGE_PAGES ) _strcatW(tBuff, L" MEM_LARGE_PAGES");
	if ( AllocationType & MEM_WRITE_WATCH ) _strcatW(tBuff, L" MEM_WRITE_WATCH");
	_strcatW(tBuff, CommaW);

	//put protect
	if ( Protect & PAGE_NOACCESS ) _strcatW(tBuff, L" PAGE_NOACCESS");
	if ( Protect & PAGE_EXECUTE ) _strcatW(tBuff, L" PAGE_EXECUTE");
	if ( Protect & PAGE_READONLY ) _strcatW(tBuff, L" PAGE_READONLY");
	if ( Protect & PAGE_READWRITE ) _strcatW(tBuff, L" PAGE_READWRITE");
	if ( Protect & PAGE_NOCACHE)  _strcatW(tBuff, L" PAGE_NOCACHE");
	if ( Protect & PAGE_EXECUTE_READWRITE ) _strcatW(tBuff, L" PAGE_EXECUTE_READWRITE");
	if ( Protect & PAGE_GUARD ) _strcatW(tBuff, L" PAGE_GUARD");
	if ( Protect & PAGE_WRITECOMBINE ) _strcatW(tBuff, L" PAGE_WRITECOMBINE");
	
	//put regionsize
	__try {
		if ( RegionSize != NULL ) {
			_strcatW(tBuff, L", RegionSize=0x");
			Size = *RegionSize;
			utohexW((ULONG_PTR)Size, _strendW(tBuff));
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatW(tBuff, NTDLL_EXCEPTION);
		utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
	}
	
	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS NTAPI NtWriteVirtualMemoryHook(
	HANDLE ProcessHandle, 
	PVOID BaseAddress, 
	VOID *Buffer, 
	SIZE_T BufferSize, 
	PSIZE_T NumberOfBytesWritten
	)
{
	PTLS Tls;
	DWORD dwProcessId;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"WriteProcessMemory(");

	//put filename
	dwProcessId = 0;
	if (!QueryProcessName(ProcessHandle, _strendW(tBuff), MAX_PATH * 2, &dwProcessId)) {
		if (!LogSystemProcess(dwProcessId, _strendW(tBuff))) {
			ultostrW((ULONG_PTR)dwProcessId, _strendW(tBuff));
		}
	}
	_strcatW(tBuff, CommaExW);

	//put address
	_strcatW(tBuff, L"BaseAddress=0x");
	utohexW((ULONG_PTR)BaseAddress, _strendW(tBuff));

	//put size
	_strcatW(tBuff, CommaExW);
	_strcatW(tBuff, L"BufferSize=0x");
	utohexW((ULONG_PTR)BufferSize, _strendW(tBuff));

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

NTSTATUS NTAPI NtReadVirtualMemoryHook( 
	HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead
    )
{
	PTLS Tls;
	DWORD dwProcessId;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"ReadProcessMemory(");

	//put filename
	dwProcessId = 0;
	if (!QueryProcessName(ProcessHandle, _strendW(tBuff), MAX_PATH * 2, &dwProcessId)) {
		if (!LogSystemProcess(dwProcessId, _strendW(tBuff))) {
			ultostrW((ULONG_PTR)dwProcessId, _strendW(tBuff));
		}
	}
	_strcatW(tBuff, CommaExW);

	//put address
	_strcatW(tBuff, L"BaseAddress=0x");
	utohexW((ULONG_PTR)BaseAddress, _strendW(tBuff));

	//put size
	_strcatW(tBuff, CommaExW);
	_strcatW(tBuff, L"BufferSize=0x");
	utohexW((ULONG_PTR)BufferSize, _strendW(tBuff));

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
}

NTSTATUS NTAPI NtResumeThreadHook(
	HANDLE ThreadHandle, 
	PULONG PreviousSuspendCount
	)
{
	PTLS Tls;
	DWORD dwThreadId;
	WCHAR tBuff[LOGBUFFERSIZESMALL];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pNtResumeThread(ThreadHandle, PreviousSuspendCount);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	dwThreadId = GetThreadIdByHandle(ThreadHandle);

	//put prolog
	_strcpyW(tBuff, L"ResumeThread(");

	//put thread id
	ultostrW(dwThreadId, _strendW(tBuff));

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZESMALL, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNtResumeThread(ThreadHandle, PreviousSuspendCount);
}

NTSTATUS NTAPI NtSuspendThreadHook(
	HANDLE ThreadHandle, 
	PULONG PreviousSuspendCount
	)
{
	PTLS Tls;
	DWORD dwThreadId;
	WCHAR tBuff[LOGBUFFERSIZESMALL];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pNtSuspendThread(ThreadHandle, PreviousSuspendCount);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	dwThreadId = GetThreadIdByHandle(ThreadHandle);

	//put prolog
	_strcpyW(tBuff, L"SuspendThread(");

	//put thread id
	ultostrW(dwThreadId, _strendW(tBuff));

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZESMALL, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNtSuspendThread(ThreadHandle, PreviousSuspendCount);
}

NTSTATUS NTAPI NtQueueApcThreadHook(
	HANDLE ThreadHandle, 
	PPS_APC_ROUTINE ApcRoutine, 
	PVOID ApcArgument1, 
	PVOID ApcArgument2, 
	PVOID ApcArgument3
	)
{
	PTLS Tls;
	DWORD dwThreadId;
	WCHAR tBuff[LOGBUFFERSIZESMALL];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pNtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	dwThreadId = GetThreadIdByHandle(ThreadHandle);

	//put prolog
	_strcpyW(tBuff, L"QueueUserAPC(");

	//put thread id
	ultostrW(dwThreadId, _strendW(tBuff));

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZESMALL, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
}

NTSTATUS NTAPI NtOpenProcessHook(    
	PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
	)
{
	PTLS Tls;
	NTSTATUS Status;
	HANDLE ProcessId;
	BOOL bFound;
	WCHAR tBuff[LOGBUFFERSIZE];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"OpenProcess(");

	__try {
		ProcessId = ClientId->UniqueProcess;
		_WARNING_OFF(4305);
		bFound = LogSystemProcess((DWORD)ProcessId, _strendW(tBuff));
		_WARNING_ON(4305);
		//put process name
		if ( bFound == FALSE ) {
			Status = QueryProcessNameByProcessId(ProcessId, _strendW(tBuff), MAX_PATH * 2);
			if (!NT_SUCCESS(Status)) {
				//put process id on fail
				_ultostrW((ULONG_PTR)ProcessId, _strendW(tBuff));
			}
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatW(tBuff, NTDLL_EXCEPTION);
		utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
	}

	//put access mask
	if ( DesiredAccess == shctx.ProcessAllAccess ) {
		_strcatW(tBuff, L", PROCESS_ALL_ACCESS");
	} else {
		if ( DesiredAccess & PROCESS_QUERY_INFORMATION ) _strcatW(tBuff, L", PROCESS_QUERY_INFORMATION");
		if ( DesiredAccess & PROCESS_TERMINATE ) _strcatW(tBuff, L", PROCESS_TERMINATE");
		if ( DesiredAccess & PROCESS_CREATE_THREAD ) _strcatW(tBuff, L", PROCESS_CREATE_THREAD");
		if ( DesiredAccess & PROCESS_SET_SESSIONID ) _strcatW(tBuff, L", PROCESS_SET_SESSIONID");
		if ( DesiredAccess & PROCESS_VM_OPERATION ) _strcatW(tBuff, L", PROCESS_VM_OPERATION");
		if ( DesiredAccess & PROCESS_VM_READ ) _strcatW(tBuff, L", PROCESS_VM_READ");
		if ( DesiredAccess & PROCESS_VM_WRITE ) _strcatW(tBuff, L", PROCESS_VM_WRITE");
		if ( DesiredAccess & PROCESS_DUP_HANDLE ) _strcatW(tBuff, L", PROCESS_DUP_HANDLE");
		if ( DesiredAccess & PROCESS_CREATE_PROCESS ) _strcatW(tBuff, L", PROCESS_CREATE_PROCESS");
		if ( DesiredAccess & PROCESS_SET_QUOTA ) _strcatW(tBuff, L", PROCESS_SET_QUOTA");
		if ( DesiredAccess & PROCESS_SET_INFORMATION ) _strcatW(tBuff, L", PROCESS_SET_INFORMATION");
		//if ( DesiredAccess & PROCESS_SET_PORT ) _strcatW(tBuff, L", PROCESS_SET_PORT");
		if ( DesiredAccess & PROCESS_SUSPEND_RESUME ) _strcatW(tBuff, L", PROCESS_SUSPEND_RESUME");
		if ( DesiredAccess & PROCESS_QUERY_LIMITED_INFORMATION ) _strcatW(tBuff, L", PROCESS_QUERY_LIMITED_INFORMATION");
		if ( DesiredAccess & SYNCHRONIZE ) _strcatW(tBuff, L", SYNCHRONIZE");
		if ( DesiredAccess & MAXIMUM_ALLOWED ) _strcatW(tBuff, L", MAXIMUM_ALLOWED");
		if ( DesiredAccess & DELETE) _strcatW(tBuff, L", DELETE");
		if ( DesiredAccess & READ_CONTROL) _strcatW(tBuff, L", READ_CONTROL");
		if ( DesiredAccess & WRITE_DAC) _strcatW(tBuff, L", WRITE_DAC");
		if ( DesiredAccess & WRITE_OWNER) _strcatW(tBuff, L", WRITE_OWNER");
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;

	//disallow access to protected list
	if ( IsProtectedProcess(ClientId) == TRUE ) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return STATUS_INVALID_CID;
	} else {
		return pNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	}
}

VOID LogSystemInfoClass(
	 SYSTEM_INFORMATION_CLASS SystemInformationClass,
	 LPWSTR Buffer
	 )
{
	switch ( SystemInformationClass ) {

	case SystemBasicInformation:
		_strcatW(Buffer, L"SystemBasicInformation");
		break;
	case SystemProcessorInformation:
		_strcatW(Buffer, L"SystemProcessorInformation");
		break;
	case SystemPerformanceInformation:
		_strcatW(Buffer, L"SystemPerformanceInformation");
		break;
	case SystemTimeOfDayInformation:
		_strcatW(Buffer, L"SystemTimeOfDayInformation");
		break;
	case SystemPathInformation:
		_strcatW(Buffer, L"SystemPathInformation");
		break;
	case SystemProcessInformation:
		_strcatW(Buffer, L"SystemProcessInformation");
		break;
	case SystemCallCountInformation:
		_strcatW(Buffer, L"SystemCallCountInformation");
		break;
	case SystemDeviceInformation:
		_strcatW(Buffer, L"SystemDeviceInformation");
		break;
	case SystemProcessorPerformanceInformation:
		_strcatW(Buffer, L"SystemProcessorPerformanceInformation");
		break;
	case SystemFlagsInformation:
		_strcatW(Buffer, L"SystemFlagsInformation");
		break;
	case SystemModuleInformation:
		_strcatW(Buffer, L"SystemModuleInformation");
		break;
	case SystemLocksInformation:
		_strcatW(Buffer, L"SystemLocksInformation");
		break;
	case SystemStackTraceInformation:
		_strcatW(Buffer, L"SystemStackTraceInformation");
		break;
	case SystemPagedPoolInformation:
		_strcatW(Buffer, L"SystemPagedPoolInformation");
		break;
	case SystemNonPagedPoolInformation:
		_strcatW(Buffer, L"SystemNonPagedPoolInformation");
		break;
	case SystemHandleInformation:
		_strcatW(Buffer, L"SystemHandleInformation");
		break;
	case SystemObjectInformation:
		_strcatW(Buffer, L"SystemObjectInformation");
		break;
	case SystemPageFileInformation:
		_strcatW(Buffer, L"SystemPageFileInformation");
		break;
	case SystemVdmInstemulInformation:
		_strcatW(Buffer, L"SystemVdmInstemulInformation");
		break;
	case SystemVdmBopInformation:
		_strcatW(Buffer, L"SystemVdmBopInformation");
		break;
	case SystemFileCacheInformation:
		_strcatW(Buffer, L"SystemFileCacheInformation");
		break;
	case SystemPoolTagInformation:
		_strcatW(Buffer, L"SystemPoolTagInformation");
		break;
	case SystemInterruptInformation:
		_strcatW(Buffer, L"SystemInterruptInformation");
		break;
	case SystemDpcBehaviorInformation:
		_strcatW(Buffer, L"SystemDpcBehaviorInformation");
		break;
	case SystemFullMemoryInformation:
		_strcatW(Buffer, L"SystemFullMemoryInformation");
		break;
	case SystemLoadGdiDriverInformation:
		_strcatW(Buffer, L"SystemLoadGdiDriverInformation");
		break;
	case SystemUnloadGdiDriverInformation:
		_strcatW(Buffer, L"SystemUnloadGdiDriverInformation");
		break;
	case SystemTimeAdjustmentInformation:
		_strcatW(Buffer, L"SystemTimeAdjustmentInformation");
		break;
	case SystemSummaryMemoryInformation:
		_strcatW(Buffer, L"SystemSummaryMemoryInformation");
		break;
	case SystemMirrorMemoryInformation:
		_strcatW(Buffer, L"SystemMirrorMemoryInformation");
		break;
	case SystemPerformanceTraceInformation:
		_strcatW(Buffer, L"SystemPerformanceTraceInformation");
		break;
	case SystemExceptionInformation:
		_strcatW(Buffer, L"SystemExceptionInformation");
		break;
	case SystemCrashDumpStateInformation:
		_strcatW(Buffer, L"SystemCrashDumpStateInformation");
		break;
	case SystemKernelDebuggerInformation:
		_strcatW(Buffer, L"SystemKernelDebuggerInformation");
		break;
	case SystemContextSwitchInformation:
		_strcatW(Buffer, L"SystemContextSwitchInformation");
		break;
	case SystemRegistryQuotaInformation:
		_strcatW(Buffer, L"SystemRegistryQuotaInformation");
		break;
	case SystemExtendServiceTableInformation:
		_strcatW(Buffer, L"SystemExtendServiceTableInformation");
		break;
	case SystemPrioritySeperation:
		_strcatW(Buffer, L"SystemPrioritySeperation");
		break;
	case SystemVerifierAddDriverInformation:
		_strcatW(Buffer, L"SystemVerifierAddDriverInformation");
		break;
	case SystemVerifierRemoveDriverInformation:
		_strcatW(Buffer, L"SystemVerifierRemoveDriverInformation");
		break;
	case SystemProcessorIdleInformation:
		_strcatW(Buffer, L"SystemProcessorIdleInformation");
		break;
	case SystemLegacyDriverInformation:
		_strcatW(Buffer, L"SystemLegacyDriverInformation");
		break;
	case SystemCurrentTimeZoneInformation:
		_strcatW(Buffer, L"SystemCurrentTimeZoneInformation");
		break;
	case SystemLookasideInformation:
		_strcatW(Buffer, L"SystemLookasideInformation");
		break;
	case SystemTimeSlipNotification:
		_strcatW(Buffer, L"SystemTimeSlipNotification");
		break;
	case SystemSessionCreate:
		_strcatW(Buffer, L"SystemSessionCreate");
		break;
	case SystemSessionDetach:
		_strcatW(Buffer, L"SystemSessionDetach");
		break;
	case SystemSessionInformation:
		_strcatW(Buffer, L"SystemSessionInformation");
		break;
	case SystemRangeStartInformation:
		_strcatW(Buffer, L"SystemRangeStartInformation");
		break;
	case SystemVerifierInformation:
		_strcatW(Buffer, L"SystemVerifierInformation");
		break;
	case SystemVerifierThunkExtend:
		_strcatW(Buffer, L"SystemVerifierThunkExtend");
		break;
	case SystemSessionProcessInformation:
		_strcatW(Buffer, L"SystemSessionProcessInformation");
		break;
	case SystemLoadGdiDriverInSystemSpace:
		_strcatW(Buffer, L"SystemLoadGdiDriverInSystemSpace");
		break;
	case SystemNumaProcessorMap:
		_strcatW(Buffer, L"SystemNumaProcessorMap");
		break;
	case SystemPrefetcherInformation:
		_strcatW(Buffer, L"SystemPrefetcherInformation");
		break;
	case SystemExtendedProcessInformation:
		_strcatW(Buffer, L"SystemExtendedProcessInformation");
		break;
	case SystemRecommendedSharedDataAlignment:
		_strcatW(Buffer, L"SystemRecommendedSharedDataAlignment");
		break;
	case SystemComPlusPackage:
		_strcatW(Buffer, L"SystemComPlusPackage");
		break;
	case SystemNumaAvailableMemory:
		_strcatW(Buffer, L"SystemNumaAvailableMemory");
		break;
	case SystemProcessorPowerInformation:
		_strcatW(Buffer, L"SystemProcessorPowerInformation");
		break;
	case SystemEmulationBasicInformation:
		_strcatW(Buffer, L"SystemEmulationBasicInformation");
		break;
	case SystemEmulationProcessorInformation:
		_strcatW(Buffer, L"SystemEmulationProcessorInformation");
		break;
	case SystemExtendedHandleInformation:
		_strcatW(Buffer, L"SystemExtendedHandleInformation");
		break;
	case SystemLostDelayedWriteInformation:
		_strcatW(Buffer, L"SystemLostDelayedWriteInformation");
		break;
	case SystemBigPoolInformation:
		_strcatW(Buffer, L"SystemBigPoolInformation");
		break;
	case SystemSessionPoolTagInformation:
		_strcatW(Buffer, L"SystemSessionPoolTagInformation");
		break;
	case SystemSessionMappedViewInformation:
		_strcatW(Buffer, L"SystemSessionMappedViewInformation");
		break;
	case SystemHotpatchInformation:
		_strcatW(Buffer, L"SystemHotpatchInformation");
		break;
	case SystemObjectSecurityMode:
		_strcatW(Buffer, L"SystemObjectSecurityMode");
		break;
	case SystemWatchdogTimerHandler:
		_strcatW(Buffer, L"SystemWatchdogTimerHandler");
		break;
	case SystemWatchdogTimerInformation:
		_strcatW(Buffer, L"SystemWatchdogTimerInformation");
		break;
	case SystemLogicalProcessorInformation:
		_strcatW(Buffer, L"SystemLogicalProcessorInformation");
		break;
	case SystemWow64SharedInformation:
		_strcatW(Buffer, L"SystemWow64SharedInformation");
		break;
	case SystemRegisterFirmwareTableInformationHandler:
		_strcatW(Buffer, L"SystemRegisterFirmwareTableInformationHandler");
		break;
	case SystemFirmwareTableInformation:
		_strcatW(Buffer, L"SystemFirmwareTableInformation");
		break;
	case SystemModuleInformationEx:
		_strcatW(Buffer, L"SystemModuleInformationEx");
		break;
	case SystemVerifierTriageInformation:
		_strcatW(Buffer, L"SystemVerifierTriageInformation");
		break;
	case SystemSuperfetchInformation:
		_strcatW(Buffer, L"SystemSuperfetchInformation");
		break;
	case SystemMemoryListInformation:
		_strcatW(Buffer, L"SystemMemoryListInformation");
		break;
	case SystemFileCacheInformationEx:
		_strcatW(Buffer, L"SystemFileCacheInformationEx");
		break;
	case SystemThreadPriorityClientIdInformation:
		_strcatW(Buffer, L"SystemThreadPriorityClientIdInformation");
		break;
	case SystemProcessorIdleCycleTimeInformation:
		_strcatW(Buffer, L"SystemProcessorIdleCycleTimeInformation");
		break;
	case SystemVerifierCancellationInformation:
		_strcatW(Buffer, L"SystemVerifierCancellationInformation");
		break;
	case SystemProcessorPowerInformationEx:
		_strcatW(Buffer, L"SystemProcessorPowerInformationEx");
		break;
	case SystemRefTraceInformation:
		_strcatW(Buffer, L"SystemRefTraceInformation");
		break;
	case SystemSpecialPoolInformation:
		_strcatW(Buffer, L"SystemSpecialPoolInformation");
		break;
	case SystemProcessIdInformation:
		_strcatW(Buffer, L"SystemProcessIdInformation");
		break;
	case SystemErrorPortInformation:
		_strcatW(Buffer, L"SystemErrorPortInformation");
		break;
	case SystemBootEnvironmentInformation:
		_strcatW(Buffer, L"SystemBootEnvironmentInformation");
		break;
	case SystemHypervisorInformation:
		_strcatW(Buffer, L"SystemHypervisorInformation");
		break;
	case SystemVerifierInformationEx:
		_strcatW(Buffer, L"SystemVerifierInformationEx");
		break;
	case SystemTimeZoneInformation:
		_strcatW(Buffer, L"SystemTimeZoneInformation");
		break;
	case SystemImageFileExecutionOptionsInformation:
		_strcatW(Buffer, L"SystemImageFileExecutionOptionsInformation");
		break;
	case SystemCoverageInformation:
		_strcatW(Buffer, L"SystemCoverageInformation");
		break;
	case SystemPrefetchPatchInformation:
		_strcatW(Buffer, L"SystemPrefetchPatchInformation");
		break;
	case SystemVerifierFaultsInformation:
		_strcatW(Buffer, L"SystemVerifierFaultsInformation");
		break;
	case SystemSystemPartitionInformation:
		_strcatW(Buffer, L"SystemSystemPartitionInformation");
		break;
	case SystemSystemDiskInformation:
		_strcatW(Buffer, L"SystemSystemDiskInformation");
		break;
	case SystemProcessorPerformanceDistribution:
		_strcatW(Buffer, L"SystemProcessorPerformanceDistribution");
		break;
	case SystemNumaProximityNodeInformation:
		_strcatW(Buffer, L"SystemNumaProximityNodeInformation");
		break;
	case SystemDynamicTimeZoneInformation:
		_strcatW(Buffer, L"SystemDynamicTimeZoneInformation");
		break;
	case SystemCodeIntegrityInformation:
		_strcatW(Buffer, L"SystemCodeIntegrityInformation");
		break;
	case SystemProcessorMicrocodeUpdateInformation:
		_strcatW(Buffer, L"SystemProcessorMicrocodeUpdateInformation");
		break;
	case SystemProcessorBrandString:
		_strcatW(Buffer, L"SystemProcessorBrandString");
		break;
	case SystemVirtualAddressInformation:
		_strcatW(Buffer, L"SystemVirtualAddressInformation");
		break;
	default:
		ultostrW(SystemInformationClass, _strendW(Buffer));
		break;
	}
}

BOOL HideProtectedProcesses(
	PSYSTEM_PROCESSES_INFORMATION Entry
	)
{
	PSYSTEM_PROCESSES_INFORMATION pNext, pCurrent;
	PWSTR lpImageName;

	__try {
		pCurrent = NULL;
		pNext = Entry;
		do {
			pCurrent = pNext;
			pNext = (PSYSTEM_PROCESSES_INFORMATION)(((LPBYTE)pCurrent) + pCurrent->NextEntryDelta);

			/* fake parent id if explorer pid available */
			_WARNING_OFF(4305);
			_WARNING_OFF(4306);
			if ( (DWORD)pNext->UniqueProcessId == shctx.dwCurrentProcessId) {			
				if (shctx.dwExplorerProcessId != 0) {
					if ( IsProcessRunning(pNext->InheritedFromUniqueProcessId) == FALSE) {
						pNext->InheritedFromUniqueProcessId = (HANDLE)shctx.dwExplorerProcessId;
					}
				}
			}
			_WARNING_ON(4305);
			_WARNING_ON(4306);

			/* remove protected process from result */
			lpImageName = pNext->ImageName.Buffer;		 
			if ( lpImageName != NULL ) {				
				if ( IsSandboxieProcessW(lpImageName) ) {
					if ( pNext->NextEntryDelta == 0 )
						pCurrent->NextEntryDelta = 0;
					else
						pCurrent->NextEntryDelta += pNext->NextEntryDelta;
					pNext = pCurrent;
				}
			}
		} while ( pCurrent->NextEntryDelta != 0 );
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
	return TRUE;
}

NTSTATUS NTAPI NtQuerySystemInformationHook(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    )
{
	PTLS Tls;
	NTSTATUS Status;
	WCHAR tBuff[LOGBUFFERSIZE];
	
	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"QuerySystemInformation(");
	LogSystemInfoClass(SystemInformationClass, _strendW(tBuff));

	Status = pNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
#ifndef _DEBUG
	if (NT_SUCCESS(Status)) {
		switch ( SystemInformationClass ) {
		case SystemProcessInformation:
			HideProtectedProcesses((PSYSTEM_PROCESSES_INFORMATION)SystemInformation);
			break;
		default:
			break;
		}
	}
#endif

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

	return Status;
}

NTSTATUS NTAPI NtDelayExecutionHook(   //Sleep, SleepEx
	BOOLEAN Alertable, 
	PLARGE_INTEGER DelayInterval
	)
{
	PTLS Tls;
	DWORD dwMilliseconds;
	WCHAR tBuff[LOGBUFFERSIZESMALL];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pNtDelayExecution(Alertable, DelayInterval);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"Sleep(");
	
	__try {
		//put seconds to log
		if ( ARGUMENT_PRESENT(DelayInterval) ) {
			if ( DelayInterval->QuadPart == 0x8000000000000000 ) {
				_strcatW(tBuff, L"INFINITE");
			} else {
				dwMilliseconds = (DWORD)(-DelayInterval->QuadPart / 10000);
				ultostrW(dwMilliseconds, _strendW(tBuff));
				//fix seconds if needed
				if ( dwMilliseconds >= 60000 ) {
					DelayInterval->QuadPart = UInt32x32To64(1000, 10000);
					DelayInterval->QuadPart *= -1;
				}
			}
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatW(tBuff, NTDLL_EXCEPTION);
		utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZESMALL, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNtDelayExecution(Alertable, DelayInterval);
}

NTSTATUS NTAPI LdrFindEntryForAddressHook(
	PVOID Address, 
	PLDR_DATA_TABLE_ENTRY *TableEntry
	)
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZESMALL];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pLdrFindEntryForAddress(Address, TableEntry);
		Tls->ourcall = TRUE;
	}

	//put prolog
	_strcpyW(tBuff, L"LdrFindEntryForAddress(0x");

	//put address
	utohexW((ULONG_PTR)Address, _strendW(tBuff));

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZESMALL, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pLdrFindEntryForAddress(Address, TableEntry);
}

BOOL IsProtectedRegion(
	PVOID BaseAddress
	)
{
	if ( IN_REGION(BaseAddress, 
		shctx.SbieDll.BaseAddress, 
		shctx.SbieDll.SizeOfImage) ) 
	{
		return TRUE;
	} 

	if ( IN_REGION(BaseAddress, 
		shctx.ThisDll.BaseAddress, 
		shctx.ThisDll.SizeOfImage) ) 
	{
		return TRUE;
	}

	return FALSE;
}

VOID LogMemoryInfoClass(
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	LPWSTR Buffer
	)
{
	switch ( MemoryInformationClass ) {
	case MemoryBasicInformation:
		_strcatW(Buffer, L"MemoryBasicInformation");
		break;
	case MemoryWorkingSetInformation:
		_strcatW(Buffer, L"MemoryWorkingSetInformation");
		break;
	case MemoryMappedFilenameInformation:
		_strcatW(Buffer, L"MemoryMappedFilenameInformation");
		break;
	case MemoryRegionInformation:
		_strcatW(Buffer, L"MemoryRegionInformation");
		break;
	case MemoryWorkingSetExInformation:
		_strcatW(Buffer, L"MemoryWorkingSetExInformation");
		break;
	default:
		break;
	}
}

NTSTATUS NTAPI NtQueryVirtualMemoryHook(
	HANDLE ProcessHandle, 
	PVOID BaseAddress, 
	MEMORY_INFORMATION_CLASS MemoryInformationClass, 
	PVOID MemoryInformation, 
	SIZE_T MemoryInformationLength,
	PSIZE_T ReturnLength
	)
{
	PTLS Tls;
#ifdef VERBOSE_BUILD
	DWORD dwProcessId;
	WCHAR tBuff[LOGBUFFERSIZELONG];
#endif
	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pNtQueryVirtualMemory(
				ProcessHandle, 
				BaseAddress, 
				MemoryInformationClass, 
				MemoryInformation, 
				MemoryInformationLength, 
				ReturnLength);
		Tls->ourcall = TRUE;
	}

	//protect sbiedll/selfdll regions
	switch ( MemoryInformationClass ) {
	case MemoryMappedFilenameInformation:
		if ( IsProtectedRegion(BaseAddress) ) {

			if ( Tls ) Tls->ourcall = FALSE;
			SetLastError(ERROR_INVALID_PARAMETER);
			return STATUS_INVALID_ADDRESS; /* psapi crash on STATUS_SUCCESS */

		}
		break;
	default:
		break;
	}

#ifdef VERBOSE_BUILD
	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"VirtualQueryEx(");

	//put filename
	dwProcessId = 0;
	if (!QueryProcessName(ProcessHandle, _strendW(tBuff), MAX_PATH * 2, &dwProcessId)) {
		if (!LogSystemProcess(dwProcessId, _strendW(tBuff))) {
			ultostrW((ULONG_PTR)dwProcessId, _strendW(tBuff));
		}
	}
	_strcatW(tBuff, CommaExW);

	//put memory class
	LogMemoryInfoClass(MemoryInformationClass, _strendW(tBuff));
	_strcatW(tBuff, CommaExW);

	//put address
	_strcatW(tBuff, L"BaseAddress=0x");
	utohexW((ULONG_PTR)BaseAddress, _strendW(tBuff));

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);
#endif

	if ( Tls ) Tls->ourcall = FALSE;
	return pNtQueryVirtualMemory(
		ProcessHandle, 
		BaseAddress, 
		MemoryInformationClass, 
		MemoryInformation, 
		MemoryInformationLength, 
		ReturnLength);
}

VOID LogProcessInformation(
	PWSTR ApiName,
	PUNICODE_STRING DynamicString,
	PWSTR Buffer,
	ULONG BufferSize,
	ULONG LogBufferSize
	)
{
	if ( ARGUMENT_PRESENT(ApiName) ) {
		_strcpyW(Buffer, ApiName);
		_strcatW(Buffer, OpenBracketW);
		if ( ARGUMENT_PRESENT(DynamicString) ) {
			if (( DynamicString->Buffer != NULL ) && ( DynamicString->Length > 0 ))
				_strncpyW(_strendW(Buffer), BufferSize, DynamicString->Buffer, LogBufferSize);
		} else {
			_strcatW(Buffer, NullStrW);
		}
		_strcatW(Buffer, CloseBracketW);
		PushToLogW(Buffer, LogBufferSize, LOG_NORMAL);
	}
}

VOID LogProcessInformationClass(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PWSTR Buffer,
	ULONG LogBufferSize
	)
{
	DWORD dwProcessId;

	//put prolog
	_strcpyW(Buffer, L"QueryProcessInformation(");

	//put filename
	dwProcessId = 0;
	if (!QueryProcessName(ProcessHandle, _strendW(Buffer), MAX_PATH * 2, &dwProcessId)) {
		if (!LogSystemProcess(dwProcessId, _strendW(Buffer))) {
			ultostrW((ULONG_PTR)dwProcessId, _strendW(Buffer));
		}
	}
	_strcatW(Buffer, CommaExW);

	//put info class name
	switch ( ProcessInformationClass ) {

	case ProcessBasicInformation:
		_strcatW(Buffer, L"ProcessBasicInformation");
		break;
	case ProcessQuotaLimits:
		_strcatW(Buffer, L"ProcessQuotaLimits");
		break;
	case ProcessIoCounters:
		_strcatW(Buffer, L"ProcessIoCounters");
		break;
	case ProcessVmCounters:
		_strcatW(Buffer, L"ProcessVmCounters");
		break;
	case ProcessTimes:
		_strcatW(Buffer, L"ProcessTimes");
		break;
	case ProcessBasePriority:
		_strcatW(Buffer, L"ProcessBasePriority");
		break;
	case ProcessRaisePriority:
		_strcatW(Buffer, L"ProcessRaisePriority");
		break;
	case ProcessExceptionPort:
		_strcatW(Buffer, L"ProcessExceptionPort");
		break;
	case ProcessAccessToken:
		_strcatW(Buffer, L"ProcessAccessToken");
		break;
	case ProcessLdtInformation:
		_strcatW(Buffer, L"ProcessLdtInformation");
		break;	
	case ProcessLdtSize:
		_strcatW(Buffer, L"ProcessLdtSize");
		break;
	case ProcessDefaultHardErrorMode:
		_strcatW(Buffer, L"ProcessDefaultHardErrorMode");
		break;
	case ProcessIoPortHandlers:
		_strcatW(Buffer, L"ProcessAccessToken");
		break;
	case ProcessPooledUsageAndLimits:
		_strcatW(Buffer, L"ProcessPooledUsageAndLimits");
		break;
	case ProcessWorkingSetWatch:
		_strcatW(Buffer, L"ProcessWorkingSetWatch");
		break;
	case ProcessUserModeIOPL:
		_strcatW(Buffer, L"ProcessUserModeIOPL");
		break;
	case ProcessEnableAlignmentFaultFixup:
		_strcatW(Buffer, L"ProcessEnableAlignmentFaultFixup");
		break;
	case ProcessPriorityClass:
		_strcatW(Buffer, L"ProcessPriorityClass");
		break;
	case ProcessWx86Information:
		_strcatW(Buffer, L"ProcessWx86Information");
		break;
	case ProcessHandleCount:
		_strcatW(Buffer, L"ProcessHandleCount");
		break;
	case ProcessAffinityMask:
		_strcatW(Buffer, L"ProcessAffinityMask");
		break;
	case ProcessPriorityBoost:
		_strcatW(Buffer, L"ProcessPriorityBoost");
		break;
	case ProcessDeviceMap:
		_strcatW(Buffer, L"ProcessDeviceMap");
		break;
	case ProcessSessionInformation:
		_strcatW(Buffer, L"ProcessSessionInformation");
		break;
	case ProcessForegroundInformation:
		_strcatW(Buffer, L"ProcessForegroundInformation");
		break;
	case ProcessWow64Information:
		_strcatW(Buffer, L"ProcessWow64Information");
		break;
	case ProcessLUIDDeviceMapsEnabled:
		_strcatW(Buffer, L"ProcessLUIDDeviceMapsEnabled");
		break;
	case ProcessBreakOnTermination:
		_strcatW(Buffer, L"ProcessBreakOnTermination");
		break;
	case ProcessHandleTracing:
		_strcatW(Buffer, L"ProcessHandleTracing");
		break;
	case ProcessIoPriority:
		_strcatW(Buffer, L"ProcessIoPriority");
		break;
	case ProcessTlsInformation:
		_strcatW(Buffer, L"ProcessTlsInformation");
		break;
	case ProcessCookie:
		_strcatW(Buffer, L"ProcessCookie");
		break;
	case ProcessImageInformation:
		_strcatW(Buffer, L"ProcessImageInformation");
		break;
	case ProcessCycleTime:
		_strcatW(Buffer, L"ProcessCycleTime");
		break;
	case ProcessPagePriority:
		_strcatW(Buffer, L"ProcessPagePriority");
		break;
	case ProcessInstrumentationCallback:
		_strcatW(Buffer, L"ProcessInstrumentationCallback");
		break;
	case ProcessThreadStackAllocation:
		_strcatW(Buffer, L"ProcessThreadStackAllocation");
		break;
	case ProcessWorkingSetWatchEx:
		_strcatW(Buffer, L"ProcessWorkingSetWatchEx");
		break;
	case ProcessImageFileMapping:
		_strcatW(Buffer, L"ProcessImageFileMapping");
		break;
	case ProcessAffinityUpdateMode:
		_strcatW(Buffer, L"ProcessAffinityUpdateMode");
		break;
	case ProcessMemoryAllocationMode:
		_strcatW(Buffer, L"ProcessMemoryAllocationMode");
		break;
	case ProcessGroupInformation:
		_strcatW(Buffer, L"ProcessGroupInformation");
		break;
	case ProcessTokenVirtualizationEnabled:
		_strcatW(Buffer, L"ProcessTokenVirtualizationEnabled");
		break;
	case ProcessConsoleHostProcess:
		_strcatW(Buffer, L"ProcessConsoleHostProcess");
		break;
	case ProcessWindowInformation:
		_strcatW(Buffer, L"ProcessWindowInformation");
		break;
	default:
		ultostrW(ProcessInformationClass, _strendW(Buffer));
		break;
	}

	//put epilog and log
	_strcatW(Buffer, CloseBracketW);
	PushToLogW(Buffer, LogBufferSize, LOG_NORMAL);
}

VOID ProtectParentId(
	PPROCESS_BASIC_INFORMATION pBasicInfo
	)
{
	if (!ARGUMENT_PRESENT(pBasicInfo))
		return;

	if (shctx.dwExplorerProcessId != 0) {
		if ( IsProcessRunning((HANDLE)pBasicInfo->InheritedFromUniqueProcessId) == FALSE) {
			pBasicInfo->InheritedFromUniqueProcessId = (ULONG_PTR)shctx.dwExplorerProcessId;
		}
	}
}

VOID LogDebuggerDetect(
	LPSTR DetectionType
	)
{
	CHAR szLog[LOGBUFFERSIZESMALL];

	RtlSecureZeroMemory(szLog, sizeof(szLog));

	if (!ARGUMENT_PRESENT(DetectionType) ) 
		return;
	_strcpyA(szLog, "DebuggerDetect");
	_strcatA(szLog, OpenBracketA);
	_strcatA(szLog, DetectionType);
	_strcatA(szLog, CloseBracketA);

	PushToLogA(szLog, LOGBUFFERSIZESMALL, LOG_NORMAL);
}

NTSTATUS NTAPI NtQueryInformationProcessHook(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    )
{
	PTLS Tls;
	NTSTATUS Status;
	PUNICODE_STRING DynamicString;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pNtQueryInformationProcess(
					ProcessHandle, 
					ProcessInformationClass, 
					ProcessInformation, 
					ProcessInformationLength, 
					ReturnLength);
		Tls->ourcall = TRUE;
	}

	__try {

		RtlSecureZeroMemory(tBuff, sizeof(tBuff));

		Status = pNtQueryInformationProcess(
			ProcessHandle, 
			ProcessInformationClass, 
			ProcessInformation, 
			ProcessInformationLength, 
			ReturnLength);

		if ( NT_SUCCESS(Status) ) {
			DynamicString = (PUNICODE_STRING)ProcessInformation;
			switch ( ProcessInformationClass ) {
				/* protect from parent id trick */
			case ProcessBasicInformation:
				ProtectParentId((PPROCESS_BASIC_INFORMATION)ProcessInformation);
				LogProcessInformationClass(ProcessHandle, ProcessInformationClass, tBuff, LOGBUFFERSIZELONG);
				break;
				/* psapi!GetProcessImageFileName */
			case ProcessImageFileName:
				if ( Tls ) Tls->showcomparision = TRUE;
				LogProcessInformation(L"GetProcessImageFileName", DynamicString, tBuff, MAX_PATH * 2, LOGBUFFERSIZELONG);
				break;
				/* kernel32!QueryFullProcessImageName Vista+ */
			case ProcessImageFileNameWin32:
				if ( Tls ) Tls->showcomparision = TRUE;
				LogProcessInformation(L"QueryFullProcessImageName", DynamicString, tBuff, MAX_PATH * 2, LOGBUFFERSIZELONG);
				break;
				/* kernel32!GetProcessDEPPolicy */
			case ProcessExecuteFlags:
				LogAsCall(L"GetProcessDEPPolicy()", LOG_NORMAL);
				break;
				/* kernel32!CheckRemoteDebuggerPresent */
			case ProcessDebugPort:
				LogAsCall(L"CheckRemoteDebuggerPresent()", LOG_NORMAL);
				break;
				/* attempt to detect debugger via debugger port */
			case ProcessDebugObjectHandle:
				LogDebuggerDetect("ProcessDebugObjectHandle");
				break;
				/* attempt to detect debugger via debug flags */
			case ProcessDebugFlags:
				LogDebuggerDetect("ProcessDebugFlags");
				break;
			default:
				LogProcessInformationClass(ProcessHandle, ProcessInformationClass, tBuff, LOGBUFFERSIZELONG);
				break;
			}
		} 

	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcpyW(tBuff, L"NtQueryInformationProcess()");
		_strcatW(tBuff, NTDLL_EXCEPTION);
		utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
		PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);
		Status = STATUS_ACCESS_VIOLATION;
	}

	if ( Tls ) Tls->ourcall = FALSE;
	return Status;
}

NTSTATUS NTAPI NtSetInformationProcessHook(
	HANDLE ProcessHandle, 
	PROCESSINFOCLASS ProcessInformationClass, 
	PVOID ProcessInformation, 
	ULONG ProcessInformationLength
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);	
		Tls->ourcall = TRUE;
	}

	switch ( ProcessInformationClass ) {

	/* attempt to turn on tracing of system calls */
	case ProcessHandleTracing:
		
		LogAsCall(L"SetInformationProcess(ProcessHandleTracing)", LOG_NORMAL);
		break;

	/* ntdll!RtlSetProcessIsCritical */
	case ProcessBreakOnTermination:
		LogAsCall(L"RtlSetProcessIsCritical()", LOG_NORMAL);
		break;

	/* kernel32!SetProcessDEPPolicy */
	case ProcessExecuteFlags:
		LogAsCall(L"SetProcessDEPPolicy()", LOG_NORMAL);
		break;

	default:
		break;
	}

	if ( Tls ) Tls->ourcall = FALSE;
	return pNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}

NTSTATUS NTAPI NtAdjustPrivilegesTokenHook(
	HANDLE TokenHandle, 
	BOOLEAN DisableAllPrivileges, 
	PTOKEN_PRIVILEGES NewState, 
	ULONG BufferLength, 
	PTOKEN_PRIVILEGES PreviousState, 
	PULONG ReturnLength
	)
{
	PTLS Tls;
	DWORD PrivilegeCount;
	DWORD Attributes;
	LARGE_INTEGER luid;
	DWORD i;
	BOOL bFound;

	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pNtAdjustPrivilegesToken(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"AdjustTokenPrivileges(");

	if ( DisableAllPrivileges == TRUE ) {
		_strcatW(tBuff, L"DisableAllPrivileges");
	} else {

		//put privileges
		if ( ARGUMENT_PRESENT(NewState) ) {
			__try {
				PrivilegeCount = NewState->PrivilegeCount;
				//list first 5 privileges, do not change amount without increasing temp buffer size
				if ( PrivilegeCount > 5 ) PrivilegeCount = 5;
				for (i = 0; i < PrivilegeCount; i++) {
					luid.HighPart = NewState->Privileges[i].Luid.HighPart;
					luid.LowPart = NewState->Privileges[i].Luid.LowPart;
					if (i > 0) _strcatW(tBuff, CommaExW);
					if (( luid.LowPart < PRIVILEGE_COUNT ) && (luid.HighPart == 0) ) {
						_strcatW(tBuff, pwszPrivileges[luid.LowPart]);
					} else {
						utohexW((ULONG_PTR)luid.QuadPart, _strendW(tBuff));
					}
					_strcatW(tBuff, ColonW);
					bFound = FALSE;
					Attributes = NewState->Privileges[i].Attributes;
					if ( Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) { 
						_strcatW(tBuff, L" EnabledByDefault");
						bFound = TRUE;
					}
					if ( Attributes & SE_PRIVILEGE_ENABLED) {
						_strcatW(tBuff, L" Enable"); 
						bFound = TRUE;
					}
					if ( Attributes & SE_PRIVILEGE_REMOVED) {
						_strcatW(tBuff, L" Disable");
						bFound = TRUE;
					}
					if ( Attributes & SE_PRIVILEGE_USED_FOR_ACCESS) {
						_strcatW(tBuff, L" PrivilegeUsedForAccess");
						bFound = TRUE;
					}
					if ( bFound == FALSE ) {
						//zero or invalid attributes value specified
						_ultostrW(Attributes, _strendW(tBuff));
					}
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				_strcatW(tBuff, NTDLL_EXCEPTION);
				utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
			}
		} else { //<- ARGUMENT_PRESENT(NewState);
			_strcatW(tBuff, NullStrW);
		}
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNtAdjustPrivilegesToken(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
}

NTSTATUS NTAPI NtOpenProcessTokenHook(
	HANDLE ProcessHandle, 
	ACCESS_MASK DesiredAccess, 
	PHANDLE TokenHandle
	)
{
	PTLS Tls;
	DWORD dwProcessId;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pNtOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"OpenProcessToken(");

	//put filename
	dwProcessId = 0;
	if (!QueryProcessName(ProcessHandle, _strendW(tBuff), MAX_PATH * 2, &dwProcessId)) {
		if (!LogSystemProcess(dwProcessId, _strendW(tBuff))) {
			ultostrW((ULONG_PTR)dwProcessId, _strendW(tBuff));
		}
	}

	//put DesiredAccess
	if ( DesiredAccess == TOKEN_ALL_ACCESS ) { 
		_strcatW(tBuff, L", TOKEN_ALL_ACCESS"); 
	} else {
		if ( DesiredAccess & TOKEN_ADJUST_DEFAULT ) _strcatW(tBuff, L", TOKEN_ADJUST_DEFAULT"); 
		if ( DesiredAccess & TOKEN_ADJUST_GROUPS ) _strcatW(tBuff, L", TOKEN_ADJUST_GROUPS"); 
		if ( DesiredAccess & TOKEN_ADJUST_PRIVILEGES ) _strcatW(tBuff, L", TOKEN_ADJUST_PRIVILEGES"); 
		if ( DesiredAccess & TOKEN_ADJUST_SESSIONID ) _strcatW(tBuff, L", TOKEN_ADJUST_SESSIONID"); 
		if ( DesiredAccess & TOKEN_ASSIGN_PRIMARY ) _strcatW(tBuff, L", TOKEN_ASSIGN_PRIMARY"); 
		if ( DesiredAccess & TOKEN_DUPLICATE ) _strcatW(tBuff, L", TOKEN_DUPLICATE"); 
		if ( DesiredAccess & TOKEN_EXECUTE ) _strcatW(tBuff, L", TOKEN_EXECUTE"); 
		if ( DesiredAccess & TOKEN_IMPERSONATE ) _strcatW(tBuff, L", TOKEN_IMPERSONATE"); 
		if ( DesiredAccess & TOKEN_QUERY ) _strcatW(tBuff, L", TOKEN_QUERY"); 
		if ( DesiredAccess & TOKEN_QUERY_SOURCE ) _strcatW(tBuff, L", TOKEN_QUERY_SOURCE"); 
		if ( DesiredAccess & TOKEN_READ ) _strcatW(tBuff, L", TOKEN_READ"); 
		if ( DesiredAccess & TOKEN_WRITE ) _strcatW(tBuff, L", TOKEN_WRITE");
		if ( DesiredAccess & ACCESS_SYSTEM_SECURITY) _strcatW(tBuff, L", ACCESS_SYSTEM_SECURITY");
		if ( DesiredAccess & DELETE) _strcatW(tBuff, L", DELETE");
		if ( DesiredAccess & READ_CONTROL) _strcatW(tBuff, L", READ_CONTROL");
		if ( DesiredAccess & WRITE_DAC) _strcatW(tBuff, L", WRITE_DAC");
		if ( DesiredAccess & WRITE_OWNER) _strcatW(tBuff, L", WRITE_OWNER");
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNtOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);
}

NTSTATUS NTAPI NtOpenProcessTokenExHook(
	HANDLE ProcessHandle, 
	ACCESS_MASK DesiredAccess, 
	ULONG HandleAttributes,
	PHANDLE TokenHandle
	)
{
	PTLS Tls;
	DWORD dwProcessId;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pNtOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"OpenProcessTokenEx(");

	//put filename
	dwProcessId = 0;
	if (!QueryProcessName(ProcessHandle, _strendW(tBuff), MAX_PATH * 2, &dwProcessId)) {
		if (!LogSystemProcess(dwProcessId, _strendW(tBuff))) {
			ultostrW((ULONG_PTR)dwProcessId, _strendW(tBuff));
		}
	}

	//put DesiredAccess
	if ( DesiredAccess == TOKEN_ALL_ACCESS ) { 
		_strcatW(tBuff, L", TOKEN_ALL_ACCESS"); 
	} else {
		if ( DesiredAccess & TOKEN_ADJUST_DEFAULT ) _strcatW(tBuff, L", TOKEN_ADJUST_DEFAULT"); 
		if ( DesiredAccess & TOKEN_ADJUST_GROUPS ) _strcatW(tBuff, L", TOKEN_ADJUST_GROUPS"); 
		if ( DesiredAccess & TOKEN_ADJUST_PRIVILEGES ) _strcatW(tBuff, L", TOKEN_ADJUST_PRIVILEGES"); 
		if ( DesiredAccess & TOKEN_ADJUST_SESSIONID ) _strcatW(tBuff, L", TOKEN_ADJUST_SESSIONID"); 
		if ( DesiredAccess & TOKEN_ASSIGN_PRIMARY ) _strcatW(tBuff, L", TOKEN_ASSIGN_PRIMARY"); 
		if ( DesiredAccess & TOKEN_DUPLICATE ) _strcatW(tBuff, L", TOKEN_DUPLICATE"); 
		if ( DesiredAccess & TOKEN_EXECUTE ) _strcatW(tBuff, L", TOKEN_EXECUTE"); 
		if ( DesiredAccess & TOKEN_IMPERSONATE ) _strcatW(tBuff, L", TOKEN_IMPERSONATE"); 
		if ( DesiredAccess & TOKEN_QUERY ) _strcatW(tBuff, L", TOKEN_QUERY"); 
		if ( DesiredAccess & TOKEN_QUERY_SOURCE ) _strcatW(tBuff, L", TOKEN_QUERY_SOURCE"); 
		if ( DesiredAccess & TOKEN_READ ) _strcatW(tBuff, L", TOKEN_READ"); 
		if ( DesiredAccess & TOKEN_WRITE ) _strcatW(tBuff, L", TOKEN_WRITE");
		if ( DesiredAccess & ACCESS_SYSTEM_SECURITY) _strcatW(tBuff, L", ACCESS_SYSTEM_SECURITY");
		if ( DesiredAccess & DELETE) _strcatW(tBuff, L", DELETE");
		if ( DesiredAccess & READ_CONTROL) _strcatW(tBuff, L", READ_CONTROL");
		if ( DesiredAccess & WRITE_DAC) _strcatW(tBuff, L", WRITE_DAC");
		if ( DesiredAccess & WRITE_OWNER) _strcatW(tBuff, L", WRITE_OWNER");
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNtOpenProcessTokenEx(ProcessHandle, DesiredAccess, HandleAttributes, TokenHandle);
}

NTSTATUS NTAPI NtDeviceIoControlFileHook(
	HANDLE FileHandle, 
	HANDLE Event, 
	PIO_APC_ROUTINE ApcRoutine, 
	PVOID ApcContext, 
	PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
	PVOID InputBuffer,
	ULONG InputBufferLength, 
	PVOID OutputBuffer, 
	ULONG OutputBufferLength
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pNtDeviceIoControlFile(
						FileHandle,
						Event, 
						ApcRoutine, 
						ApcContext, 
						IoStatusBlock, 
						IoControlCode, 
						InputBuffer, 
						InputBufferLength, 
						OutputBuffer, 
						OutputBufferLength
						);
		
		Tls->ourcall = TRUE;
	}

	switch ( IoControlCode ) {
	case IOCTL_STORAGE_QUERY_PROPERTY:
		LogAsCallA("DeviceIoControl(IOCTL_STORAGE_QUERY_PROPERTY)", LOG_NORMAL);
		break;
	default:
		break;
	}

	if ( Tls ) Tls->ourcall = FALSE;
	return pNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, 
		IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
}

NTSTATUS NTAPI NtSetEaFileHook(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID Buffer,
    IN ULONG Length
    )
{
	PTLS Tls;
	WCHAR tBuff[LOGBUFFERSIZE];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pNtSetEaFile(FileHandle, IoStatusBlock, Buffer, Length);
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"NtSetEaFile(");

	if (ARGUMENT_PRESENT( Buffer ) & Length ) {
		_strcatW(tBuff, L"Buffer=0x");
		utohexW((ULONG_PTR)Buffer, _strendW(tBuff));
		_strcatW(tBuff, EaLengthW);
		ultostrW(Length, _strendW(tBuff));
	} else {
		_strcatW(tBuff, NullStrW);
	}
	/*NtSetEaFile(Buffer=0xADDRESS, Length=XXXXXX)*/

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNtSetEaFile(FileHandle, IoStatusBlock, Buffer, Length);
}

NTSTATUS NTAPI NtCreateFileHook(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength
	)
{
	PTLS Tls;
	PUNICODE_STRING pObjectName = NULL;
	WCHAR tBuff[LOGBUFFERSIZELONG];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) 
			return pNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, 
			FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
		Tls->ourcall = TRUE;
	}

	//write access check
	if ( DesiredAccess & FILE_WRITE_EA ) {
		//EaBuffer cannot be NULL
		if (ARGUMENT_PRESENT( EaBuffer ) && EaLength) {

			RtlSecureZeroMemory(tBuff, sizeof(tBuff));

			//put prolog
			_strcpyW(tBuff, L"NtCreateFile(");

			//query file name from attributes
			if (ARGUMENT_PRESENT( ObjectAttributes ) ) {
				//probe object attributes
				__try {
					pObjectName = ObjectAttributes->ObjectName;
					if ( pObjectName != NULL ) {
						if (( pObjectName->Buffer != NULL ) && ( pObjectName->Length > 0 )) {
							_strncpyW(_strendW(tBuff), MAX_PATH, pObjectName->Buffer, MAX_PATH);
						} else {
							if ( ObjectAttributes->RootDirectory != NULL ) {
								_strcatW(tBuff, RootDirectoryW);
								utohexW((ULONG_PTR)ObjectAttributes->RootDirectory, _strendW(tBuff));
							} else {
								_strcatW(tBuff, NullStrW);
							}
						}
					} else {
						//ObjectName not specified, used root handle
						if ( ObjectAttributes->RootDirectory != NULL ) {
							_strcatW(tBuff, RootDirectoryW);
							utohexW((ULONG_PTR)ObjectAttributes->RootDirectory, _strendW(tBuff));
						} else {
							_strcatW(tBuff, NullStrW);
						}
					}
				} __except (EXCEPTION_EXECUTE_HANDLER) {
					_strcatW(tBuff, NTDLL_EXCEPTION);
					utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
				}
			} else {
				_strcatW(tBuff, NullStrW);
			}
			_strcatW(tBuff, L", EaBuffer=0x");
			utohexW((ULONG_PTR)EaBuffer, _strendW(tBuff));
			_strcatW(tBuff, EaLengthW);
			ultostrW(EaLength, _strendW(tBuff));

			//put epilog and log
			_strcatW(tBuff, CloseBracketW);
			PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);
			/*NtCreateFile(FileName, EaBuffer=0xADDRESS, EaLength=XXXXX)*/
		}
	}

	if ( Tls ) Tls->ourcall = FALSE;
	return pNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, 
		FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}
