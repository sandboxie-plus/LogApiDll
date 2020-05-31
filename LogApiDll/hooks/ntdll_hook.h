/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	ntdll_hook.h

Abstract:

	NT DLL hook interface.

	Last change 27.01.13

--*/

#ifndef _SHNTDLLHOOK_
#define _SHNTDLLHOOK_

#define NTDLL_EXCEPTION   L" ntdll!exception 0x"
#define RootDirectoryW    L"RootDirectory=0x"
#define EaLengthW         L", EaLength="

typedef NTSTATUS (NTAPI *PNtSetInformationThread)(
	HANDLE ThreadHandle, 
	THREADINFOCLASS ThreadInformationClass, 
	PVOID ThreadInformation, 
	ULONG ThreadInformationLength
	);

typedef NTSTATUS (NTAPI *PNtLoadDriver)(
	PUNICODE_STRING DriverServiceName
	);

typedef NTSTATUS (NTAPI *PNtTerminateProcess)(
	HANDLE ProcessHandle, 
	NTSTATUS ExitStatus
	);

typedef NTSTATUS (NTAPI *PNtWriteVirtualMemory) (
	HANDLE ProcessHandle, 
	PVOID BaseAddress, 
	VOID *Buffer, 
	SIZE_T BufferSize, 
	PSIZE_T NumberOfBytesWritten
	);

typedef NTSTATUS (NTAPI *PNtResumeThread) (
	HANDLE ThreadHandle, 
	PULONG PreviousSuspendCount
	);

typedef NTSTATUS (NTAPI *PNtSuspendThread) (
	HANDLE ThreadHandle, 
	PULONG PreviousSuspendCount
	);

typedef NTSTATUS (NTAPI *PNtQueueApcThread) (
	HANDLE ThreadHandle, 
	PPS_APC_ROUTINE ApcRoutine, 
	PVOID ApcArgument1, 
	PVOID ApcArgument2, 
	PVOID ApcArgument3
	);

typedef NTSTATUS (NTAPI *PNtDelayExecution) (
	BOOLEAN Alertable, 
	PLARGE_INTEGER DelayInterval
	);

typedef NTSTATUS (NTAPI *PNtQueryAttributesFile) (
	POBJECT_ATTRIBUTES ObjectAttributes, 
	PFILE_BASIC_INFORMATION FileInformation
	);

typedef NTSTATUS (NTAPI *PNtQueryVirtualMemory) (
	HANDLE ProcessHandle, 
	PVOID BaseAddress, 
	MEMORY_INFORMATION_CLASS MemoryInformationClass, 
	PVOID MemoryInformation, 
	SIZE_T MemoryInformationLength,
	PSIZE_T ReturnLength
	);

typedef NTSTATUS (NTAPI *PNtSetInformationProcess)(
	HANDLE ProcessHandle, 
	PROCESSINFOCLASS ProcessInformationClass, 
	PVOID ProcessInformation, 
	ULONG ProcessInformationLength
	);

typedef NTSTATUS (NTAPI *PNtAdjustPrivilegesToken)(
	HANDLE TokenHandle, 
	BOOLEAN DisableAllPrivileges, 
	PTOKEN_PRIVILEGES NewState, 
	ULONG BufferLength, 
	PTOKEN_PRIVILEGES PreviousState, 
	PULONG ReturnLength
	);

typedef NTSTATUS (NTAPI *PNtOpenProcessToken)(
	HANDLE ProcessHandle, 
	ACCESS_MASK DesiredAccess, 
	PHANDLE TokenHandle
	);

typedef NTSTATUS (NTAPI *PNtDeviceIoControlFile)(
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
	);

typedef NTSTATUS (NTAPI *PNtSetEaFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length
    );

typedef NTSTATUS (NTAPI *PNtCreateFile)(
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
    );

extern PNtSetInformationThread pNtSetInformationThread;
extern PNtLoadDriver pNtLoadDriver;
extern PNtTerminateProcess pNtTerminateProcess;
extern PNtWriteVirtualMemory pNtWriteVirtualMemory;
extern PNtResumeThread pNtResumeThread;
extern PNtSuspendThread pNtSuspendThread;
extern PNtQueueApcThread pNtQueueApcThread;
extern PNtDelayExecution pNtDelayExecution;
extern PNtQueryVirtualMemory pNtQueryVirtualMemory;
extern PNtSetInformationProcess pNtSetInformationProcess;
extern PNtAdjustPrivilegesToken pNtAdjustPrivilegesToken;
extern PNtOpenProcessToken pNtOpenProcessToken;
extern PNtDeviceIoControlFile pNtDeviceIoControlFile;
extern PNtSetEaFile pNtSetEaFile;
extern PNtCreateFile pNtCreateFile;

typedef NTSTATUS (NTAPI *PLdrFindEntryForAddress)(
	PVOID Address, 
	PLDR_DATA_TABLE_ENTRY *TableEntry
	);

extern PLdrFindEntryForAddress pLdrFindEntryForAddress;

NTSTATUS NTAPI NtSetInformationThreadHook(
	HANDLE ThreadHandle, 
	THREADINFOCLASS ThreadInformationClass, 
	PVOID ThreadInformation, 
	ULONG ThreadInformationLength
	);

NTSTATUS NTAPI NtLoadDriverHook(
	PUNICODE_STRING DriverServiceName
	);

NTSTATUS NTAPI NtTerminateProcessHook(
	HANDLE ProcessHandle, 
	NTSTATUS ExitStatus
	);

NTSTATUS NTAPI NtAllocateVirtualMemoryHook(
	HANDLE ProcessHandle, 
	PVOID *BaseAddress, 
	ULONG_PTR ZeroBits, 
	PSIZE_T RegionSize, 
	ULONG AllocationType, 
	ULONG Protect
	);

NTSTATUS NTAPI NtWriteVirtualMemoryHook(
	HANDLE ProcessHandle, 
	PVOID BaseAddress, 
	VOID *Buffer, 
	SIZE_T BufferSize, 
	PSIZE_T NumberOfBytesWritten
	);

NTSTATUS NTAPI NtReadVirtualMemoryHook( 
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesRead
	);

NTSTATUS NTAPI NtResumeThreadHook(
	HANDLE ThreadHandle, 
	PULONG PreviousSuspendCount
	);

NTSTATUS NTAPI NtSuspendThreadHook(
	HANDLE ThreadHandle, 
	PULONG PreviousSuspendCount
	);

NTSTATUS NTAPI NtQueueApcThreadHook(
	HANDLE ThreadHandle, 
	PPS_APC_ROUTINE ApcRoutine, 
	PVOID ApcArgument1, 
	PVOID ApcArgument2, 
	PVOID ApcArgument3
	);

NTSTATUS NTAPI NtOpenProcessHook(    
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
	);

NTSTATUS NTAPI NtQuerySystemInformationHook(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

NTSTATUS NTAPI NtDelayExecutionHook(
	BOOLEAN Alertable, 
	PLARGE_INTEGER DelayInterval
	);

NTSTATUS NTAPI NtQueryVirtualMemoryHook(
	HANDLE ProcessHandle, 
	PVOID BaseAddress, 
	MEMORY_INFORMATION_CLASS MemoryInformationClass, 
	PVOID MemoryInformation, 
	SIZE_T MemoryInformationLength,
	PSIZE_T ReturnLength
	);

NTSTATUS NTAPI NtQueryInformationProcessHook(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

NTSTATUS NTAPI NtSetInformationProcessHook(
	HANDLE ProcessHandle, 
	PROCESSINFOCLASS ProcessInformationClass, 
	PVOID ProcessInformation, 
	ULONG ProcessInformationLength
	);

NTSTATUS NTAPI NtAdjustPrivilegesTokenHook(
	HANDLE TokenHandle, 
	BOOLEAN DisableAllPrivileges, 
	PTOKEN_PRIVILEGES NewState, 
	ULONG BufferLength, 
	PTOKEN_PRIVILEGES PreviousState, 
	PULONG ReturnLength
	);

NTSTATUS NTAPI NtOpenProcessTokenHook(
	HANDLE ProcessHandle, 
	ACCESS_MASK DesiredAccess, 
	PHANDLE TokenHandle
	);

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
	);

NTSTATUS NTAPI NtSetEaFileHook(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID Buffer,
    IN ULONG Length
    );

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
    );

/* Ldr routines */
NTSTATUS NTAPI LdrFindEntryForAddressHook(
	PVOID Address, 
	PLDR_DATA_TABLE_ENTRY *TableEntry
	);

#endif /* _SHNTDLLHOOK_ */