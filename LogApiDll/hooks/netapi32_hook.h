/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	netapi32_hook.h

Abstract:

	Network API hook interface.

	Last change 24.01.13

--*/

#ifndef _SHNETAPI32HOOK_
#define _SHNETAPI32HOOK_

#include <LM.h>
#include <Lmat.h>

#define NETAPI32_EXCEPTION   L" netapi32!exception 0x"
#define NETAPI32_EXCEPTION_A   " netapi32!exception 0x"

#define LocalHostW L"127.0.0.1"

typedef NET_API_STATUS (NET_API_FUNCTION *PNetServerEnum)(
    LMCSTR servername,
    DWORD level,
    LPBYTE *bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries,
    DWORD servertype,
    LMCSTR domain,
    LPDWORD  resume_handle 
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetShareEnum)(
    LMSTR servername,
    DWORD level,
    LPBYTE *bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries,
    LPDWORD resume_handle
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetShareEnumSticky)(
    LMSTR servername,
    DWORD level,
    LPBYTE *bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries,
    LPDWORD resume_handle
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetShareAdd) (
    LMSTR servername,
    DWORD level,
    LPBYTE buf,
    LPDWORD parm_err
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetShareDel)(
    LMSTR servername,
    LMSTR netname,
    DWORD reserved
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetShareDelSticky)(
    LMSTR servername,
    LMSTR netname,
    DWORD reserved
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetScheduleJobAdd)(
    LPCWSTR Servername,
    LPBYTE Buffer,
    LPDWORD JobId
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetUserAdd)(
    LPCWSTR servername,
    DWORD level,
    LPBYTE buf,
    LPDWORD parm_err
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetUserEnum)(
    LPCWSTR servername,
    DWORD level,
    DWORD filter,
    LPBYTE *bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries,
    LPDWORD resume_handle 
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetUserChangePassword)(
    LPCWSTR domainname,
    LPCWSTR username,
    LPCWSTR oldpassword,
    LPCWSTR newpassword
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetUserDel)(
    LPCWSTR servername,
    LPCWSTR username
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetUserGetGroups)(
    LPCWSTR servername,
    LPCWSTR username,
    DWORD level,
    LPBYTE *bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetUserSetGroups)(
    LPCWSTR servername,
    LPCWSTR username,
    DWORD level,
    LPBYTE buf,
    DWORD num_entries
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetUserGetInfo)(
    LPCWSTR servername,
    LPCWSTR username,
    DWORD level,
    LPBYTE *bufptr
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetUserSetInfo)(
    LPCWSTR servername,
    LPCWSTR username,
    DWORD level,
    LPBYTE buf,
    LPDWORD parm_err 
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetUserGetLocalGroups)(
    LPCWSTR servername,
    LPCWSTR username,
    DWORD level,
    DWORD flags,
    LPBYTE *bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetUseAdd)(
    LMSTR UncServerName,
    DWORD Level,
    LPBYTE Buf,
    LPDWORD ParmError
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetUseDel)(
    LMSTR UncServerName,
    LMSTR UseName,
    DWORD ForceCond
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetUseEnum)(
    LMSTR UncServerName,
    DWORD Level,
    LPBYTE *BufPtr,
    DWORD PreferedMaximumSize,
    LPDWORD EntriesRead,
    LPDWORD TotalEntries,
    LPDWORD ResumeHandle
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetLocalGroupAdd)(
    LPCWSTR servername,
    DWORD level,
    LPBYTE buf,
    LPDWORD parm_err
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetLocalGroupAddMembers)(
    LPCWSTR servername,
    LPCWSTR groupname,
    DWORD level,
    LPBYTE buf,
    DWORD totalentries
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetLocalGroupDel)(
    LPCWSTR servername,
    LPCWSTR groupname
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetLocalGroupDelMembers)(
    LPCWSTR servername,
    LPCWSTR groupname,
    DWORD level,
    LPBYTE buf,
    DWORD totalentries
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetGroupAdd)(
    LPCWSTR servername,
    DWORD level,
    LPBYTE buf,
    LPDWORD parm_err
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetGroupAddUser)(
    LPCWSTR servername,
    LPCWSTR GroupName,
    LPCWSTR username
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetGroupDel)(
    LPCWSTR servername,
    LPCWSTR groupname
    );

typedef NET_API_STATUS (NET_API_FUNCTION *PNetGroupDelUser)(
    LPCWSTR servername,
    LPCWSTR GroupName,
    LPCWSTR Username
    );

extern PNetServerEnum pNetServerEnum;
extern PNetShareEnum pNetShareEnum;
extern PNetShareEnumSticky pNetShareEnumSticky;
extern PNetShareAdd pNetShareAdd;
extern PNetShareDel pNetShareDel;
extern PNetShareDelSticky pNetShareDelSticky;
extern PNetScheduleJobAdd pNetScheduleJobAdd;
extern PNetUserAdd pNetUserAdd;
extern PNetUserEnum pNetUserEnum;
extern PNetUserChangePassword pNetUserChangePassword;
extern PNetUserDel pNetUserDel;
extern PNetUserGetGroups pNetUserGetGroups;
extern PNetUserSetGroups pNetUserSetGroups;
extern PNetUserGetInfo pNetUserGetInfo;
extern PNetUserSetInfo pNetUserSetInfo;
extern PNetUserGetLocalGroups pNetUserGetLocalGroups;
extern PNetUseAdd pNetUseAdd;
extern PNetUseDel pNetUseDel;
extern PNetUseEnum pNetUseEnum;
extern PNetLocalGroupAdd pNetLocalGroupAdd;
extern PNetLocalGroupAddMembers pNetLocalGroupAddMembers;
extern PNetLocalGroupDel pNetLocalGroupDel;
extern PNetLocalGroupDelMembers pNetLocalGroupDelMembers;
extern PNetGroupAdd pNetGroupAdd;
extern PNetGroupAddUser pNetGroupAddUser;
extern PNetGroupDel pNetGroupDel;
extern PNetGroupDelUser pNetGroupDelUser;

NET_API_STATUS NET_API_FUNCTION NetServerEnumHook(
    LMCSTR servername,
    DWORD level,
    LPBYTE *bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries,
    DWORD servertype,
    LMCSTR domain,
    LPDWORD  resume_handle 
    );

NET_API_STATUS NET_API_FUNCTION NetShareEnumHook(
    LMSTR servername,
    DWORD level,
    LPBYTE *bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries,
    LPDWORD resume_handle
    );

NET_API_STATUS NET_API_FUNCTION NetShareEnumStickyHook(
    LMSTR servername,
    DWORD level,
    LPBYTE *bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries,
    LPDWORD resume_handle
    );

NET_API_STATUS NET_API_FUNCTION NetShareAddHook(
    LMSTR servername,
    DWORD level,
    LPBYTE buf,
    LPDWORD parm_err
    );

NET_API_STATUS NET_API_FUNCTION NetShareDelHook(
    LMSTR servername,
    LMSTR netname,
    DWORD reserved
    );

NET_API_STATUS NET_API_FUNCTION NetShareDelStickyHook(
    LMSTR servername,
    LMSTR netname,
    DWORD reserved
    );

NET_API_STATUS NET_API_FUNCTION NetScheduleJobAddHook(
    LPCWSTR Servername,
    LPBYTE Buffer,
    LPDWORD JobId
    );

NET_API_STATUS NET_API_FUNCTION NetUserAddHook(
    LPCWSTR servername,
    DWORD level,
    LPBYTE buf,
    LPDWORD parm_err
    );

NET_API_STATUS NET_API_FUNCTION NetUserDelHook(
    LPCWSTR servername,
    LPCWSTR username
    );

NET_API_STATUS NET_API_FUNCTION NetUserEnumHook(
    LPCWSTR servername,
    DWORD level,
    DWORD filter,
    LPBYTE *bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries,
    LPDWORD resume_handle 
    );

NET_API_STATUS NET_API_FUNCTION NetUserChangePasswordHook(
    LPCWSTR domainname,
    LPCWSTR username,
    LPCWSTR oldpassword,
    LPCWSTR newpassword
    );

NET_API_STATUS NET_API_FUNCTION NetUserGetGroupsHook(
    LPCWSTR servername,
    LPCWSTR username,
    DWORD level,
    LPBYTE *bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries
    );

NET_API_STATUS NET_API_FUNCTION NetUserSetGroupsHook(
    LPCWSTR servername,
    LPCWSTR username,
    DWORD level,
    LPBYTE buf,
    DWORD num_entries
    );

NET_API_STATUS NET_API_FUNCTION NetUserGetInfoHook(
    LPCWSTR servername,
    LPCWSTR username,
    DWORD level,
    LPBYTE *bufptr
    );

NET_API_STATUS NET_API_FUNCTION NetUserSetInfoHook(
    LPCWSTR servername,
    LPCWSTR username,
    DWORD level,
    LPBYTE buf,
    LPDWORD parm_err 
    );

NET_API_STATUS NET_API_FUNCTION NetUserGetLocalGroupsHook(
    LPCWSTR servername,
    LPCWSTR username,
    DWORD level,
    DWORD flags,
    LPBYTE *bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries
    );

NET_API_STATUS NET_API_FUNCTION NetUseAddHook(
    LMSTR UncServerName,
    DWORD Level,
    LPBYTE Buf,
    LPDWORD ParmError
    );

NET_API_STATUS NET_API_FUNCTION NetUseDelHook(
    LMSTR UncServerName,
    LMSTR UseName,
    DWORD ForceCond
    );

NET_API_STATUS NET_API_FUNCTION NetUseEnumHook(
    LMSTR UncServerName,
    DWORD Level,
    LPBYTE *BufPtr,
    DWORD PreferedMaximumSize,
    LPDWORD EntriesRead,
    LPDWORD TotalEntries,
    LPDWORD ResumeHandle
    );

NET_API_STATUS NET_API_FUNCTION NetLocalGroupAddHook(
    LPCWSTR servername,
    DWORD level,
    LPBYTE buf,
    LPDWORD parm_err
    );

NET_API_STATUS NET_API_FUNCTION NetLocalGroupAddMembersHook(
    LPCWSTR servername,
    LPCWSTR groupname,
    DWORD level,
    LPBYTE buf,
    DWORD totalentries
    );

NET_API_STATUS NET_API_FUNCTION NetLocalGroupDelHook(
    LPCWSTR servername,
    LPCWSTR groupname
    );

NET_API_STATUS NET_API_FUNCTION NetLocalGroupDelMembersHook(
    LPCWSTR servername,
    LPCWSTR groupname,
    DWORD level,
    LPBYTE buf,
    DWORD totalentries
    );

NET_API_STATUS NET_API_FUNCTION NetGroupAddHook(
    LPCWSTR servername,
    DWORD level,
    LPBYTE buf,
    LPDWORD parm_err
    );

NET_API_STATUS NET_API_FUNCTION NetGroupAddUserHook(
    LPCWSTR servername,
    LPCWSTR GroupName,
    LPCWSTR username
    );

NET_API_STATUS NET_API_FUNCTION NetGroupDelHook(
    LPCWSTR servername,
    LPCWSTR groupname
    );

NET_API_STATUS NET_API_FUNCTION NetGroupDelUserHook(
    LPCWSTR servername,
    LPCWSTR GroupName,
    LPCWSTR Username
    );

#endif /* _SHNETAPI32HOOK_ */