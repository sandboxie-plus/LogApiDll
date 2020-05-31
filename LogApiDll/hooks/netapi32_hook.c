/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	netapi32_hook.c

Abstract:

	Network API hook implementation.

	Last change 04.02.13

--*/

#include "..\global.h"
#include "netapi32_hook.h"

PNetServerEnum pNetServerEnum = NULL;
PNetShareEnum pNetShareEnum = NULL;
PNetShareEnumSticky pNetShareEnumSticky = NULL;
PNetShareAdd pNetShareAdd = NULL;
PNetShareDel pNetShareDel = NULL;
PNetShareDelSticky pNetShareDelSticky = NULL;
PNetScheduleJobAdd pNetScheduleJobAdd = NULL;
PNetUserAdd pNetUserAdd = NULL;
PNetUserEnum pNetUserEnum = NULL;
PNetUserChangePassword pNetUserChangePassword = NULL;
PNetUserDel pNetUserDel = NULL;
PNetUserGetGroups pNetUserGetGroups = NULL;
PNetUserSetGroups pNetUserSetGroups = NULL;
PNetUserGetInfo pNetUserGetInfo = NULL;
PNetUserSetInfo pNetUserSetInfo = NULL;
PNetUserGetLocalGroups pNetUserGetLocalGroups = NULL;
PNetUseAdd pNetUseAdd = NULL;
PNetUseDel pNetUseDel = NULL;
PNetUseEnum pNetUseEnum = NULL;
PNetLocalGroupAdd pNetLocalGroupAdd = NULL;
PNetLocalGroupAddMembers pNetLocalGroupAddMembers = NULL;
PNetLocalGroupDel pNetLocalGroupDel = NULL;
PNetLocalGroupDelMembers pNetLocalGroupDelMembers = NULL;
PNetGroupAdd pNetGroupAdd = NULL;
PNetGroupAddUser pNetGroupAddUser = NULL;
PNetGroupDel pNetGroupDel = NULL;
PNetGroupDelUser pNetGroupDelUser = NULL;

VOID LogNetCallW(
	LPCWSTR ApiName,
	LPCWSTR lpParam1,
	LPCWSTR lpParam2,
	LPCWSTR lpParam3,
	LPCWSTR lpParam4,
	DWORD NumberOfParams
	)
{
	WCHAR tBuff[LOGBUFFERSIZELONG];

	if (!ARGUMENT_PRESENT(ApiName)) 
		return;

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, ApiName);
	_strcatW(tBuff, OpenBracketW);

	__try {
		//put lpParam1
		if ( NumberOfParams > 0 ) {
			if ( ARGUMENT_PRESENT(lpParam1) ) {
				_strncpyW(_strendW(tBuff), MAX_PATH, lpParam1, MAX_PATH);
			} else {
				_strcatW(tBuff, NullStrW);
			}
		}

		//put lpParam2
		if ( NumberOfParams > 1 ) {
			_strcatW(tBuff, CommaExW);
			if ( ARGUMENT_PRESENT(lpParam2) ) {
				_strncpyW(_strendW(tBuff), MAX_PATH, lpParam2, MAX_PATH);
			} else {
				_strcatW(tBuff, NullStrW);
			}
		}

		//put lpParam3
		if ( NumberOfParams > 2 ) {
			_strcatW(tBuff, CommaExW);
			if ( ARGUMENT_PRESENT(lpParam3) ) {
				_strncpyW(_strendW(tBuff), MAX_PATH, lpParam3, MAX_PATH);
			} else {
				_strcatW(tBuff, NullStrW);
			}
		}

		//put lpParam4
		if ( NumberOfParams > 3 ) {
			_strcatW(tBuff, CommaExW);
			if ( ARGUMENT_PRESENT(lpParam4) ) {
				_strncpyW(_strendW(tBuff), MAX_PATH, lpParam4, MAX_PATH);
			} else {
				_strcatW(tBuff, NullStrW);
			}
		}

	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatW(tBuff, NETAPI32_EXCEPTION);
		utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);
}

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
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetServerEnum(servername, level, bufptr, prefmaxlen, entriesread, totalentries, servertype, domain, resume_handle);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetServerEnum", domain, NULL, NULL, NULL, 1);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetServerEnum(servername, level, bufptr, prefmaxlen, 
		entriesread, totalentries, servertype, domain, resume_handle);
}

NET_API_STATUS NET_API_FUNCTION NetShareEnumHook(
	LMSTR servername,
	DWORD level,
	LPBYTE *bufptr,
	DWORD prefmaxlen,
	LPDWORD entriesread,
	LPDWORD totalentries,
	LPDWORD resume_handle
	)
{
	PTLS Tls;
	LMSTR lmszServerName = NULL;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetShareEnum(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resume_handle);
		}
		Tls->ourcall = TRUE;
	}

	if ( servername == NULL ) {
		lmszServerName = LocalHostW;
	} else {
		lmszServerName = servername;
	}

	LogNetCallW(L"NetShareEnum", lmszServerName, NULL, NULL, NULL, 1);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetShareEnum(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resume_handle);
}

NET_API_STATUS NET_API_FUNCTION NetShareEnumStickyHook(
	LMSTR servername,
	DWORD level,
	LPBYTE *bufptr,
	DWORD prefmaxlen,
	LPDWORD entriesread,
	LPDWORD totalentries,
	LPDWORD resume_handle
	)
{
	PTLS Tls;
	LMSTR lmszServerName = NULL;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetShareEnumSticky(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resume_handle);
		}
		Tls->ourcall = TRUE;
	}

	if ( servername == NULL ) {
		lmszServerName = LocalHostW;
	} else {
		lmszServerName = servername;
	}

	LogNetCallW(L"NetShareEnumSticky", lmszServerName, NULL, NULL, NULL, 1);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetShareEnumSticky(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resume_handle);
}

NET_API_STATUS NET_API_FUNCTION NetShareAddHook(
	LMSTR servername,
	DWORD level,
	LPBYTE buf,
	LPDWORD parm_err
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetShareAdd(servername, level, buf, parm_err);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetShareAdd", servername, NULL, NULL, NULL, 1);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetShareAdd(servername, level, buf, parm_err);
}

NET_API_STATUS NET_API_FUNCTION NetShareDelHook(
	LMSTR servername,
	LMSTR netname,
	DWORD reserved
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetShareDel(servername, netname, reserved);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetShareDel", servername, netname, NULL, NULL, 2);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetShareDel(servername, netname, reserved);
}

NET_API_STATUS NET_API_FUNCTION NetShareDelStickyHook(
	LMSTR servername,
	LMSTR netname,
	DWORD reserved
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetShareDelSticky(servername, netname, reserved);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetShareDelSticky", servername, netname, NULL, NULL, 2);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetShareDelSticky(servername, netname, reserved);
}

NET_API_STATUS NET_API_FUNCTION NetScheduleJobAddHook(
	LPCWSTR Servername,
	LPBYTE Buffer,
	LPDWORD JobId
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetScheduleJobAdd(Servername, Buffer, JobId);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetScheduleJobAdd", Servername, NULL, NULL, NULL, 1);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetScheduleJobAdd(Servername, Buffer, JobId);
}

NET_API_STATUS NET_API_FUNCTION NetUserAddHook(
	LPCWSTR servername,
	DWORD level,
	LPBYTE buf,
	LPDWORD parm_err
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetUserAdd(servername, level, buf, parm_err);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetUserAdd", servername, NULL, NULL, NULL, 1);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetUserAdd(servername, level, buf, parm_err);
}

NET_API_STATUS NET_API_FUNCTION NetUserDelHook(
	LPCWSTR servername,
	LPCWSTR username
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetUserDel(servername, username);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetUserDel", servername, username, NULL, NULL, 2);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetUserDel(servername, username);
}

NET_API_STATUS NET_API_FUNCTION NetUserEnumHook(
	LPCWSTR servername,
	DWORD level,
	DWORD filter,
	LPBYTE *bufptr,
	DWORD prefmaxlen,
	LPDWORD entriesread,
	LPDWORD totalentries,
	LPDWORD resume_handle 
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetUserEnum(servername, level, filter, bufptr, prefmaxlen, entriesread, totalentries, resume_handle);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetUserEnum", servername, NULL, NULL, NULL, 1);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetUserEnum(servername, level, filter, bufptr, prefmaxlen, entriesread, totalentries, resume_handle);
}

NET_API_STATUS NET_API_FUNCTION NetUserChangePasswordHook(
	LPCWSTR domainname,
	LPCWSTR username,
	LPCWSTR oldpassword,
	LPCWSTR newpassword
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetUserChangePassword(domainname, username, oldpassword, newpassword);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetUserChangePassword", domainname, username, oldpassword, newpassword, 4);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetUserChangePassword(domainname, username, oldpassword, newpassword);
}

NET_API_STATUS NET_API_FUNCTION NetUserGetGroupsHook(
	LPCWSTR servername,
	LPCWSTR username,
	DWORD level,
	LPBYTE *bufptr,
	DWORD prefmaxlen,
	LPDWORD entriesread,
	LPDWORD totalentries
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetUserGetGroups(servername, username, level, bufptr, prefmaxlen, entriesread, totalentries);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetUserGetGroups", servername, username, NULL, NULL, 2);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetUserGetGroups(servername, username, level, bufptr, prefmaxlen, entriesread, totalentries);
}

NET_API_STATUS NET_API_FUNCTION NetUserSetGroupsHook(
	LPCWSTR servername,
	LPCWSTR username,
	DWORD level,
	LPBYTE buf,
	DWORD num_entries
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetUserSetGroups(servername, username, level, buf, num_entries);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetUserSetGroups", servername, username, NULL, NULL, 2);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetUserSetGroups(servername, username, level, buf, num_entries);
}

NET_API_STATUS NET_API_FUNCTION NetUserGetInfoHook(
	LPCWSTR servername,
	LPCWSTR username,
	DWORD level,
	LPBYTE *bufptr
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetUserGetInfo(servername, username, level, bufptr);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetUserGetInfo", servername, username, NULL, NULL, 2);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetUserGetInfo(servername, username, level, bufptr);
}

NET_API_STATUS NET_API_FUNCTION NetUserSetInfoHook(
	LPCWSTR servername,
	LPCWSTR username,
	DWORD level,
	LPBYTE buf,
	LPDWORD parm_err 
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetUserSetInfo(servername, username, level, buf, parm_err);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetUserSetInfo", servername, username, NULL, NULL, 2);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetUserSetInfo(servername, username, level, buf, parm_err);
}

NET_API_STATUS NET_API_FUNCTION NetUserGetLocalGroupsHook(
	LPCWSTR servername,
	LPCWSTR username,
	DWORD level,
	DWORD flags,
	LPBYTE *bufptr,
	DWORD prefmaxlen,
	LPDWORD entriesread,
	LPDWORD totalentries
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetUserGetLocalGroups(servername, username, level, flags, bufptr, prefmaxlen, entriesread, totalentries);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetUserGetLocalGroups", servername, username, NULL, NULL, 2);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetUserGetLocalGroups(servername, username, level, flags, bufptr, prefmaxlen, entriesread, totalentries);
}

NET_API_STATUS NET_API_FUNCTION NetUseAddHook(
	LMSTR UncServerName,
	DWORD Level,
	LPBYTE Buf,
	LPDWORD ParmError
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetUseAdd(UncServerName, Level, Buf, ParmError);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetUseAdd", UncServerName, NULL, NULL, NULL, 1);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetUseAdd(UncServerName, Level, Buf, ParmError);
}

NET_API_STATUS NET_API_FUNCTION NetUseDelHook(
	LMSTR UncServerName,
	LMSTR UseName,
	DWORD ForceCond
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetUseDel(UncServerName, UseName, ForceCond);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetUseDel", UncServerName, UseName, NULL, NULL, 2);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetUseDel(UncServerName, UseName, ForceCond);
}

NET_API_STATUS NET_API_FUNCTION NetUseEnumHook(
	LMSTR UncServerName,
	DWORD Level,
	LPBYTE *BufPtr,
	DWORD PreferedMaximumSize,
	LPDWORD EntriesRead,
	LPDWORD TotalEntries,
	LPDWORD ResumeHandle
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetUseEnum(UncServerName, Level, BufPtr, PreferedMaximumSize, EntriesRead, TotalEntries, ResumeHandle);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetUseEnum", UncServerName, NULL, NULL, NULL, 1);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetUseEnum(UncServerName, Level, BufPtr, PreferedMaximumSize, EntriesRead, TotalEntries, ResumeHandle);
}

NET_API_STATUS NET_API_FUNCTION NetLocalGroupAddHook(
	LPCWSTR servername,
	DWORD level,
	LPBYTE buf,
	LPDWORD parm_err
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetLocalGroupAdd(servername, level, buf, parm_err);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetLocalGroupAdd", servername, NULL, NULL, NULL, 1);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetLocalGroupAdd(servername, level, buf, parm_err);
}

NET_API_STATUS NET_API_FUNCTION NetLocalGroupAddMembersHook(
    LPCWSTR servername,
    LPCWSTR groupname,
    DWORD level,
    LPBYTE buf,
    DWORD totalentries
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetLocalGroupAddMembers(servername, groupname, level, buf, totalentries);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetLocalGroupAddMembers", servername, groupname, NULL, NULL, 2);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetLocalGroupAddMembers(servername, groupname, level, buf, totalentries);
}

NET_API_STATUS NET_API_FUNCTION NetLocalGroupDelHook(
    LPCWSTR servername,
    LPCWSTR groupname
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetLocalGroupDel(servername, groupname);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetLocalGroupDel", servername, groupname, NULL, NULL, 2);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetLocalGroupDel(servername, groupname);
}

NET_API_STATUS NET_API_FUNCTION NetLocalGroupDelMembersHook(
    LPCWSTR servername,
    LPCWSTR groupname,
    DWORD level,
    LPBYTE buf,
    DWORD totalentries
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetLocalGroupDelMembers(servername, groupname, level, buf, totalentries);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetLocalGroupDelMembers", servername, groupname, NULL, NULL, 2);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetLocalGroupDelMembers(servername, groupname, level, buf, totalentries);
}

NET_API_STATUS NET_API_FUNCTION NetGroupAddHook(
    LPCWSTR servername,
    DWORD level,
    LPBYTE buf,
    LPDWORD parm_err
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetGroupAdd(servername, level, buf, parm_err);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetGroupAdd", servername, NULL, NULL, NULL, 1);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetGroupAdd(servername, level, buf, parm_err);
}

NET_API_STATUS NET_API_FUNCTION NetGroupAddUserHook(
    LPCWSTR servername,
    LPCWSTR GroupName,
    LPCWSTR username
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetGroupAddUser(servername, GroupName, username);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetGroupAddUser", servername, GroupName, username, NULL, 3);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetGroupAddUser(servername, GroupName, username);
}

NET_API_STATUS NET_API_FUNCTION NetGroupDelHook(
    LPCWSTR servername,
    LPCWSTR groupname
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetGroupDel(servername, groupname);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetGroupDel", servername, groupname, NULL, NULL, 2);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetGroupDel(servername, groupname);
}

NET_API_STATUS NET_API_FUNCTION NetGroupDelUserHook(
    LPCWSTR servername,
    LPCWSTR GroupName,
    LPCWSTR Username
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pNetGroupDelUser(servername, GroupName, Username);
		}
		Tls->ourcall = TRUE;
	}

	LogNetCallW(L"NetGroupDelUser", servername, GroupName, Username, NULL, 3);

	if ( Tls ) Tls->ourcall = FALSE;
	return pNetGroupDelUser(servername, GroupName, Username);
}