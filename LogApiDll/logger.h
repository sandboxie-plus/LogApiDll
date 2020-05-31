/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	logger.h

Abstract:

	Logger subsystem header.

	Last change 27.02.13

--*/

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#ifndef VERBOSE_BUILD
	#ifdef _M_X86
		#define LOGAPIVERSIONSTRING "LOG_API_x86 v1.04"
	#else
		#ifdef _M_X64
			#define LOGAPIVERSIONSTRING "LOG_API_x64 v1.04"
		#endif
	#endif
#else
	#ifdef _M_X86
		#define LOGAPIVERSIONSTRING "LOG_API_x86 v1.04 verbose"
	#else
		#ifdef _M_X64
			#define LOGAPIVERSIONSTRING "LOG_API_x64 v1.04 verbose"
		#endif
	#endif	
#endif

#define LOG_NORMAL 0
#define LOG_EXECUTING 1

VOID PushToLogA(
	LPCSTR lpBuffer,
	ULONG_PTR uptrSize,
	DWORD dwFlags
	);

VOID PushToLogW(
	LPWSTR lpBuffer,
	ULONG_PTR uptrSize,
	DWORD dwFlags
	);

VOID SendLog(
	PVOID lpBuffer,
	ULONG_PTR uptrSize,
	DWORD dwFlags,
	BOOL IsUnicode
	);

#ifdef __cplusplus
}
#endif //__cplusplus
