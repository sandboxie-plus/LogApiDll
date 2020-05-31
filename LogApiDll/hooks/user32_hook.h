/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	user32_hook.h

Abstract:

	Windows USER API hook interface.

	Last change 28.02.13

--*/

#ifndef _SHUSER32HOOK_
#define _SHUSER32HOOK_

#define USER32_EXCEPTION   L" user32!exception 0x"
#define USER32_EXCEPTION_A   " user32!exception 0x"

//Available since Windows 8
#ifndef SPI_GETTHREADLOCALINPUTSETTINGS
#define SPI_GETTHREADLOCALINPUTSETTINGS 0x104E
#endif

#ifndef SPI_GETSYSTEMLANGUAGEBAR
#define SPI_GETSYSTEMLANGUAGEBAR 0x1050
#endif

#ifndef SPI_SETTHREADLOCALINPUTSETTINGS
#define SPI_SETTHREADLOCALINPUTSETTINGS 0x104F
#endif

#ifndef SPI_SETSYSTEMLANGUAGEBAR
#define SPI_SETSYSTEMLANGUAGEBAR 0x1051 
#endif

typedef BOOL (WINAPI *PSystemParametersInfoA)(
	UINT uiAction,
	UINT uiParam,
	PVOID pvParam,
	UINT fWinIni
	);

typedef BOOL (WINAPI *PSystemParametersInfoW)(
	UINT uiAction,
	UINT uiParam,
	PVOID pvParam,
	UINT fWinIni
	);

typedef HHOOK (WINAPI *PSetWindowsHookExA)(
	int idHook,
	HOOKPROC lpfn,
	HINSTANCE hmod,
	DWORD dwThreadId
	);

typedef HHOOK (WINAPI *PSetWindowsHookExW)(
	int idHook,
	HOOKPROC lpfn,
	HINSTANCE hmod,
	DWORD dwThreadId
	);

typedef VOID (WINAPI *Pkeybd_event)(
	BYTE bVk,
	BYTE bScan,
	DWORD dwFlags,
	ULONG_PTR dwExtraInfo
	);

typedef SHORT (WINAPI *PGetAsyncKeyState)(
	int vKey
	);

typedef SHORT (WINAPI *PGetKeyState)(
	int nVirtKey
	);

typedef BOOL (WINAPI *PGetKeyboardState)(
    PBYTE lpKeyState
	);

typedef UINT (WINAPI *PGetRawInputData)(
    HRAWINPUT hRawInput,
    UINT uiCommand,
    LPVOID pData,
    PUINT pcbSize,
    UINT cbSizeHeader
	);

typedef BOOL (WINAPI *PPrintWindow)(
    HWND hwnd,
    HDC hdcBlt,
    UINT nFlags
	);

typedef HWND (WINAPI *PFindWindowA)(
    LPCSTR lpClassName,
    LPCSTR lpWindowName
	);

typedef HWND (WINAPI *PFindWindowW)(
    LPCWSTR lpClassName,
    LPCWSTR lpWindowName
	);

typedef HWND (WINAPI *PFindWindowExA)(
    HWND hWndParent,
    HWND hWndChildAfter,
    LPCSTR lpszClass,
    LPCSTR lpszWindow
	);

typedef HWND (WINAPI *PFindWindowExW)(
    HWND hWndParent,
    HWND hWndChildAfter,
    LPCWSTR lpszClass,
    LPCWSTR lpszWindow
	);

typedef BOOL (WINAPI *PAttachThreadInput)(
    DWORD idAttach,
    DWORD idAttachTo,
    BOOL fAttach
	);

typedef BOOL (WINAPI *PRegisterHotKey)(
    HWND hWnd,
    int id,
    UINT fsModifiers,
    UINT vk
	);

typedef BOOL (WINAPI *PSwitchDesktop)(
    HDESK hDesktop
	);

typedef HWND (WINAPI *PGetForegroundWindow)(
    VOID
	);

typedef int (WINAPI *PGetWindowTextLengthA)(
    HWND hWnd
	);

typedef int (WINAPI *PGetWindowTextLengthW)(
    HWND hWnd
	);

typedef BOOL (WINAPI *PLockWorkStation)(
    VOID
	);

typedef BOOL (WINAPI *PSetWindowPos)(
    HWND hWnd,
    HWND hWndInsertAfter,
    int X,
    int Y,
    int cx,
    int cy,
    UINT uFlags
	);

typedef UINT_PTR (WINAPI *PSetTimer)(
    HWND hWnd,
    UINT_PTR nIDEvent,
    UINT uElapse,
    TIMERPROC lpTimerFunc
	);

typedef BOOL (WINAPI *PClipCursor)(
    CONST RECT *lpRect
	);

typedef HWND (WINAPI *PSetClipboardViewer)(
    HWND hWndNewViewer
	);

typedef BOOL (WINAPI *PAddClipboardFormatListener)(
    HWND hwnd
	);

typedef int (WINAPI *PGetWindowTextA)(
    HWND hWnd,
    LPSTR lpString,
    int nMaxCount
	);

typedef int (WINAPI *PGetWindowTextW)(
    HWND hWnd,
    LPWSTR lpString,
    int nMaxCount
	);

typedef int (WINAPI *PGetClassNameA)(
    HWND hWnd,
    LPSTR lpClassName,
    int nMaxCount
    );

typedef int (WINAPI *PGetClassNameW)(
    HWND hWnd,
    LPWSTR lpClassName,
    int nMaxCount
    );

typedef LRESULT (WINAPI *PSendMessageA)(
    HWND hWnd,
    UINT Msg,
    WPARAM wParam,
    LPARAM lParam
	);

typedef LRESULT (WINAPI *PSendMessageW)(
    HWND hWnd,
    UINT Msg,
    WPARAM wParam,
    LPARAM lParam
	);

typedef LRESULT (WINAPI *PSendMessageTimeoutA)(
    HWND hWnd,
    UINT Msg,
    WPARAM wParam,
    LPARAM lParam,
    UINT fuFlags,
    UINT uTimeout,
    PDWORD_PTR lpdwResult
	);

typedef LRESULT (WINAPI *PSendMessageTimeoutW)(
    HWND hWnd,
    UINT Msg,
    WPARAM wParam,
    LPARAM lParam,
    UINT fuFlags,
    UINT uTimeout,
    PDWORD_PTR lpdwResult
	);

typedef int (WINAPI *PInternalGetWindowText)(
    HWND hWnd,
    LPWSTR pString,
    int cchMaxCount
	);

typedef int (WINAPI *PGetKeyboardLayoutList)(
	int nBuff,
	HKL *lpList
	);

typedef HDESK (WINAPI *PCreateDesktopA)(
    LPCSTR lpszDesktop,
    LPCSTR lpszDevice,
    DEVMODEA* pDevmode,
    DWORD dwFlags,
    ACCESS_MASK dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpsa
	);

typedef HDESK (WINAPI *PCreateDesktopW)(
    LPCWSTR lpszDesktop,
    LPCWSTR lpszDevice,
    DEVMODEW* pDevmode,
    DWORD dwFlags,
    ACCESS_MASK dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpsa
	);

typedef HDESK (WINAPI *PCreateDesktopExA)(
    LPCSTR lpszDesktop,
    LPCSTR lpszDevice,
    DEVMODEA* pDevmode,
    DWORD dwFlags,
    ACCESS_MASK dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpsa,
    ULONG ulHeapSize,
    PVOID pvoid
	);

typedef HDESK (WINAPI *PCreateDesktopExW)(
    LPCWSTR lpszDesktop,
    LPCWSTR lpszDevice,
    DEVMODEW* pDevmode,
    DWORD dwFlags,
    ACCESS_MASK dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpsa,
    ULONG ulHeapSize,
    PVOID pvoid
	);

extern PSystemParametersInfoA pSystemParametersInfoA;
extern PSystemParametersInfoW pSystemParametersInfoW;
extern PSetWindowsHookExA pSetWindowsHookExA;
extern PSetWindowsHookExW pSetWindowsHookExW;
extern Pkeybd_event pkeybd_event;
extern PGetAsyncKeyState pGetAsyncKeyState;
extern PGetKeyState pGetKeyState;
extern PGetKeyboardState pGetKeyboardState;
extern PGetRawInputData pGetRawInputData;
extern PPrintWindow pPrintWindow;
extern PFindWindowA pFindWindowA;
extern PFindWindowW pFindWindowW;
extern PFindWindowExA pFindWindowExA;
extern PFindWindowExW pFindWindowExW;
extern PAttachThreadInput pAttachThreadInput;
extern PRegisterHotKey pRegisterHotKey;
extern PSwitchDesktop pSwitchDesktop;
extern PGetKeyboardLayoutList pGetKeyboardLayoutList;
extern PGetForegroundWindow pGetForegroundWindow;
extern PGetWindowTextLengthA pGetWindowTextLengthA;
extern PGetWindowTextLengthW pGetWindowTextLengthW;
extern PLockWorkStation pLockWorkStation;
extern PSetWindowPos pSetWindowPos;
extern PSetTimer pSetTimer;
extern PClipCursor pClipCursor;
extern PSetClipboardViewer pSetClipboardViewer;
extern PAddClipboardFormatListener pAddClipboardFormatListener;
extern PGetWindowTextA pGetWindowTextA;
extern PGetWindowTextW pGetWindowTextW;
extern PGetClassNameA pGetClassNameA;
extern PGetClassNameW pGetClassNameW;
extern PSendMessageA pSendMessageA;
extern PSendMessageW pSendMessageW;
extern PSendMessageTimeoutA pSendMessageTimeoutA;
extern PSendMessageTimeoutW pSendMessageTimeoutW;
extern PInternalGetWindowText pInternalGetWindowText;
extern PCreateDesktopA pCreateDesktopA;
extern PCreateDesktopW pCreateDesktopW;
extern PCreateDesktopExA pCreateDesktopExA;
extern PCreateDesktopExW pCreateDesktopExW;

BOOL WINAPI SystemParametersInfoHookA(
	UINT uiAction,
	UINT uiParam,
	PVOID pvParam,
	UINT fWinIni
	);

BOOL WINAPI SystemParametersInfoHookW(
	UINT uiAction,
	UINT uiParam,
	PVOID pvParam,
	UINT fWinIni
	);

HHOOK WINAPI SetWindowsHookExHookA(
	int idHook,
	HOOKPROC lpfn,
	HINSTANCE hmod,
	DWORD dwThreadId
	);

HHOOK WINAPI SetWindowsHookExHookW(
	int idHook,
	HOOKPROC lpfn,
	HINSTANCE hmod,
	DWORD dwThreadId
	);

VOID WINAPI keybd_eventHook(
	BYTE bVk,
	BYTE bScan,
	DWORD dwFlags,
	ULONG_PTR dwExtraInfo
	);

SHORT WINAPI GetAsyncKeyStateHook(
	int vKey
	);

SHORT WINAPI GetKeyStateHook(
	int nVirtKey
	);

BOOL WINAPI GetKeyboardStateHook(
    PBYTE lpKeyState
	);

UINT WINAPI GetRawInputDataHook(
    HRAWINPUT hRawInput,
    UINT uiCommand,
    LPVOID pData,
    PUINT pcbSize,
    UINT cbSizeHeader
	);

BOOL WINAPI PrintWindowHook(
    HWND hwnd,
    HDC hdcBlt,
    UINT nFlags
	);

HWND WINAPI SetClipboardViewerHook(
    HWND hWndNewViewer
	);

BOOL WINAPI AddClipboardFormatListenerHook(
    HWND hwnd
	);

BOOL WINAPI LockWorkStationHook(
    VOID
	);

int WINAPI GetWindowTextLengthHookA(
    HWND hWnd
	);

int WINAPI GetWindowTextLengthHookW(
    HWND hWnd
	);

HWND WINAPI GetForegroundWindowHook(
    VOID
	);

BOOL WINAPI AttachThreadInputHook(
    DWORD idAttach,
    DWORD idAttachTo,
    BOOL fAttach
	);

BOOL WINAPI SetWindowPosHook(
    HWND hWnd,
    HWND hWndInsertAfter,
    int X,
    int Y,
    int cx,
    int cy,
    UINT uFlags
	);

UINT_PTR WINAPI SetTimerHook(
    HWND hWnd,
    UINT_PTR nIDEvent,
    UINT uElapse,
    TIMERPROC lpTimerFunc
	);

BOOL WINAPI RegisterHotKeyHook(
    HWND hWnd,
    int id,
    UINT fsModifiers,
    UINT vk
	);

BOOL WINAPI ClipCursorHook(
    CONST RECT *lpRect
	);

BOOL WINAPI SwitchDesktopHook(
    HDESK hDesktop
	);

int WINAPI GetKeyboardLayoutListHook(
	int nBuff,
	HKL *lpList
	);

HWND WINAPI FindWindowHookA(
    LPCSTR lpClassName,
    LPCSTR lpWindowName
	);

HWND WINAPI FindWindowHookW(
    LPCWSTR lpClassName,
    LPCWSTR lpWindowName
	);

HWND WINAPI FindWindowExHookA(
    HWND hWndParent,
    HWND hWndChildAfter,
    LPCSTR lpszClass,
    LPCSTR lpszWindow
	);

HWND WINAPI FindWindowExHookW(
    HWND hWndParent,
    HWND hWndChildAfter,
    LPCWSTR lpszClass,
    LPCWSTR lpszWindow
	);

DWORD WINAPI GetWindowThreadProcessIdHook(
    HWND hWnd,
    LPDWORD lpdwProcessId
	);

int WINAPI GetWindowTextHookA(
    HWND hWnd,
    LPSTR lpString,
    int nMaxCount
	);

int WINAPI GetWindowTextHookW(
    HWND hWnd,
    LPWSTR lpString,
    int nMaxCount
	);

int WINAPI GetClassNameHookA(
    HWND hWnd,
    LPSTR lpClassName,
    int nMaxCount
    );

int WINAPI GetClassNameHookW(
    HWND hWnd,
    LPWSTR lpClassName,
    int nMaxCount
    );

LRESULT WINAPI SendMessageHookA(
    HWND hWnd,
    UINT Msg,
    WPARAM wParam,
    LPARAM lParam
	);

LRESULT WINAPI SendMessageHookW(
    HWND hWnd,
    UINT Msg,
    WPARAM wParam,
    LPARAM lParam
	);

LRESULT WINAPI SendMessageTimeoutHookA(
    HWND hWnd,
    UINT Msg,
    WPARAM wParam,
    LPARAM lParam,
    UINT fuFlags,
    UINT uTimeout,
    PDWORD_PTR lpdwResult
	);

LRESULT WINAPI SendMessageTimeoutHookW(
    HWND hWnd,
    UINT Msg,
    WPARAM wParam,
    LPARAM lParam,
    UINT fuFlags,
    UINT uTimeout,
    PDWORD_PTR lpdwResult
	);

int WINAPI InternalGetWindowTextHook(
    HWND hWnd,
    LPWSTR pString,
    int cchMaxCount
	);

HDESK WINAPI CreateDesktopHookA(
    LPCSTR lpszDesktop,
    LPCSTR lpszDevice,
    DEVMODEA* pDevmode,
    DWORD dwFlags,
    ACCESS_MASK dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpsa
	);

HDESK WINAPI CreateDesktopHookW(
    LPCWSTR lpszDesktop,
    LPCWSTR lpszDevice,
    DEVMODEW* pDevmode,
    DWORD dwFlags,
    ACCESS_MASK dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpsa
	);

HDESK WINAPI CreateDesktopExHookA(
    LPCSTR lpszDesktop,
    LPCSTR lpszDevice,
    DEVMODEA* pDevmode,
    DWORD dwFlags,
    ACCESS_MASK dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpsa,
    ULONG ulHeapSize,
    PVOID pvoid
	);

HDESK WINAPI CreateDesktopExHookW(
    LPCWSTR lpszDesktop,
    LPCWSTR lpszDevice,
    DEVMODEW* pDevmode,
    DWORD dwFlags,
    ACCESS_MASK dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpsa,
    ULONG ulHeapSize,
    PVOID pvoid
	);

#endif /* _SHUSER32HOOK_ */