/*++

Copyright (c) Project Authors, 2013 (see AUTHORS.txt).  

Module Name:

	user32_hook.c

Abstract:

	Windows USER API hook implementation.

	Last change 28.02.13

--*/

#include "..\global.h"
#include "user32_hook.h"

PSystemParametersInfoA pSystemParametersInfoA = NULL;
PSystemParametersInfoW pSystemParametersInfoW = NULL;
PSetWindowsHookExA pSetWindowsHookExA = NULL;
PSetWindowsHookExW pSetWindowsHookExW = NULL;
Pkeybd_event pkeybd_event = NULL;
PGetAsyncKeyState pGetAsyncKeyState = NULL;
PGetKeyState pGetKeyState = NULL;
PGetKeyboardState pGetKeyboardState = NULL;
PGetRawInputData pGetRawInputData = NULL;
PPrintWindow pPrintWindow = NULL;
PFindWindowA pFindWindowA = NULL;
PFindWindowW pFindWindowW = NULL;
PFindWindowExA pFindWindowExA = NULL;
PFindWindowExW pFindWindowExW = NULL;
PAttachThreadInput pAttachThreadInput = NULL;
PRegisterHotKey pRegisterHotKey = NULL;
PSwitchDesktop pSwitchDesktop = NULL;
PGetKeyboardLayoutList pGetKeyboardLayoutList = NULL;
PGetForegroundWindow pGetForegroundWindow = NULL;
PGetWindowTextLengthA pGetWindowTextLengthA = NULL;
PGetWindowTextLengthW pGetWindowTextLengthW = NULL;
PLockWorkStation pLockWorkStation = NULL;
PSetWindowPos pSetWindowPos = NULL;
PSetTimer pSetTimer = NULL;
PClipCursor pClipCursor = NULL;
PSetClipboardViewer pSetClipboardViewer = NULL;
PAddClipboardFormatListener pAddClipboardFormatListener = NULL;
PGetWindowTextA pGetWindowTextA = NULL;
PGetWindowTextW pGetWindowTextW = NULL;
PGetClassNameA pGetClassNameA = NULL;
PGetClassNameW pGetClassNameW = NULL;
PSendMessageA pSendMessageA = NULL;
PSendMessageW pSendMessageW = NULL;
PSendMessageTimeoutA pSendMessageTimeoutA = NULL;
PSendMessageTimeoutW pSendMessageTimeoutW = NULL;
PInternalGetWindowText pInternalGetWindowText = NULL;
PCreateDesktopA pCreateDesktopA = NULL;
PCreateDesktopW pCreateDesktopW = NULL;
PCreateDesktopExA pCreateDesktopExA = NULL;
PCreateDesktopExW pCreateDesktopExW = NULL;

VOID LogPutSystemParametersInfoA(
	UINT uiAction,
	LPSTR Buffer
	)
{
	LPSTR lpParam = NULL; 
	
	if (!ARGUMENT_PRESENT(Buffer)) 
		return;

	switch ( uiAction ) {

	case SPI_GETSYSTEMLANGUAGEBAR:
		lpParam = "SPI_GETSYSTEMLANGUAGEBAR";
		break;
	case SPI_GETACCESSTIMEOUT:
		lpParam = "SPI_GETACCESSTIMEOUT";
		break;
	case SPI_GETAUDIODESCRIPTION:
		lpParam = "SPI_GETAUDIODESCRIPTION";
		break;
	case SPI_GETCLIENTAREAANIMATION:
		lpParam = "SPI_GETCLIENTAREAANIMATION";
		break;
	case SPI_GETDISABLEOVERLAPPEDCONTENT:
		lpParam = "SPI_GETDISABLEOVERLAPPEDCONTENT";
		break;
	case SPI_GETFILTERKEYS:
		lpParam = "SPI_GETFILTERKEYS";
		break;
	case SPI_GETFOCUSBORDERHEIGHT:
		lpParam = "SPI_GETFOCUSBORDERHEIGHT";
		break;
	case SPI_GETFOCUSBORDERWIDTH:
		lpParam = "SPI_GETFOCUSBORDERWIDTH";
		break;
	case SPI_GETHIGHCONTRAST:
		lpParam = "SPI_GETHIGHCONTRAST";
		break;
	case SPI_GETMESSAGEDURATION:
		lpParam = "SPI_GETMESSAGEDURATION";
		break;
	case SPI_GETMOUSECLICKLOCK:
		lpParam = "SPI_GETMOUSECLICKLOCK";
		break;
	case SPI_GETMOUSECLICKLOCKTIME:
		lpParam = "SPI_GETMOUSECLICKLOCKTIME";
		break;
	case SPI_GETMOUSEKEYS:
		lpParam = "SPI_GETMOUSEKEYS";
		break;
	case SPI_GETMOUSESONAR:
		lpParam = "SPI_GETMOUSESONAR";
		break;
	case SPI_GETMOUSEVANISH:
		lpParam = "SPI_GETMOUSEVANISH";
		break;
	case SPI_GETSCREENREADER:
		lpParam = "SPI_GETSCREENREADER";
		break;
	case SPI_GETSERIALKEYS:
		lpParam = "SPI_GETSERIALKEYS";
		break;
	case SPI_GETSHOWSOUNDS:
		lpParam = "SPI_GETSHOWSOUNDS";
		break;
	case SPI_GETSOUNDSENTRY:
		lpParam = "SPI_GETSOUNDSENTRY";
		break;
	case SPI_GETSTICKYKEYS:
		lpParam = "SPI_GETSTICKYKEYS";
		break;
	case SPI_GETTOGGLEKEYS:
		lpParam = "SPI_GETTOGGLEKEYS";
		break;
	case SPI_SETACCESSTIMEOUT:
		lpParam = "SPI_SETACCESSTIMEOUT";
		break;
	case SPI_SETAUDIODESCRIPTION:
		lpParam = "SPI_SETAUDIODESCRIPTION";
		break;
	case SPI_SETCLIENTAREAANIMATION:
		lpParam = "SPI_SETCLIENTAREAANIMATION";
		break;
	case SPI_SETDISABLEOVERLAPPEDCONTENT:
		lpParam = "SPI_SETDISABLEOVERLAPPEDCONTENT";
		break;
	case SPI_SETFILTERKEYS:
		lpParam = "SPI_SETFILTERKEYS";
		break;
	case SPI_SETFOCUSBORDERHEIGHT:
		lpParam = "SPI_SETFOCUSBORDERHEIGHT";
		break;
	case SPI_SETFOCUSBORDERWIDTH:
		lpParam = "SPI_SETFOCUSBORDERWIDTH";
		break;
	case SPI_SETHIGHCONTRAST:
		lpParam = "SPI_SETHIGHCONTRAST";
		break;
	case SPI_SETMESSAGEDURATION:
		lpParam = "SPI_SETMESSAGEDURATION";
		break;
	case SPI_SETMOUSECLICKLOCK:
		lpParam = "SPI_SETMOUSECLICKLOCK";
		break;
	case SPI_SETMOUSECLICKLOCKTIME:
		lpParam = "SPI_SETMOUSECLICKLOCKTIME";
		break;
	case SPI_SETMOUSEKEYS:
		lpParam = "SPI_SETMOUSEKEYS";
		break;
	case SPI_SETMOUSESONAR:
		lpParam = "SPI_SETMOUSESONAR";
		break;
	case SPI_SETMOUSEVANISH:
		lpParam = "SPI_SETMOUSEVANISH";
		break;
	case SPI_SETSCREENREADER:
		lpParam = "SPI_SETSCREENREADER";
		break;
	case SPI_SETSERIALKEYS:
		lpParam = "SPI_SETSERIALKEYS";
		break;
	case SPI_SETSHOWSOUNDS:
		lpParam = "SPI_SETSHOWSOUNDS";
		break;
	case SPI_SETSOUNDSENTRY:
		lpParam = "SPI_SETSOUNDSENTRY";
		break;
	case SPI_SETSTICKYKEYS:
		lpParam = "SPI_SETSTICKYKEYS";
		break;
	case SPI_SETTOGGLEKEYS:
		lpParam = "SPI_SETTOGGLEKEYS";
		break;
	case SPI_GETCLEARTYPE:
		lpParam = "SPI_GETCLEARTYPE";
		break;
	case SPI_GETDESKWALLPAPER:
		lpParam = "SPI_GETDESKWALLPAPER";
		break;
	case SPI_GETDROPSHADOW:
		lpParam = "SPI_GETDROPSHADOW";
		break;
	case SPI_GETFLATMENU:
		lpParam = "SPI_GETFLATMENU";
		break;
	case SPI_GETFONTSMOOTHING:
		lpParam = "SPI_GETFONTSMOOTHING";
		break;
	case SPI_GETFONTSMOOTHINGCONTRAST:
		lpParam = "SPI_GETFONTSMOOTHINGCONTRAST";
		break;
	case SPI_GETFONTSMOOTHINGORIENTATION:
		lpParam = "SPI_GETFONTSMOOTHINGORIENTATION";
		break;
	case SPI_GETFONTSMOOTHINGTYPE:
		lpParam = "SPI_GETFONTSMOOTHINGTYPE";
		break;
	case SPI_GETWORKAREA:
		lpParam = "SPI_GETWORKAREA";
		break;
	case SPI_SETCLEARTYPE:
		lpParam = "SPI_SETCLEARTYPE";
		break;
	case SPI_SETCURSORS:
		lpParam = "SPI_SETCURSORS";
		break;
	case SPI_SETDESKPATTERN:
		lpParam = "SPI_SETDESKPATTERN";
		break;
	case SPI_SETDESKWALLPAPER:
		lpParam = "SPI_SETDESKWALLPAPER";
		break;
	case SPI_SETDROPSHADOW:
		lpParam = "SPI_SETDROPSHADOW";
		break;
	case SPI_SETFLATMENU:
		lpParam = "SPI_SETFLATMENU";
		break;
	case SPI_SETFONTSMOOTHING:
		lpParam = "SPI_SETFONTSMOOTHING";
		break;
	case SPI_SETFONTSMOOTHINGCONTRAST:
		lpParam = "SPI_SETFONTSMOOTHINGCONTRAST";
		break;
	case SPI_SETFONTSMOOTHINGORIENTATION:
		lpParam = "SPI_SETFONTSMOOTHINGORIENTATION";
		break;
	case SPI_SETFONTSMOOTHINGTYPE:
		lpParam = "SPI_SETFONTSMOOTHINGTYPE";
		break;
	case SPI_SETWORKAREA:
		lpParam = "SPI_SETWORKAREA";
		break;
	case SPI_GETICONMETRICS:
		lpParam = "SPI_GETICONMETRICS";
		break;
	case SPI_GETICONTITLELOGFONT:
		lpParam = "SPI_GETICONTITLELOGFONT";
		break;
	case SPI_GETICONTITLEWRAP:
		lpParam = "SPI_GETICONTITLEWRAP";
		break;
	case SPI_ICONHORIZONTALSPACING:
		lpParam = "SPI_ICONHORIZONTALSPACING";
		break;
	case SPI_ICONVERTICALSPACING:
		lpParam = "SPI_ICONVERTICALSPACING";
		break;
	case SPI_SETICONMETRICS:
		lpParam = "SPI_SETICONMETRICS";
		break;
	case SPI_SETICONS:
		lpParam = "SPI_SETICONS";
		break;
	case SPI_SETICONTITLELOGFONT:
		lpParam = "SPI_SETICONTITLELOGFONT";
		break;
	case SPI_SETICONTITLEWRAP:
		lpParam = "SPI_SETICONTITLEWRAP";
		break;
	case SPI_GETBEEP:
		lpParam = "SPI_GETBEEP";
		break;
	case SPI_GETBLOCKSENDINPUTRESETS:
		lpParam = "SPI_GETBLOCKSENDINPUTRESETS";
		break;
	case SPI_GETDEFAULTINPUTLANG:
		lpParam = "SPI_GETDEFAULTINPUTLANG";
		break;
	case SPI_GETKEYBOARDCUES:
		lpParam = "SPI_GETKEYBOARDCUES";
		break;
	case SPI_GETKEYBOARDDELAY:
		lpParam = "SPI_GETKEYBOARDDELAY";
		break;
	case SPI_GETKEYBOARDPREF:
		lpParam = "SPI_GETKEYBOARDPREF";
		break;
	case SPI_GETKEYBOARDSPEED:
		lpParam = "SPI_GETKEYBOARDSPEED";
		break;
	case SPI_GETMOUSE:
		lpParam = "SPI_GETMOUSE";
		break;
	case SPI_GETMOUSEHOVERHEIGHT:
		lpParam = "SPI_GETMOUSEHOVERHEIGHT";
		break;
	case SPI_GETMOUSEHOVERTIME:
		lpParam = "SPI_GETMOUSEHOVERTIME";
		break;
	case SPI_GETMOUSEHOVERWIDTH:
		lpParam = "SPI_GETMOUSEHOVERWIDTH";
		break;
	case SPI_GETMOUSESPEED:
		lpParam = "SPI_GETMOUSESPEED";
		break;
	case SPI_GETMOUSETRAILS:
		lpParam = "SPI_GETMOUSETRAILS";
		break;
	case SPI_GETSNAPTODEFBUTTON:
		lpParam = "SPI_GETSNAPTODEFBUTTON";
		break;
	case SPI_GETTHREADLOCALINPUTSETTINGS:
		lpParam = "SPI_GETTHREADLOCALINPUTSETTINGS";
		break;
	case SPI_GETWHEELSCROLLCHARS:
		lpParam = "SPI_GETWHEELSCROLLCHARS";
		break;
	case SPI_GETWHEELSCROLLLINES:
		lpParam = "SPI_GETWHEELSCROLLLINES";
		break;
	case SPI_SETBEEP:
		lpParam = "SPI_SETBEEP";
		break;
	case SPI_SETBLOCKSENDINPUTRESETS:
		lpParam = "SPI_SETBLOCKSENDINPUTRESETS";
		break;
	case SPI_SETDEFAULTINPUTLANG:
		lpParam = "SPI_SETDEFAULTINPUTLANG";
		break;
	case SPI_SETDOUBLECLICKTIME:
		lpParam = "SPI_SETDOUBLECLICKTIME";
		break;
	case SPI_SETDOUBLECLKHEIGHT:
		lpParam = "SPI_SETDOUBLECLKHEIGHT";
		break;
	case SPI_SETDOUBLECLKWIDTH:
		lpParam = "SPI_SETDOUBLECLKWIDTH";
		break;
	case SPI_SETKEYBOARDCUES:
		lpParam = "SPI_SETKEYBOARDCUES";
		break;
	case SPI_SETKEYBOARDDELAY:
		lpParam = "SPI_SETKEYBOARDDELAY";
		break;
	case SPI_SETKEYBOARDPREF:
		lpParam = "SPI_SETKEYBOARDPREF";
		break;
	case SPI_SETKEYBOARDSPEED:
		lpParam = "SPI_SETKEYBOARDSPEED";
		break;
	case SPI_SETLANGTOGGLE:
		lpParam = "SPI_SETLANGTOGGLE";
		break;
	case SPI_SETMOUSE:
		lpParam = "SPI_SETMOUSE";
		break;
	case SPI_SETMOUSEBUTTONSWAP:
		lpParam = "SPI_SETMOUSEBUTTONSWAP";
		break;
	case SPI_SETMOUSEHOVERHEIGHT:
		lpParam = "SPI_SETMOUSEHOVERHEIGHT";
		break;
	case SPI_SETMOUSEHOVERTIME:
		lpParam = "SPI_SETMOUSEHOVERTIME";
		break;
	case SPI_SETMOUSEHOVERWIDTH:
		lpParam = "SPI_SETMOUSEHOVERWIDTH";
		break;
	case SPI_SETMOUSESPEED:
		lpParam = "SPI_SETMOUSESPEED";
		break;
	case SPI_SETMOUSETRAILS:
		lpParam = "SPI_SETMOUSETRAILS";
		break;
	case SPI_SETSNAPTODEFBUTTON:
		lpParam = "SPI_SETSNAPTODEFBUTTON";
		break;
	case SPI_SETSYSTEMLANGUAGEBAR:
		lpParam = "SPI_SETSYSTEMLANGUAGEBAR";
		break;
	case SPI_SETTHREADLOCALINPUTSETTINGS:
		lpParam = "SPI_SETTHREADLOCALINPUTSETTINGS";
		break;
	case SPI_SETWHEELSCROLLCHARS:
		lpParam = "SPI_SETWHEELSCROLLCHARS";
		break;
	case SPI_SETWHEELSCROLLLINES:
		lpParam = "SPI_SETWHEELSCROLLLINES";
		break;
	case SPI_GETMENUDROPALIGNMENT:
		lpParam = "SPI_GETMENUDROPALIGNMENT";
		break;
	case SPI_GETMENUFADE:
		lpParam = "SPI_GETMENUFADE";
		break;
	case SPI_GETMENUSHOWDELAY:
		lpParam = "SPI_GETMENUSHOWDELAY";
		break;
	case SPI_SETMENUDROPALIGNMENT:
		lpParam = "SPI_SETMENUDROPALIGNMENT";
		break;
	case SPI_SETMENUFADE:
		lpParam = "SPI_SETMENUFADE";
		break;
	case SPI_SETMENUSHOWDELAY:
		lpParam = "SPI_SETMENUSHOWDELAY";
		break;
	case SPI_GETLOWPOWERACTIVE:
		lpParam = "SPI_GETLOWPOWERACTIVE";
		break;
	case SPI_GETLOWPOWERTIMEOUT:
		lpParam = "SPI_GETLOWPOWERTIMEOUT";
		break;
	case SPI_GETPOWEROFFACTIVE:
		lpParam = "SPI_GETPOWEROFFACTIVE";
		break;
	case SPI_GETPOWEROFFTIMEOUT:
		lpParam = "SPI_GETPOWEROFFTIMEOUT";
		break;
	case SPI_SETLOWPOWERACTIVE:
		lpParam = "SPI_SETLOWPOWERACTIVE";
		break;
	case SPI_SETLOWPOWERTIMEOUT:
		lpParam = "SPI_SETLOWPOWERTIMEOUT";
		break;
	case SPI_SETPOWEROFFACTIVE:
		lpParam = "SPI_SETPOWEROFFACTIVE";
		break;
	case SPI_SETPOWEROFFTIMEOUT:
		lpParam = "SPI_SETPOWEROFFTIMEOUT";
		break;
	case SPI_GETSCREENSAVEACTIVE:
		lpParam = "SPI_GETSCREENSAVEACTIVE";
		break;
	case SPI_GETSCREENSAVERRUNNING:
		lpParam = "SPI_GETSCREENSAVERRUNNING";
		break;
	case SPI_GETSCREENSAVESECURE:
		lpParam = "SPI_GETSCREENSAVESECURE";
		break;
	case SPI_GETSCREENSAVETIMEOUT:
		lpParam = "SPI_GETSCREENSAVETIMEOUT";
		break;
	case SPI_SETSCREENSAVEACTIVE:
		lpParam = "SPI_SETSCREENSAVEACTIVE";
		break;
	case SPI_SETSCREENSAVESECURE:
		lpParam = "SPI_SETSCREENSAVESECURE";
		break;
	case SPI_SETSCREENSAVETIMEOUT:
		lpParam = "SPI_SETSCREENSAVETIMEOUT";
		break;
	case SPI_GETHUNGAPPTIMEOUT:
		lpParam = "SPI_GETHUNGAPPTIMEOUT";
		break;
	case SPI_GETWAITTOKILLTIMEOUT:
		lpParam = "SPI_GETWAITTOKILLTIMEOUT";
		break;
	case SPI_GETWAITTOKILLSERVICETIMEOUT:
		lpParam = "SPI_GETWAITTOKILLSERVICETIMEOUT";
		break;
	case SPI_SETHUNGAPPTIMEOUT:
		lpParam = "SPI_SETHUNGAPPTIMEOUT";
		break;
	case SPI_SETWAITTOKILLTIMEOUT:
		lpParam = "SPI_SETWAITTOKILLTIMEOUT";
		break;
	case SPI_SETWAITTOKILLSERVICETIMEOUT:
		lpParam = "SPI_SETWAITTOKILLSERVICETIMEOUT";
		break;
	case SPI_GETCOMBOBOXANIMATION:
		lpParam = "SPI_GETCOMBOBOXANIMATION";
		break;
	case SPI_GETCURSORSHADOW:
		lpParam = "SPI_GETCURSORSHADOW";
		break;
	case SPI_GETGRADIENTCAPTIONS:
		lpParam = "SPI_GETGRADIENTCAPTIONS";
		break;
	case SPI_GETHOTTRACKING:
		lpParam = "SPI_GETHOTTRACKING";
		break;
	case SPI_GETLISTBOXSMOOTHSCROLLING:
		lpParam = "SPI_GETLISTBOXSMOOTHSCROLLING";
		break;
	case SPI_GETMENUANIMATION:
		lpParam = "SPI_GETMENUANIMATION";
		break;
	case SPI_GETSELECTIONFADE:
		lpParam = "SPI_GETSELECTIONFADE";
		break;
	case SPI_GETTOOLTIPANIMATION:
		lpParam = "SPI_GETTOOLTIPANIMATION";
		break;
	case SPI_GETTOOLTIPFADE:
		lpParam = "SPI_GETTOOLTIPFADE";
		break;
	case SPI_GETUIEFFECTS:
		lpParam = "SPI_GETUIEFFECTS";
		break;
	case SPI_SETCOMBOBOXANIMATION:
		lpParam = "SPI_SETCOMBOBOXANIMATION";
		break;
	case SPI_SETCURSORSHADOW:
		lpParam = "SPI_SETCURSORSHADOW";
		break;
	case SPI_SETGRADIENTCAPTIONS:
		lpParam = "SPI_SETGRADIENTCAPTIONS";
		break;
	case SPI_SETHOTTRACKING:
		lpParam = "SPI_SETHOTTRACKING";
		break;
	case SPI_SETLISTBOXSMOOTHSCROLLING:
		lpParam = "SPI_SETLISTBOXSMOOTHSCROLLING";
		break;
	case SPI_SETMENUANIMATION:
		lpParam = "SPI_SETMENUANIMATION";
		break;
	case SPI_SETSELECTIONFADE:
		lpParam = "SPI_SETSELECTIONFADE";
		break;
	case SPI_SETTOOLTIPANIMATION:
		lpParam = "SPI_SETTOOLTIPANIMATION";
		break;
	case SPI_SETTOOLTIPFADE:
		lpParam = "SPI_SETTOOLTIPFADE";
		break;
	case SPI_SETUIEFFECTS:
		lpParam = "SPI_SETUIEFFECTS";
		break;
	case SPI_GETACTIVEWINDOWTRACKING:
		lpParam = "SPI_GETACTIVEWINDOWTRACKING";
		break;
	case SPI_GETACTIVEWNDTRKZORDER:
		lpParam = "SPI_GETACTIVEWNDTRKZORDER";
		break;
	case SPI_GETACTIVEWNDTRKTIMEOUT:
		lpParam = "SPI_GETACTIVEWNDTRKTIMEOUT";
		break;
	case SPI_GETANIMATION:
		lpParam = "SPI_GETANIMATION";
		break;
	case SPI_GETBORDER:
		lpParam = "SPI_GETBORDER";
		break;
	case SPI_GETCARETWIDTH:
		lpParam = "SPI_GETCARETWIDTH";
		break;
	case SPI_GETDOCKMOVING:
		lpParam = "SPI_GETDOCKMOVING";
		break;
	case SPI_GETDRAGFROMMAXIMIZE:
		lpParam = "SPI_GETDRAGFROMMAXIMIZE";
		break;
	case SPI_GETDRAGFULLWINDOWS:
		lpParam = "SPI_GETDRAGFULLWINDOWS";
		break;
	case SPI_GETFOREGROUNDFLASHCOUNT:
		lpParam = "SPI_GETFOREGROUNDFLASHCOUNT";
		break;
	case SPI_GETFOREGROUNDLOCKTIMEOUT:
		lpParam = "SPI_GETFOREGROUNDLOCKTIMEOUT";
		break;
	case SPI_GETMINIMIZEDMETRICS:
		lpParam = "SPI_GETMINIMIZEDMETRICS";
		break;
	case SPI_GETMOUSEDOCKTHRESHOLD:
		lpParam = "SPI_GETMOUSEDOCKTHRESHOLD";
		break;
	case SPI_GETMOUSEDRAGOUTTHRESHOLD:
		lpParam = "SPI_GETMOUSEDRAGOUTTHRESHOLD";
		break;
	case SPI_GETMOUSESIDEMOVETHRESHOLD:
		lpParam = "SPI_GETMOUSESIDEMOVETHRESHOLD";
		break;
	case SPI_GETNONCLIENTMETRICS:
		lpParam = "SPI_GETNONCLIENTMETRICS";
		break;
	case SPI_GETPENDOCKTHRESHOLD:
		lpParam = "SPI_GETPENDOCKTHRESHOLD";
		break;
	case SPI_GETPENDRAGOUTTHRESHOLD:
		lpParam = "SPI_GETPENDRAGOUTTHRESHOLD";
		break;
	case SPI_GETPENSIDEMOVETHRESHOLD:
		lpParam = "SPI_GETPENSIDEMOVETHRESHOLD";
		break;
	case SPI_GETSHOWIMEUI:
		lpParam = "SPI_GETSHOWIMEUI";
		break;
	case SPI_GETSNAPSIZING:
		lpParam = "SPI_GETSNAPSIZING";
		break;
	case SPI_GETWINARRANGING:
		lpParam = "SPI_GETWINARRANGING";
		break;
	case SPI_SETACTIVEWINDOWTRACKING:
		lpParam = "SPI_SETACTIVEWINDOWTRACKING";
		break;
	case SPI_SETACTIVEWNDTRKZORDER:
		lpParam = "SPI_SETACTIVEWNDTRKZORDER";
		break;
	case SPI_SETACTIVEWNDTRKTIMEOUT:
		lpParam = "SPI_SETACTIVEWNDTRKTIMEOUT";
		break;
	case SPI_SETANIMATION:
		lpParam = "SPI_SETANIMATION";
		break;
	case SPI_SETBORDER:
		lpParam = "SPI_SETBORDER";
		break;
	case SPI_SETCARETWIDTH:
		lpParam = "SPI_SETCARETWIDTH";
		break;
	case SPI_SETDOCKMOVING:
		lpParam = "SPI_SETDOCKMOVING";
		break;
	case SPI_SETDRAGFROMMAXIMIZE:
		lpParam = "SPI_SETDRAGFROMMAXIMIZE";
		break;
	case SPI_SETDRAGFULLWINDOWS:
		lpParam = "SPI_SETDRAGFULLWINDOWS";
		break;
	case SPI_SETDRAGHEIGHT:
		lpParam = "SPI_SETDRAGHEIGHT";
		break;
	case SPI_SETDRAGWIDTH:
		lpParam = "SPI_SETDRAGWIDTH";
		break;
	case SPI_SETFOREGROUNDFLASHCOUNT:
		lpParam = "SPI_SETFOREGROUNDFLASHCOUNT";
		break;
	case SPI_SETFOREGROUNDLOCKTIMEOUT:
		lpParam = "SPI_SETFOREGROUNDLOCKTIMEOUT";
		break;
	case SPI_SETMINIMIZEDMETRICS:
		lpParam = "SPI_SETMINIMIZEDMETRICS";
		break;
	case SPI_SETMOUSEDOCKTHRESHOLD:
		lpParam = "SPI_SETMOUSEDOCKTHRESHOLD";
		break;
	case SPI_SETMOUSEDRAGOUTTHRESHOLD:
		lpParam = "SPI_SETMOUSEDRAGOUTTHRESHOLD";
		break;
	case SPI_SETMOUSESIDEMOVETHRESHOLD:
		lpParam = "SPI_SETMOUSESIDEMOVETHRESHOLD";
		break;
	case SPI_SETNONCLIENTMETRICS:
		lpParam = "SPI_SETNONCLIENTMETRICS";
		break;
	case SPI_SETPENDOCKTHRESHOLD:
		lpParam = "SPI_SETPENDOCKTHRESHOLD";
		break;
	case SPI_SETPENDRAGOUTTHRESHOLD:
		lpParam = "SPI_SETPENDRAGOUTTHRESHOLD";
		break;
	case SPI_SETPENSIDEMOVETHRESHOLD:
		lpParam = "SPI_SETPENSIDEMOVETHRESHOLD";
		break;
	case SPI_SETSHOWIMEUI:
		lpParam = "SPI_SETSHOWIMEUI";
		break;
	case SPI_SETSNAPSIZING:
		lpParam = "SPI_SETSNAPSIZING";
		break;
	case SPI_SETWINARRANGING:
		lpParam = "SPI_SETWINARRANGING";
		break;
	default:
		lpParam = NullStrA;
		break;
	}

	if ( lpParam != NULL ) {
		_strcatA(Buffer, lpParam);
	}
}

VOID LogSystemParametersInfo(
	UINT uiAction,
	UINT uiParam
	)
{
	CHAR tBuff[LOGBUFFERSIZE];

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyA(tBuff, "SystemParametersInfo(");

	//put uiAction
	LogPutSystemParametersInfoA(uiAction, tBuff);

	//log uiParam
	_strcatA(tBuff, CommaExA);
	ultostrA(uiParam, _strendA(tBuff));

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZE, LOG_NORMAL);
}

BOOL WINAPI SystemParametersInfoHookA(
	UINT uiAction,
	UINT uiParam,
	PVOID pvParam,
	UINT fWinIni
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pSystemParametersInfoA(uiAction, uiParam, pvParam, fWinIni);
		}
		Tls->ourcall = TRUE;
	}

	LogSystemParametersInfo(uiAction, uiParam);

	if ( Tls ) Tls->ourcall = FALSE;
	return pSystemParametersInfoA(uiAction, uiParam, pvParam, fWinIni);
}

BOOL WINAPI SystemParametersInfoHookW(
	UINT uiAction,
	UINT uiParam,
	PVOID pvParam,
	UINT fWinIni
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pSystemParametersInfoW(uiAction, uiParam, pvParam, fWinIni);
		}
		Tls->ourcall = TRUE;
	}

	LogSystemParametersInfo(uiAction, uiParam);

	if ( Tls ) Tls->ourcall = FALSE;
	return pSystemParametersInfoW(uiAction, uiParam, pvParam, fWinIni);
}

VOID LogHookIdA(
	int idHook
	)
{
	LPSTR lpType = NULL;
	CHAR tBuff[LOGBUFFERSIZE];

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyA(tBuff, "SetWindowsHookEx(");

	//put idHook
	switch ( idHook ) {
	case WH_MSGFILTER:
		lpType = "WH_MSGFILTER";
		break;
	case WH_JOURNALRECORD:
		lpType = "WH_JOURNALRECORD";
		break;
	case WH_JOURNALPLAYBACK:
		lpType = "WH_JOURNALPLAYBACK";
		break;
	case WH_KEYBOARD:
		lpType = "WH_KEYBOARD";
		break;
	case WH_GETMESSAGE:
		lpType = "WH_GETMESSAGE";
		break;
	case WH_CALLWNDPROC:
		lpType = "WH_CALLWNDPROC";
		break;
	case WH_CBT:
		lpType = "WH_CBT";
		break;
	case WH_SYSMSGFILTER:
		lpType = "WH_SYSMSGFILTER";
		break;
	case WH_MOUSE:
		lpType = "WH_MOUSE";
		break;
	case WH_DEBUG:
		lpType = "WH_DEBUG";
		break;
	case WH_SHELL:
		lpType = "WH_SHELL";
		break;
	case WH_FOREGROUNDIDLE:
		lpType = "WH_FOREGROUNDIDLE";
		break;
	case WH_CALLWNDPROCRET:
		lpType = "WH_CALLWNDPROCRET";
		break;
	case WH_KEYBOARD_LL:
		lpType = "WH_KEYBOARD_LL";
		break;
	case WH_MOUSE_LL:
		lpType = "WH_MOUSE_LL";
		break;
	default:
		lpType = UnknownA;
		break;
	}
	_strcatA(tBuff, lpType);

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZE, LOG_NORMAL);
}

HHOOK WINAPI SetWindowsHookExHookA(
	int idHook,
	HOOKPROC lpfn,
	HINSTANCE hmod,
	DWORD dwThreadId
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pSetWindowsHookExA(idHook, lpfn, hmod, dwThreadId);
		}
		Tls->ourcall = TRUE;
	}

	if ( dwThreadId == (DWORD)0 ) {
		LogHookIdA(idHook);
	}

	if ( Tls ) Tls->ourcall = FALSE;
	return pSetWindowsHookExA(idHook, lpfn, hmod, dwThreadId);
}

HHOOK WINAPI SetWindowsHookExHookW(
	int idHook,
	HOOKPROC lpfn,
	HINSTANCE hmod,
	DWORD dwThreadId
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pSetWindowsHookExW(idHook, lpfn, hmod, dwThreadId);
		}
		Tls->ourcall = TRUE;
	}

	if ( dwThreadId == (DWORD)0 ) {
		LogHookIdA(idHook);
	}

	if ( Tls ) Tls->ourcall = FALSE;
	return pSetWindowsHookExW(idHook, lpfn, hmod, dwThreadId);
}

VOID WINAPI keybd_eventHook(
	BYTE bVk,
	BYTE bScan,
	DWORD dwFlags,
	ULONG_PTR dwExtraInfo
	)
{
	PTLS Tls;
	CHAR tBuff[LOGBUFFERSIZESMALL];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			pkeybd_event(bVk, bScan, dwFlags, dwExtraInfo);
			return;
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyA(tBuff, "keybd_event(");
	//put bVk
	ultostrA(bVk, _strendA(tBuff));

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZE, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	pkeybd_event(bVk, bScan, dwFlags, dwExtraInfo);
}

SHORT WINAPI GetAsyncKeyStateHook(
	__in int vKey
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pGetAsyncKeyState(vKey);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCallA("GetAsyncKeyState()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pGetAsyncKeyState(vKey);
}

SHORT WINAPI GetKeyStateHook(
	int nVirtKey
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pGetKeyState(nVirtKey);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCallA("GetKeyState()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pGetKeyState(nVirtKey);
}

BOOL WINAPI GetKeyboardStateHook(
    PBYTE lpKeyState
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pGetKeyboardState(lpKeyState);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCallA("GetKeyboardState()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pGetKeyboardState(lpKeyState);
}

UINT WINAPI GetRawInputDataHook(
    HRAWINPUT hRawInput,
    UINT uiCommand,
    LPVOID pData,
    PUINT pcbSize,
    UINT cbSizeHeader
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pGetRawInputData(hRawInput, uiCommand, pData, pcbSize, cbSizeHeader);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCallA("GetRawInputData()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pGetRawInputData(hRawInput, uiCommand, pData, pcbSize, cbSizeHeader);
}

BOOL WINAPI PrintWindowHook(
    HWND hwnd,
    HDC hdcBlt,
    UINT nFlags
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pPrintWindow(hwnd, hdcBlt, nFlags);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCallA("PrintWindow()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pPrintWindow(hwnd, hdcBlt, nFlags);
}

HWND WINAPI SetClipboardViewerHook(
    HWND hWndNewViewer
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pSetClipboardViewer(hWndNewViewer);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCallA("SetClipboardViewer()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pSetClipboardViewer(hWndNewViewer);
}

BOOL WINAPI AddClipboardFormatListenerHook(
    HWND hwnd
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pAddClipboardFormatListener(hwnd);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCallA("AddClipboardFormatListener()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pAddClipboardFormatListener(hwnd);
}

BOOL WINAPI LockWorkStationHook(
    VOID
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pLockWorkStation();
		}
		Tls->ourcall = TRUE;
	}

	LogAsCallA("LockWorkStation()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pLockWorkStation();
}

int WINAPI GetWindowTextLengthHookA(
    HWND hWnd
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pGetWindowTextLengthA(hWnd);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCallA("GetWindowTextLength()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pGetWindowTextLengthA(hWnd);
}

int WINAPI GetWindowTextLengthHookW(
    HWND hWnd
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pGetWindowTextLengthW(hWnd);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCallA("GetWindowTextLength()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pGetWindowTextLengthW(hWnd);
}

HWND WINAPI GetForegroundWindowHook(
    VOID
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pGetForegroundWindow();
		}
		Tls->ourcall = TRUE;
	}

	LogAsCallA("GetForegroundWindow()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pGetForegroundWindow();
}

BOOL WINAPI AttachThreadInputHook(
    DWORD idAttach,
    DWORD idAttachTo,
    BOOL fAttach
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pAttachThreadInput(idAttach, idAttachTo, fAttach);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCallA("AttachThreadInput()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pAttachThreadInput(idAttach, idAttachTo, fAttach);
}

BOOL WINAPI SetWindowPosHook(
    HWND hWnd,
    HWND hWndInsertAfter,
    int X,
    int Y,
    int cx,
    int cy,
    UINT uFlags
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pSetWindowPos(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags);
		}
		Tls->ourcall = TRUE;
	}

	_WARNING_OFF(4306);
	if ( hWndInsertAfter == HWND_TOPMOST ) {
		LogAsCallA("SetWindowPos(HWND_TOPMOST)", LOG_NORMAL);
	}
	_WARNING_ON(4306);

	if ( Tls ) Tls->ourcall = FALSE;
	return pSetWindowPos(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags);
}

UINT_PTR WINAPI SetTimerHook(
    HWND hWnd,
    UINT_PTR nIDEvent,
    UINT uElapse,
    TIMERPROC lpTimerFunc
	)
{
	PTLS Tls;
	CHAR tBuff[LOGBUFFERSIZESMALL];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pSetTimer(hWnd, nIDEvent, uElapse, lpTimerFunc);
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyA(tBuff, "SetTimer(");

	//put hWnd
	_strcatA(tBuff, HexPrepA);
	utohexA((ULONG_PTR)hWnd, _strendA(tBuff));

	//put uElapse
	_strcatA(tBuff, ", Elapse=0x");
	utohexA(uElapse, _strendA(tBuff));

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZESMALL, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pSetTimer(hWnd, nIDEvent, uElapse, lpTimerFunc);
}

BOOL WINAPI RegisterHotKeyHook(
    HWND hWnd,
    int id,
    UINT fsModifiers,
    UINT vk
	)
{
	PTLS Tls;
	CHAR tBuff[LOGBUFFERSIZESMALL];
	LPSTR Modifier;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pRegisterHotKey(hWnd, id, fsModifiers, vk);
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyA(tBuff, "RegisterHotKey(");

	Modifier = NULL;

	switch ( fsModifiers ) {
	case MOD_ALT:
		Modifier = "ALT+";
		break;
	case MOD_CONTROL:
		Modifier = "CTRL+";
		break;
	case MOD_SHIFT:
		Modifier = "SHIFT+";
		break;
	case MOD_WIN:
		Modifier = "WIN+";
		break;
	default:
		Modifier = NULL;
		break;
	}

	//put fsModifiers + vk
	if ( Modifier != NULL ) {
		_strcatA(tBuff, Modifier);
		ultostrA(vk, _strendA(tBuff));
	}

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZESMALL, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pRegisterHotKey(hWnd, id, fsModifiers, vk);
}

BOOL WINAPI ClipCursorHook(
    CONST RECT *lpRect
	)
{
	PTLS Tls;
	CHAR tBuff[LOGBUFFERSIZESMALL];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pClipCursor(lpRect);
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyA(tBuff, "ClipCursor(");

	//put lpRect
	if ( ARGUMENT_PRESENT(lpRect) ) {
		__try {
		    //put left
			ltostrA(lpRect->left, _strendA(tBuff));
			_strcatA(tBuff, CommaExA);
			//put right
			ltostrA(lpRect->right, _strendA(tBuff));
			_strcatA(tBuff, CommaExA);
			//put top
			ltostrA(lpRect->top, _strendA(tBuff));
			_strcatA(tBuff, CommaExA);
			//put bottom
			ltostrA(lpRect->bottom, _strendA(tBuff));
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			_strcatA(tBuff, USER32_EXCEPTION_A);
			utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
		}
	} else {
		_strcatA(tBuff, NullStrA);
	}

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZESMALL, LOG_NORMAL);
	/* example of output ClipCursor(-100, 103, -555, 198) */

	if ( Tls ) Tls->ourcall = FALSE;
	return pClipCursor(lpRect);
}

BOOL WINAPI SwitchDesktopHook(
    HDESK hDesktop
	)
{
	PTLS Tls;
	DWORD szNeeded = 0;
	WCHAR tBuff[LOGBUFFERSIZELONG];
	WCHAR szDesktop[MAX_PATH];

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pSwitchDesktop(hDesktop);
		}
		Tls->ourcall = TRUE;
	}

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));
	RtlSecureZeroMemory(szDesktop, sizeof(szDesktop));

	//put prolog
	_strcpyW(tBuff, L"SwitchDesktop(");


	//put desktop name
	if (!GetUserObjectInformationW(hDesktop, UOI_NAME, szDesktop, MAX_PATH, &szNeeded)) {
		_strcpyW(szDesktop, UnknownW);
	}

	//put desktop name
	_strcatW(tBuff, szDesktop);

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;

	//attempt to switch to another desktop?
	if (_strcmpiW(szDesktop, L"Default") == 0) {
		return pSwitchDesktop(hDesktop);
	} else {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
}

int WINAPI GetKeyboardLayoutListHook(
    int nBuff,
    HKL *lpList
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pGetKeyboardLayoutList(nBuff, lpList);
		}
		Tls->ourcall = TRUE;
	}

	LogAsCallA("GetKeyboardLayoutList()", LOG_NORMAL);

	if ( Tls ) Tls->ourcall = FALSE;
	return pGetKeyboardLayoutList(nBuff, lpList);
}

#pragma warning (disable: 4306)
BOOL IsProtectedWindow(
	HWND hwnd
	)
{
	DWORD dwProcessId;
	CLIENT_ID ClientId;

	dwProcessId = (DWORD)0;

	pGetWindowThreadProcessId(hwnd, &dwProcessId);
	if ( dwProcessId == (DWORD)0) {
		return FALSE; 
	}

	ClientId.UniqueProcess = (HANDLE)dwProcessId;
	ClientId.UniqueThread = NULL;

	return IsProtectedProcess(&ClientId);
}
#pragma warning (default: 4306)

VOID LogFindWindowA(
    LPCSTR lpClass,
    LPCSTR lpWindow
	)
{
	ULONG_PTR ulParam;
	CHAR tBuff[LOGBUFFERSIZELONG];

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyA(tBuff, "FindWindow(");

	__try {
		//put lpClass
		if ( ARGUMENT_PRESENT(lpClass) ) {

			//check if atom 
			ulParam = (ULONG_PTR)lpClass;
			if ((ulParam & ((ULONG_PTR)LongToPtr(0xffff0000))) == 0) {
				if (GetClipboardFormatNameA((UINT)ulParam, _strendA(tBuff), MAX_PATH) == 0) {
					_strcatA(tBuff, NullStrA);
				}
			} else {
				//if not atom copy class name
				_strncpyA(_strendA(tBuff), MAX_PATH, lpClass, MAX_PATH);
			}
		} else {
			_strcatA(tBuff, NullStrA);//no lpClass
		}
		_strcatA(tBuff, CommaExA);
		//put lpWindow
		if ( ARGUMENT_PRESENT(lpWindow) ) {
			_strncpyA(_strendA(tBuff), MAX_PATH, lpWindow, MAX_PATH);
		} else {
			_strcatA(tBuff, NullStrA);//no lpWindow
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatA(tBuff, USER32_EXCEPTION_A);
		utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
	}

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);
}

VOID LogFindWindowW(
    LPCWSTR lpClass,
    LPCWSTR lpWindow
	)
{
	ULONG_PTR ulParam;
	WCHAR tBuff[LOGBUFFERSIZELONG];
	
	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"FindWindow(");

	__try {
		//put lpClass
		if ( ARGUMENT_PRESENT(lpClass) ) {

			//check if atom 
			ulParam = (ULONG_PTR)lpClass;
			if ((ulParam & ((ULONG_PTR)LongToPtr(0xffff0000))) == 0) {
				if (GetClipboardFormatNameW((UINT)ulParam, _strendW(tBuff), MAX_PATH) == 0) {
					_strcatW(tBuff, NullStrW);
				}
			} else {
				//if not atom copy class name
				_strncpyW(_strendW(tBuff), MAX_PATH, lpClass, MAX_PATH);
			}
		} else {
			_strcatW(tBuff, NullStrW);//no lpClass
		}
		//put lpWindow
		_strcatW(tBuff, CommaExW);
		if ( ARGUMENT_PRESENT(lpWindow) ) {		
			_strncpyW(_strendW(tBuff), MAX_PATH, lpWindow, MAX_PATH);
		} else {
			_strcatW(tBuff, NullStrW);//no lpWindow
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatW(tBuff, USER32_EXCEPTION);
		utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZELONG, LOG_NORMAL);
}

HWND WINAPI FindWindowHookA(
    LPCSTR lpClassName,
    LPCSTR lpWindowName
	)
{
	PTLS Tls;
	HWND hWnd; 

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pFindWindowA(lpClassName, lpWindowName);
		}
		Tls->ourcall = TRUE;
	}

	//log this call
	LogFindWindowA(lpClassName, lpWindowName);

	hWnd = pFindWindowA(lpClassName, lpWindowName);
	if ( IsProtectedWindow(hWnd) ) {
		SetLastError(ERROR_INVALID_NAME);
		hWnd = NULL;
	}

	if ( Tls ) Tls->ourcall = FALSE;
	return hWnd;
}

HWND WINAPI FindWindowHookW(
    LPCWSTR lpClassName,
    LPCWSTR lpWindowName
	)
{
	PTLS Tls;
	HWND hWnd; 	

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pFindWindowW(lpClassName, lpWindowName);
		}
		Tls->ourcall = TRUE;
	}

	//log this call
	LogFindWindowW(lpClassName, lpWindowName);

	hWnd = pFindWindowW(lpClassName, lpWindowName);
	if ( IsProtectedWindow(hWnd) ) {
		SetLastError(ERROR_INVALID_NAME);
		hWnd = NULL;
	}

	if ( Tls ) Tls->ourcall = FALSE;
	return hWnd;
}

HWND WINAPI FindWindowExHookA(
    HWND hWndParent,
    HWND hWndChildAfter,
    LPCSTR lpszClass,
    LPCSTR lpszWindow
	)
{
	PTLS Tls;
	HWND hWnd; 
	
	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pFindWindowExA(hWndParent, hWndChildAfter, lpszClass, lpszWindow);
		}
		Tls->ourcall = TRUE;
	}

	//log this call
	LogFindWindowA(lpszClass, lpszWindow);

	hWnd = pFindWindowExA(hWndParent, hWndChildAfter, lpszClass, lpszWindow);
	if ( IsProtectedWindow(hWnd) ) {
		SetLastError(ERROR_INVALID_NAME);
		hWnd = NULL;
	}

	if ( Tls ) Tls->ourcall = FALSE;
	return hWnd;
}

HWND WINAPI FindWindowExHookW(
    HWND hWndParent,
    HWND hWndChildAfter,
    LPCWSTR lpszClass,
    LPCWSTR lpszWindow
	)
{
	PTLS Tls;
	HWND hWnd; 	

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pFindWindowExW(hWndParent, hWndChildAfter, lpszClass, lpszWindow);
		}
		Tls->ourcall = TRUE;
	}

	//log this call
	LogFindWindowW(lpszClass, lpszWindow);

	hWnd = pFindWindowExW(hWndParent, hWndChildAfter, lpszClass, lpszWindow);
	if ( IsProtectedWindow(hWnd) ) {
		SetLastError(ERROR_INVALID_NAME);
		hWnd = NULL;
	}

	if ( Tls ) Tls->ourcall = FALSE;
	return hWnd;
}

DWORD WINAPI GetWindowThreadProcessIdHook(
    HWND hWnd,
    LPDWORD lpdwProcessId
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		Tls->showcomparision = FALSE;
		if ( Tls->ourcall ) {
			return pGetWindowThreadProcessId(hWnd, lpdwProcessId);
		}
		Tls->ourcall = TRUE;
	}

	if ( IsProtectedWindow(hWnd) ) {
		SetLastError(ERROR_INVALID_PARAMETER);
		if ( Tls ) Tls->ourcall = FALSE;
		return (DWORD)0;
	}
	if ( Tls ) Tls->ourcall = FALSE;
	return pGetWindowThreadProcessId(hWnd, lpdwProcessId);
}

int WINAPI GetWindowTextHookA(
    HWND hWnd,
    LPSTR lpString,
    int nMaxCount
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		if ( Tls->ourcall ) {
			return pGetWindowTextA(hWnd, lpString, nMaxCount);
		}
		Tls->ourcall = TRUE;
	}

	if ( IsProtectedWindow(hWnd) ) {
		SetLastError(ERROR_INVALID_PARAMETER);
		if ( Tls ) Tls->ourcall = FALSE;
		return 0;
	}
	if ( Tls ) Tls->ourcall = FALSE;
	return pGetWindowTextA(hWnd, lpString, nMaxCount);
}

int WINAPI GetWindowTextHookW(
    HWND hWnd,
    LPWSTR lpString,
    int nMaxCount
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		if ( Tls->ourcall ) {
			return pGetWindowTextW(hWnd, lpString, nMaxCount);
		}
		Tls->ourcall = TRUE;
	}

	if ( IsProtectedWindow(hWnd) ) {
		SetLastError(ERROR_INVALID_PARAMETER);
		if ( Tls ) Tls->ourcall = FALSE;
		return 0;
	}
	if ( Tls ) Tls->ourcall = FALSE;
	return pGetWindowTextW(hWnd, lpString, nMaxCount);
}

int WINAPI GetClassNameHookA(
    HWND hWnd,
    LPSTR lpClassName,
    int nMaxCount
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		if ( Tls->ourcall ) {
			return pGetClassNameA(hWnd, lpClassName, nMaxCount);
		}
		Tls->ourcall = TRUE;
	}

	if ( IsProtectedWindow(hWnd) ) {
		SetLastError(ERROR_INVALID_PARAMETER);
		if ( Tls ) Tls->ourcall = FALSE;
		return 0;
	}
	if ( Tls ) Tls->ourcall = FALSE;
	return pGetClassNameA(hWnd, lpClassName, nMaxCount);
}

int WINAPI GetClassNameHookW(
    HWND hWnd,
    LPWSTR lpClassName,
    int nMaxCount
    )
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		if ( Tls->ourcall ) {
			return pGetClassNameW(hWnd, lpClassName, nMaxCount);
		}
		Tls->ourcall = TRUE;
	}

	if ( IsProtectedWindow(hWnd) ) {
		SetLastError(ERROR_INVALID_PARAMETER);
		if ( Tls ) Tls->ourcall = FALSE;
		return 0;
	}
	if ( Tls ) Tls->ourcall = FALSE;
	return pGetClassNameW(hWnd, lpClassName, nMaxCount);
}

LRESULT WINAPI SendMessageHookA(
	HWND hWnd,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam
	)
{
	PTLS Tls;

	if ( Msg != WM_GETTEXT ) {
		return pSendMessageA(hWnd, Msg, wParam, lParam);
	} else {
		Tls = GetTls();
		if ( Tls ) {
			if ( Tls->ourcall ) {
				return pSendMessageA(hWnd, Msg, wParam, lParam);
			}
			Tls->ourcall = TRUE;
		}

		if ( IsProtectedWindow(hWnd) ) {
			SetLastError(ERROR_INVALID_PARAMETER);
			if ( Tls ) Tls->ourcall = FALSE;
			return 0;
		}
		if ( Tls ) Tls->ourcall = FALSE;
		return pSendMessageA(hWnd, Msg, wParam, lParam);
	}
}

LRESULT WINAPI SendMessageHookW(
	HWND hWnd,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam
	)
{
	PTLS Tls;

	if ( Msg != WM_GETTEXT ) {
		return pSendMessageW(hWnd, Msg, wParam, lParam);
	} else {
		Tls = GetTls();
		if ( Tls ) {
			if ( Tls->ourcall ) {
				return pSendMessageW(hWnd, Msg, wParam, lParam);
			}
			Tls->ourcall = TRUE;
		}

		if ( IsProtectedWindow(hWnd) ) {
			SetLastError(ERROR_INVALID_PARAMETER);
			if ( Tls ) Tls->ourcall = FALSE;
			return 0;
		}
		if ( Tls ) Tls->ourcall = FALSE;
		return pSendMessageW(hWnd, Msg, wParam, lParam);
	}
}

LRESULT WINAPI SendMessageTimeoutHookA(
	HWND hWnd,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam,
	UINT fuFlags,
	UINT uTimeout,
	PDWORD_PTR lpdwResult
	)
{
	PTLS Tls;
	if ( Msg != WM_GETTEXT ) {
		return pSendMessageTimeoutA(hWnd, Msg, wParam, lParam, fuFlags, uTimeout, lpdwResult);
	} else {
		Tls = GetTls();
		if ( Tls ) {
			if ( Tls->ourcall ) {
				return pSendMessageTimeoutA(hWnd, Msg, wParam, lParam, fuFlags, uTimeout, lpdwResult);
			}
			Tls->ourcall = TRUE;
		}

		if ( IsProtectedWindow(hWnd) ) {
			SetLastError(ERROR_INVALID_PARAMETER);
			if ( Tls ) Tls->ourcall = FALSE;
			return 0;
		}
		if ( Tls ) Tls->ourcall = FALSE;
		return pSendMessageTimeoutA(hWnd, Msg, wParam, lParam, fuFlags, uTimeout, lpdwResult);
	}
}

LRESULT WINAPI SendMessageTimeoutHookW(
	HWND hWnd,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam,
	UINT fuFlags,
	UINT uTimeout,
	PDWORD_PTR lpdwResult
	)
{
	PTLS Tls;

	if ( Msg != WM_GETTEXT ) {
		return pSendMessageTimeoutW(hWnd, Msg, wParam, lParam, fuFlags, uTimeout, lpdwResult);
	} else {
		Tls = GetTls();
		if ( Tls ) {
			if ( Tls->ourcall ) {
				return pSendMessageTimeoutW(hWnd, Msg, wParam, lParam, fuFlags, uTimeout, lpdwResult);
			}
			Tls->ourcall = TRUE;
		}

		if ( IsProtectedWindow(hWnd) ) {
			SetLastError(ERROR_INVALID_PARAMETER);
			if ( Tls ) Tls->ourcall = FALSE;
			return 0;
		} 
		if ( Tls ) Tls->ourcall = FALSE;
		return pSendMessageTimeoutW(hWnd, Msg, wParam, lParam, fuFlags, uTimeout, lpdwResult);
	}
}

int WINAPI InternalGetWindowTextHook(
    HWND hWnd,
    LPWSTR pString,
    int cchMaxCount
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		if ( Tls->ourcall ) {
			return pInternalGetWindowText(hWnd, pString, cchMaxCount);
		}
		Tls->ourcall = TRUE;
	}

	if ( IsProtectedWindow(hWnd) ) {
		SetLastError(ERROR_INVALID_PARAMETER);
		if ( Tls ) Tls->ourcall = FALSE;
		return 0;
	}
	if ( Tls ) Tls->ourcall = FALSE;
	return pInternalGetWindowText(hWnd, pString, cchMaxCount);
}

VOID LogPutDesktopA(
	LPCSTR lpszDesktop
	)
{
	CHAR tBuff[LOGBUFFERSIZE];

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyA(tBuff, "CreateDesktop(");

	__try {
		//put lpszDesktop
		if ( ARGUMENT_PRESENT(lpszDesktop) ) {
			_strncpyA(_strendA(tBuff), MAX_PATH, lpszDesktop, MAX_PATH);
		} else {
			_strcatA(tBuff, NullStrA);//no lpszDesktop
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatA(tBuff, USER32_EXCEPTION_A);
		utohexA((ULONG_PTR)GetExceptionCode(), _strendA(tBuff));
	}

	//put epilog and log
	_strcatA(tBuff, CloseBracketA);
	PushToLogA(tBuff, LOGBUFFERSIZE, LOG_NORMAL);
}

VOID LogPutDesktopW(
	LPCWSTR lpszDesktop
	)
{
	WCHAR tBuff[LOGBUFFERSIZE];

	RtlSecureZeroMemory(tBuff, sizeof(tBuff));

	//put prolog
	_strcpyW(tBuff, L"CreateDesktop(");

	__try {
		//put lpszDesktop
		if ( ARGUMENT_PRESENT(lpszDesktop) ) {
			_strncpyW(_strendW(tBuff), MAX_PATH, lpszDesktop, MAX_PATH);
		} else {
			_strcatW(tBuff, NullStrW);//no lpszDesktop
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_strcatW(tBuff, USER32_EXCEPTION);
		utohexW((ULONG_PTR)GetExceptionCode(), _strendW(tBuff));
	}

	//put epilog and log
	_strcatW(tBuff, CloseBracketW);
	PushToLogW(tBuff, LOGBUFFERSIZE, LOG_NORMAL);
}

HDESK WINAPI CreateDesktopHookA(
    LPCSTR lpszDesktop,
    LPCSTR lpszDevice,
    DEVMODEA* pDevmode,
    DWORD dwFlags,
    ACCESS_MASK dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpsa
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		if ( Tls->ourcall ) {
			return pCreateDesktopA(lpszDesktop, lpszDevice, pDevmode, dwFlags, dwDesiredAccess, lpsa);
		}
		Tls->ourcall = TRUE;
	}

	LogPutDesktopA(lpszDesktop);

	if ( Tls ) Tls->ourcall = FALSE;
	return GetThreadDesktop(GetCurrentThreadId());
}

HDESK WINAPI CreateDesktopHookW(
    LPCWSTR lpszDesktop,
    LPCWSTR lpszDevice,
    DEVMODEW* pDevmode,
    DWORD dwFlags,
    ACCESS_MASK dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpsa
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		if ( Tls->ourcall ) {
			return pCreateDesktopW(lpszDesktop, lpszDevice, pDevmode, dwFlags, dwDesiredAccess, lpsa);
		}
		Tls->ourcall = TRUE;
	}

	LogPutDesktopW(lpszDesktop);

	if ( Tls ) Tls->ourcall = FALSE;
	return GetThreadDesktop(GetCurrentThreadId());
}

HDESK WINAPI CreateDesktopExHookA(
    LPCSTR lpszDesktop,
    LPCSTR lpszDevice,
    DEVMODEA* pDevmode,
    DWORD dwFlags,
    ACCESS_MASK dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpsa,
    ULONG ulHeapSize,
    PVOID pvoid
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		if ( Tls->ourcall ) {
			return pCreateDesktopExA(lpszDesktop, lpszDevice, pDevmode, dwFlags, dwDesiredAccess, lpsa, ulHeapSize, pvoid);
		}
		Tls->ourcall = TRUE;
	}

	LogPutDesktopA(lpszDesktop);

	if ( Tls ) Tls->ourcall = FALSE;
	return GetThreadDesktop(GetCurrentThreadId());
}

HDESK WINAPI CreateDesktopExHookW(
    LPCWSTR lpszDesktop,
    LPCWSTR lpszDevice,
    DEVMODEW* pDevmode,
    DWORD dwFlags,
    ACCESS_MASK dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpsa,
    ULONG ulHeapSize,
    PVOID pvoid
	)
{
	PTLS Tls;

	Tls = GetTls();
	if ( Tls ) {
		if ( Tls->ourcall ) {
			return pCreateDesktopExW(lpszDesktop, lpszDevice, pDevmode, dwFlags, dwDesiredAccess, lpsa, ulHeapSize, pvoid);
		}
		Tls->ourcall = TRUE;
	}

	LogPutDesktopW(lpszDesktop);

	if ( Tls ) Tls->ourcall = FALSE;
	return GetThreadDesktop(GetCurrentThreadId());
}