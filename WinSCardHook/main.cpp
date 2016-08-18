#include "stdafx.h"
#include <stdio.h>
#include <mutex>
#include <winscard.h>
#include "mhook/mhook-lib/mhook.h"
#include "Logger.h"


// Global Variables
#define				LOG_PATH		"C:\\Logs\\"
#define				APP_HOOKING		L"C:\\Windows\\system32\\LogonUI.exe"
#define				DLL_HOOKED		L"WinSCard.dll"
LOGGER::CLogger*	logger = NULL;
HMODULE				g_hDll = 0;


//typedef of WinSCard API function pointers
typedef LONG(WINAPI *PFN_SCARDESTABLISHCONTEXT)(DWORD, LPCVOID, LPCVOID, LPSCARDCONTEXT);
typedef LONG(WINAPI *PFN_SCARDRELEASECONTEXT)(SCARDCONTEXT);
typedef LONG(WINAPI *PFN_SCARDISVALIDCONTEXT)(SCARDCONTEXT);

//initialization of WinSCard API function pointers
PFN_SCARDESTABLISHCONTEXT	pOrigSCardEstablishContext = NULL;
PFN_SCARDRELEASECONTEXT		pOrigSCardReleaseContext = NULL;
PFN_SCARDISVALIDCONTEXT		pOrigSCardIsValidContext = NULL;


//SCardEstablishContext
WINSCARDAPI LONG WINAPI
pHookSCardEstablishContext(
	_In_		DWORD			dwScope,
	_Reserved_	LPCVOID			pvReserved1,
	_Reserved_	LPCVOID			pvReserved2,
	_Out_		LPSCARDCONTEXT	phContext
)
{
	if (logger) {
		logger->TraceInfo("SCardEstablishContext");
		logger->TraceInfo("IN dwScope: %d", dwScope);
	}
	return pOrigSCardEstablishContext(dwScope, pvReserved1, pvReserved2, phContext);
}


//SCardReleaseContext
WINSCARDAPI LONG WINAPI
pHookSCardReleaseContext(
	_In_	SCARDCONTEXT	hContext
)
{
	if (logger) { logger->TraceInfo("SCardReleaseContext"); }
	return pOrigSCardReleaseContext(hContext);
}


//SCardIsValidContext
WINSCARDAPI LONG WINAPI
pHookSCardIsValidContext(
	_In_	SCARDCONTEXT	hContext
)
{
	if (logger) { logger->TraceInfo("SCardIsValidContext"); }
	return pOrigSCardIsValidContext(hContext);
}


//shouldHook
bool shouldHook() {
	wchar_t	wProcessName[MAX_PATH];
	GetModuleFileName(NULL, wProcessName, MAX_PATH);
	std::wstring ws(wProcessName);//convert wchar* to wstring
	std::string strProcessName(ws.begin(), ws.end());
	if (0 == wcscmp(APP_HOOKING, wProcessName)) {
		if (logger) { logger->TraceInfo("%s is hooking onto %s", strProcessName.c_str(), DLL_HOOKED); }
		return true;
	} else {
		if (logger) { logger->TraceInfo("%s is NOT hooking onto anything", strProcessName.c_str()); }
	}
	return false;
}


//hookInitialize
void hookInitialize() {
	if (shouldHook()) {
		g_hDll = LoadLibrary(DLL_HOOKED);
		//GetProcAddress
		pOrigSCardEstablishContext = (PFN_SCARDESTABLISHCONTEXT)GetProcAddress(g_hDll, "SCardEstablishContext");
		pOrigSCardReleaseContext = (PFN_SCARDRELEASECONTEXT)GetProcAddress(g_hDll, "SCardReleaseContext");
		pOrigSCardIsValidContext = (PFN_SCARDISVALIDCONTEXT)GetProcAddress(g_hDll, "SCardIsValidContext");
		//Mhook_SetHook
		Mhook_SetHook((PVOID*)&pOrigSCardEstablishContext, pHookSCardEstablishContext);
		Mhook_SetHook((PVOID*)&pOrigSCardReleaseContext, pHookSCardReleaseContext);
		Mhook_SetHook((PVOID*)&pOrigSCardIsValidContext, pHookSCardIsValidContext);
	}
}


//hookFinalize
void hookFinalize() {
	if (shouldHook()) {
		//Mhook_Unhook
		Mhook_Unhook((PVOID*)&pOrigSCardEstablishContext);
		Mhook_Unhook((PVOID*)&pOrigSCardReleaseContext);
		Mhook_Unhook((PVOID*)&pOrigSCardIsValidContext);
	}
}


//DllMain
BOOL WINAPI DllMain(
    __in HINSTANCE  hInstance,
    __in DWORD      Reason,
    __in LPVOID     Reserved
    )
{
	logger = LOGGER::CLogger::getInstance(LOGGER::LogLevel_Info, LOG_PATH, "");

	switch (Reason) {
		case DLL_PROCESS_ATTACH:
			hookInitialize();
		break;

		case DLL_PROCESS_DETACH:
			hookFinalize();
		break;
	}
    return TRUE;
}