#include "stdafx.h"
#include <stdio.h>
#include <mutex>
#include <winscard.h>
#include "mhook/mhook-lib/mhook.h"
#include "Logger.h"


// Global Variables
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
	if (logger) {
		logger->TraceInfo("SCardReleaseContext");
	}
	return pOrigSCardReleaseContext(hContext);
}


//SCardIsValidContext
WINSCARDAPI LONG WINAPI
pHookSCardIsValidContext(
	_In_	SCARDCONTEXT	hContext
)
{
	if (logger) {
		logger->TraceInfo("SCardIsValidContext");
	}
	return pOrigSCardIsValidContext(hContext);
}


//hookInitialize
void hookInitialize() {
	if (logger) {
		logger->TraceInfo("hookInitialize");
	}

	g_hDll = LoadLibrary(L"winscard.dll");
	
	//GetProcAddress
	pOrigSCardEstablishContext = (PFN_SCARDESTABLISHCONTEXT)GetProcAddress(g_hDll, "SCardEstablishContext");
	pOrigSCardReleaseContext = (PFN_SCARDRELEASECONTEXT)GetProcAddress(g_hDll, "SCardReleaseContext");
	pOrigSCardIsValidContext = (PFN_SCARDISVALIDCONTEXT)GetProcAddress(g_hDll, "SCardIsValidContext");

	//Mhook_SetHook
	Mhook_SetHook((PVOID*)&pOrigSCardEstablishContext, pHookSCardEstablishContext);
	Mhook_SetHook((PVOID*)&pOrigSCardReleaseContext, pHookSCardReleaseContext);
	Mhook_SetHook((PVOID*)&pOrigSCardIsValidContext, pHookSCardIsValidContext);
}


//hookFinalize
void hookFinalize() {
	if (logger) {
		logger->TraceInfo("hookFinalize");
	}

	//Mhook_Unhook
	Mhook_Unhook((PVOID*)&pOrigSCardEstablishContext);
	Mhook_Unhook((PVOID*)&pOrigSCardReleaseContext);
	Mhook_Unhook((PVOID*)&pOrigSCardIsValidContext);
}


//DllMain
BOOL WINAPI DllMain(
    __in HINSTANCE  hInstance,
    __in DWORD      Reason,
    __in LPVOID     Reserved
    )
{
	logger = LOGGER::CLogger::getInstance(LOGGER::LogLevel_Info, "C:\\Logs\\", "");

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