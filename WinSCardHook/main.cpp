#include "stdafx.h"
#include <stdio.h>
#include <winscard.h>
#include "mhook/mhook-lib/mhook.h"
#include "Logger.h"


// Global Variables
FILE* fp_log = NULL;
HMODULE hDll = 0;


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
	//LONG lRet;
	LOGGER::CLogger logger(LOGGER::LogLevel_Info, "C:\\Logs\\", "_WinSCardHook.log");
	logger.TraceInfo("SCardEstablishContext");
	logger.TraceInfo("IN dwScope: %d", dwScope);
	return pOrigSCardEstablishContext(dwScope, pvReserved1, pvReserved2, phContext);
}


//SCardReleaseContext
WINSCARDAPI LONG WINAPI
pHookSCardReleaseContext(
	_In_	SCARDCONTEXT	hContext
)
{
	//LONG lRet;
	//LOGGER::CLogger logger(LOGGER::LogLevel_Info, "C:\\Logs\\", "_WinSCardHook.log");
	//logger.TraceInfo("SCardReleaseContext");
	return pOrigSCardReleaseContext(hContext);
}


//SCardIsValidContext
WINSCARDAPI LONG WINAPI
pHookSCardIsValidContext(
	_In_	SCARDCONTEXT	hContext
)
{
	//LONG lRet;
	//LOGGER::CLogger logger(LOGGER::LogLevel_Info, "C:\\Logs\\", "_WinSCardHook.log");
	//logger.TraceInfo("SCardIsValidContext");
	return pOrigSCardIsValidContext(hContext);
}


//hookInitialize
void hookInitialize() {
	LOGGER::CLogger logger(LOGGER::LogLevel_Info, "C:\\Logs", "_hookInitialize.log");
	logger.TraceInfo("hookInitialize");
	hDll = LoadLibrary(L"winscard.dll");
	
	//GetProcAddress
	pOrigSCardEstablishContext = (PFN_SCARDESTABLISHCONTEXT)GetProcAddress(hDll, "SCardEstablishContext");
	pOrigSCardReleaseContext = (PFN_SCARDRELEASECONTEXT)GetProcAddress(hDll, "SCardReleaseContext");
	pOrigSCardIsValidContext = (PFN_SCARDISVALIDCONTEXT)GetProcAddress(hDll, "SCardIsValidContext");

	//Mhook_SetHook
	Mhook_SetHook((PVOID*)&pOrigSCardEstablishContext, pHookSCardEstablishContext);
	Mhook_SetHook((PVOID*)&pOrigSCardReleaseContext, pHookSCardReleaseContext);
	Mhook_SetHook((PVOID*)&pOrigSCardIsValidContext, pHookSCardIsValidContext);
}


//hookFinalize
void hookFinalize() {
	LOGGER::CLogger logger(LOGGER::LogLevel_Info, "C:\\Logs", "_hookFinalize.log");
	logger.TraceInfo("hookFinalize");

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
	HANDLE hFile = INVALID_HANDLE_VALUE;
	char szMsg[MAX_PATH] = { 0 };

	LOGGER::CLogger logger(LOGGER::LogLevel_Info, "C:\\Logs", "_DllMain.log");
	logger.TraceInfo("DllMain");
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