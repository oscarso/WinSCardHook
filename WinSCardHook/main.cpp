#include "stdafx.h"
#include <stdio.h>
#include <winscard.h>
#include "mhook/mhook-lib/mhook.h"
#include "Logger.h"


FILE* fp_log = NULL;
HMODULE hDll = 0;


typedef LONG(WINAPI *PFN_SCARDESTABLISHCONTEXT)(DWORD, LPCVOID, LPCVOID, LPSCARDCONTEXT);
PFN_SCARDESTABLISHCONTEXT pOrigSCardEstablishContext = NULL;


WINSCARDAPI LONG WINAPI
pHookSCardEstablishContext(
	_In_  DWORD dwScope,
	_Reserved_  LPCVOID pvReserved1,
	_Reserved_  LPCVOID pvReserved2,
	_Out_ LPSCARDCONTEXT phContext)
{
	LONG lRet;
	LOGGER::CLogger logger(LOGGER::LogLevel_Info, "C:\\Logs\\", "_WinSCardHook.log");
	logger.TraceInfo("SCardEstablishContext");
	logger.TraceInfo("IN dwScope: %d", dwScope);
	return pOrigSCardEstablishContext(dwScope, pvReserved1, pvReserved2, phContext);
}


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
			hDll = LoadLibrary(L"winscard.dll");
			pOrigSCardEstablishContext = (PFN_SCARDESTABLISHCONTEXT)GetProcAddress(hDll, "SCardEstablishContext");
			Mhook_SetHook((PVOID*)&pOrigSCardEstablishContext, pHookSCardEstablishContext);
		break;

		case DLL_PROCESS_DETACH:
			Mhook_Unhook((PVOID*)&pOrigSCardEstablishContext);
		break;
	}
    return TRUE;
}