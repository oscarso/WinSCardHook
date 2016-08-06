#include "stdafx.h"
#include <stdio.h>
#include <winscard.h>
#include "mhook/mhook-lib/mhook.h"
#include "Logger.h"


FILE* fp_log = NULL;
HMODULE hDll = NULL;

typedef LONG(WINAPI *PFN_SCARDESTABLISHCONTEXT)(DWORD, LPCVOID, LPCVOID, LPSCARDCONTEXT);
PFN_SCARDESTABLISHCONTEXT pOrigSCardEstablishContext = NULL;


void test_logger(const char* msg) {
	char szProcessName[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, szProcessName, MAX_PATH);
	LOGGER::CLogger logger(LOGGER::LogLevel_Info, "C:\\Temp\\", "WinSCardHook.log");
	logger.TraceInfo(szProcessName);
	logger.TraceInfo(msg);
}


WINSCARDAPI LONG WINAPI
pHookSCardEstablishContext(
	_In_  DWORD dwScope,
	_Reserved_  LPCVOID pvReserved1,
	_Reserved_  LPCVOID pvReserved2,
	_Out_ LPSCARDCONTEXT phContext)
{
	test_logger("pHookSCardEstablishContext");
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

	switch (Reason) {
		case DLL_PROCESS_ATTACH:
			test_logger("DllMain: DLL_PROCESS_ATTACH");
			hDll = LoadLibrary(L"winscard.dll");
			sprintf(szMsg, "LoadLibrary last error: 0x%x", GetLastError());
			test_logger(szMsg);
			test_logger(hDll == NULL ? "hDll == NULL" : "hDll is GOOD");
			pOrigSCardEstablishContext = (PFN_SCARDESTABLISHCONTEXT)GetProcAddress(hDll, "SCardEstablishContext");
			sprintf(szMsg, "GetProcAddress last error: 0x%x", GetLastError());
			test_logger(szMsg);
			test_logger(hDll == NULL ? "pOrigSCardEstablishContext == NULL" : "pOrigSCardEstablishContext is GOOD");
			Mhook_SetHook((PVOID*)&pOrigSCardEstablishContext, pHookSCardEstablishContext);
		break;

		case DLL_PROCESS_DETACH:
			Mhook_Unhook((PVOID*)&pOrigSCardEstablishContext);
		break;
	}
    return TRUE;
}