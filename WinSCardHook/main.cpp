#include "stdafx.h"
#include <stdio.h>
#include <mutex>
#include <winscard.h>
#include "mhook/mhook-lib/mhook.h"
#include "Logger.h"


// Global Variables
#define				LOG_PATH		"C:\\Logs\\"
#define				APP_HOOKING		L"C:\\Windows\\system32\\LogonUI.exe"
#define				DLL_HOOKED_W	L"WinSCard.dll"
#define				DLL_HOOKED		"WinSCard.dll"
LOGGER::CLogger*	logger = NULL;
HMODULE				g_hDll = 0;


//typedef of WinSCard API function pointers
typedef LONG	(WINAPI *PFN_SCARDESTABLISHCONTEXT)(_In_ DWORD, _Reserved_ LPCVOID, _Reserved_ LPCVOID, _Out_ LPSCARDCONTEXT);
typedef LONG	(WINAPI *PFN_SCARDRELEASECONTEXT)(_In_ SCARDCONTEXT);
typedef LONG	(WINAPI *PFN_SCARDISVALIDCONTEXT)(_In_ SCARDCONTEXT);
typedef LONG	(WINAPI *PFN_SCARDFREEMEMORY)(_In_ SCARDCONTEXT, _In_ LPCVOID);
typedef LONG	(WINAPI *PFN_SCARDDISCONNECT)(_In_ SCARDHANDLE, _In_ DWORD);
typedef LONG	(WINAPI *PFN_SCARDBEGINTRANSACTION)(_In_ SCARDHANDLE);
typedef LONG	(WINAPI *PFN_SCARDENDTRANSACTION)(_In_ SCARDHANDLE, _In_ DWORD);
typedef LONG	(WINAPI *PFN_SCARDTRANSMIT)(_In_ SCARDHANDLE, _In_ LPCSCARD_IO_REQUEST, _In_reads_bytes_(cbSendLength) LPCBYTE, _In_ DWORD, _Inout_opt_ LPSCARD_IO_REQUEST, _Out_writes_bytes_(*pcbRecvLength) LPBYTE, _Inout_ LPDWORD);
typedef HANDLE	(WINAPI *PFN_SCARDACCESSSTARTEDEVENT)(void);
typedef void	(WINAPI *PFN_SCARDRELEASESTARTEDEVENT)(void);

//typedef LONG	(WINAPI *PFN_SCARDCANCELTRANSACTION)(_In_ SCARDHANDLE);//CANNOT hook - cause RDP crash


//initialization of WinSCard API function pointers
PFN_SCARDESTABLISHCONTEXT		pOrigSCardEstablishContext = NULL;
PFN_SCARDRELEASECONTEXT			pOrigSCardReleaseContext = NULL;
PFN_SCARDISVALIDCONTEXT			pOrigSCardIsValidContext = NULL;
PFN_SCARDFREEMEMORY				pOrigSCardFreeMemory = NULL;
PFN_SCARDDISCONNECT				pOrigSCardDisconnect = NULL;
PFN_SCARDBEGINTRANSACTION		pOrigSCardBeginTransaction = NULL;
PFN_SCARDENDTRANSACTION			pOrigSCardEndTransaction = NULL;
PFN_SCARDTRANSMIT				pOrigSCardTransmit = NULL;
PFN_SCARDACCESSSTARTEDEVENT		pOrigSCardAccessStartedEvent = NULL;
PFN_SCARDRELEASESTARTEDEVENT	pOrigSCardReleaseStartedEvent = NULL;


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


//SCardFreeMemory
WINSCARDAPI LONG WINAPI
pHookSCardFreeMemory(
	_In_	SCARDCONTEXT	hContext,
	_In_	LPCVOID			pvMem
)
{
	if (logger) {
		logger->TraceInfo("SCardFreeMemory");
	}
	return pOrigSCardFreeMemory(hContext, pvMem);
}


//SCardDisconnect
WINSCARDAPI LONG WINAPI
pHookSCardDisconnect(
	_In_	SCARDHANDLE	hCard,
	_In_	DWORD		dwDisposition
)
{
	if (logger) {
		logger->TraceInfo("SCardDisconnect");
	}
	return pOrigSCardDisconnect(hCard, dwDisposition);
}


//SCardBeginTransaction
WINSCARDAPI LONG WINAPI
pHookSCardBeginTransaction(
	_In_	SCARDHANDLE	hCard
)
{
	if (logger) {
		logger->TraceInfo("SCardBeginTransaction");
	}
	return pOrigSCardBeginTransaction(hCard);
}


//SCardEndTransaction
WINSCARDAPI LONG WINAPI
pHookSCardEndTransaction(
	_In_	SCARDHANDLE	hCard,
	_In_	DWORD		dwDisposition
)
{
	if (logger) {
		logger->TraceInfo("SCardEndTransaction");
	}
	return pOrigSCardEndTransaction(hCard, dwDisposition);
}


//SCardTransmit
WINSCARDAPI LONG WINAPI
pHookSCardTransmit(
	_In_        SCARDHANDLE hCard,
	_In_        LPCSCARD_IO_REQUEST pioSendPci,
	_In_reads_bytes_(cbSendLength) LPCBYTE pbSendBuffer,
	_In_        DWORD cbSendLength,
	_Inout_opt_ LPSCARD_IO_REQUEST pioRecvPci,
	_Out_writes_bytes_(*pcbRecvLength) LPBYTE pbRecvBuffer,
	_Inout_     LPDWORD pcbRecvLength)
{
	if (logger) {
		logger->TraceInfo("SCardTransmit");
	}
	return pOrigSCardTransmit(hCard, pioSendPci, pbSendBuffer, cbSendLength, pioRecvPci, pbRecvBuffer, pcbRecvLength);
}


//SCardAccessStartedEvent
WINSCARDAPI HANDLE WINAPI
pHookSCardAccessStartedEvent(
	void
)
{
	if (logger) {
		logger->TraceInfo("SCardAccessStartedEvent");
	}
	return pOrigSCardAccessStartedEvent();
}


//SCardReleaseStartedEvent
WINSCARDAPI void WINAPI
pHookSCardReleaseStartedEvent(
	void
)
{
	if (logger) {
		logger->TraceInfo("SCardReleaseStartedEvent");
	}
	pOrigSCardReleaseStartedEvent();
}


//shouldHook
bool shouldHook() {
	wchar_t	wProcessName[MAX_PATH];
	GetModuleFileName(NULL, wProcessName, MAX_PATH);
	std::wstring wsPN(wProcessName);//convert wchar* to wstring
	std::string strProcessName(wsPN.begin(), wsPN.end());
	if (0 == wcscmp(APP_HOOKING, wProcessName)) {
		if (logger) { logger->TraceInfo("%s is hooking onto a %s", strProcessName.c_str(), DLL_HOOKED); }
		return true;
	} else {
		if (logger) { logger->TraceInfo("%s is NOT hooking onto anything", strProcessName.c_str()); }
	}
	return false;
}


//hookInitialize
void hookInitialize() {
	if (shouldHook()) {
		g_hDll = LoadLibrary(DLL_HOOKED_W);

		//GetProcAddress
		 pOrigSCardEstablishContext = (PFN_SCARDESTABLISHCONTEXT)GetProcAddress(g_hDll, "SCardEstablishContext");
		   pOrigSCardReleaseContext = (PFN_SCARDRELEASECONTEXT)GetProcAddress(g_hDll, "SCardReleaseContext");
		   pOrigSCardIsValidContext = (PFN_SCARDISVALIDCONTEXT)GetProcAddress(g_hDll, "SCardIsValidContext");
			   pOrigSCardFreeMemory = (PFN_SCARDFREEMEMORY)GetProcAddress(g_hDll, "SCardFreeMemory");
			   pOrigSCardDisconnect = (PFN_SCARDDISCONNECT)GetProcAddress(g_hDll, "SCardDisconnect");
		 pOrigSCardBeginTransaction = (PFN_SCARDBEGINTRANSACTION)GetProcAddress(g_hDll, "SCardBeginTransaction");
		   pOrigSCardEndTransaction = (PFN_SCARDENDTRANSACTION)GetProcAddress(g_hDll, "SCardEndTransaction");
		         pOrigSCardTransmit = (PFN_SCARDTRANSMIT)GetProcAddress(g_hDll, "SCardTransmit");
	   pOrigSCardAccessStartedEvent = (PFN_SCARDACCESSSTARTEDEVENT)GetProcAddress(g_hDll, "SCardAccessStartedEvent");
	  pOrigSCardReleaseStartedEvent = (PFN_SCARDRELEASESTARTEDEVENT)GetProcAddress(g_hDll, "SCardReleaseStartedEvent");

		//Mhook_SetHook
		Mhook_SetHook((PVOID*)&pOrigSCardEstablishContext, pHookSCardEstablishContext);
		Mhook_SetHook((PVOID*)&pOrigSCardReleaseContext, pHookSCardReleaseContext);
		Mhook_SetHook((PVOID*)&pOrigSCardIsValidContext, pHookSCardIsValidContext);
		Mhook_SetHook((PVOID*)&pOrigSCardFreeMemory, pHookSCardFreeMemory);
		Mhook_SetHook((PVOID*)&pOrigSCardDisconnect, pHookSCardDisconnect);
		Mhook_SetHook((PVOID*)&pOrigSCardBeginTransaction, pHookSCardBeginTransaction);
		Mhook_SetHook((PVOID*)&pOrigSCardEndTransaction, pHookSCardEndTransaction);
		Mhook_SetHook((PVOID*)&pOrigSCardTransmit, pHookSCardTransmit);
		Mhook_SetHook((PVOID*)&pOrigSCardAccessStartedEvent, pHookSCardAccessStartedEvent);
		Mhook_SetHook((PVOID*)&pOrigSCardReleaseStartedEvent, pHookSCardReleaseStartedEvent);
	}
}


//hookFinalize
void hookFinalize() {
	if (shouldHook()) {
		//Mhook_Unhook
		Mhook_Unhook((PVOID*)&pOrigSCardEstablishContext);
		Mhook_Unhook((PVOID*)&pOrigSCardReleaseContext);
		Mhook_Unhook((PVOID*)&pOrigSCardIsValidContext);
		Mhook_Unhook((PVOID*)&pOrigSCardFreeMemory);
		Mhook_Unhook((PVOID*)&pOrigSCardDisconnect);
		Mhook_Unhook((PVOID*)&pOrigSCardBeginTransaction);
		Mhook_Unhook((PVOID*)&pOrigSCardEndTransaction);
		Mhook_Unhook((PVOID*)&pOrigSCardTransmit);
		Mhook_Unhook((PVOID*)&pOrigSCardAccessStartedEvent);
		Mhook_Unhook((PVOID*)&pOrigSCardReleaseStartedEvent);
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