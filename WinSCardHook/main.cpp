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
typedef LONG	(WINAPI *PFN_SCARDCANCEL)(_In_ SCARDCONTEXT);
typedef LONG	(WINAPI *PFN_SCARDRECONNECT)(_In_ SCARDHANDLE, _In_ DWORD, _In_ DWORD, _In_ DWORD, _Out_opt_ LPDWORD);
typedef LONG	(WINAPI *PFN_SCARDGETATTRIB)(_In_ SCARDHANDLE, _In_ DWORD, _Out_writes_bytes_opt_(*pcbAttrLen) LPBYTE, _Inout_ LPDWORD);
typedef LONG	(WINAPI *PFN_SCARDSETATTRIB)(_In_ SCARDHANDLE, _In_ DWORD, _In_reads_bytes_(cbAttrLen) LPCBYTE, _In_ DWORD);
typedef LONG	(WINAPI *PFN_SCARDCONTROL)(_In_ SCARDHANDLE, _In_ DWORD, _In_reads_bytes_(cbInBufferSize) LPCVOID, _In_ DWORD, _Out_writes_bytes_(cbOutBufferSize) LPVOID, _In_ DWORD, _Out_ LPDWORD);

#if (NTDDI_VERSION >= NTDDI_VISTA)
typedef LONG	(WINAPI *PFN_SCARDGETTRANSMITCOUNT)(_In_ SCARDHANDLE, _Out_ LPDWORD);
#endif // (NTDDI_VERSION >= NTDDI_VISTA)


#if 0
extern WINSCARDAPI LONG WINAPI
SCardControl(
	_In_    SCARDHANDLE hCard,
	_In_    DWORD dwControlCode,
	_In_reads_bytes_(cbInBufferSize) LPCVOID lpInBuffer,
	_In_    DWORD cbInBufferSize,
	_Out_writes_bytes_(cbOutBufferSize) LPVOID lpOutBuffer,
	_In_    DWORD cbOutBufferSize,
	_Out_   LPDWORD lpBytesReturned);
#endif


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
PFN_SCARDCANCEL					pOrigSCardCancel = NULL;
PFN_SCARDRECONNECT				pOrigSCardReconnect = NULL;
PFN_SCARDGETATTRIB				pOrigSCardGetAttrib = NULL;
PFN_SCARDSETATTRIB				pOrigSCardSetAttrib = NULL;
PFN_SCARDCONTROL				pOrigSCardControl = NULL;
#if (NTDDI_VERSION >= NTDDI_VISTA)
PFN_SCARDGETTRANSMITCOUNT		pOrigSCardGetTransmitCount = NULL;
#endif // (NTDDI_VERSION >= NTDDI_VISTA)


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


//SCardCancel
WINSCARDAPI LONG WINAPI
pHookSCardCancel(
	_In_	SCARDCONTEXT hContext
)
{
	if (logger) {
		logger->TraceInfo("SCardCancel");
	}
	return pOrigSCardCancel(hContext);
}


//SCardReconnect
WINSCARDAPI LONG WINAPI
pHookSCardReconnect(
	_In_      SCARDHANDLE hCard,
	_In_      DWORD dwShareMode,
	_In_      DWORD dwPreferredProtocols,
	_In_      DWORD dwInitialization,
	_Out_opt_ LPDWORD pdwActiveProtocol)
{
	if (logger) {
		logger->TraceInfo("SCardReconnect");
	}
	return pOrigSCardReconnect(hCard, dwShareMode, dwPreferredProtocols, dwInitialization, pdwActiveProtocol);
}


//SCardGetAttrib
WINSCARDAPI LONG WINAPI
pHookSCardGetAttrib(
	_In_    SCARDHANDLE hCard,
	_In_    DWORD dwAttrId,
	_Out_writes_bytes_opt_(*pcbAttrLen) LPBYTE pbAttr,
	_Inout_ LPDWORD pcbAttrLen
)
{
	if (logger) {
		logger->TraceInfo("SCardGetAttrib");
	}
	return pOrigSCardGetAttrib(hCard, dwAttrId, pbAttr, pcbAttrLen);
}


//SCardSetAttrib
WINSCARDAPI LONG WINAPI
pHookSCardSetAttrib(
	_In_ SCARDHANDLE hCard,
	_In_ DWORD dwAttrId,
	_In_reads_bytes_(cbAttrLen) LPCBYTE pbAttr,
	_In_ DWORD cbAttrLen
)
{
	if (logger) {
		logger->TraceInfo("SCardSetAttrib");
	}
	return pOrigSCardSetAttrib(hCard, dwAttrId, pbAttr, cbAttrLen);
}


//SCardControl
WINSCARDAPI LONG WINAPI
pHookSCardControl(
	_In_    SCARDHANDLE hCard,
	_In_    DWORD dwControlCode,
	_In_reads_bytes_(cbInBufferSize) LPCVOID lpInBuffer,
	_In_    DWORD cbInBufferSize,
	_Out_writes_bytes_(cbOutBufferSize) LPVOID lpOutBuffer,
	_In_    DWORD cbOutBufferSize,
	_Out_   LPDWORD lpBytesReturned
)
{
	if (logger) {
		logger->TraceInfo("SCardControl");
	}
	return pOrigSCardControl(hCard, dwControlCode, lpInBuffer, cbInBufferSize, lpOutBuffer, cbOutBufferSize, lpBytesReturned);
}


//SCardGetTransmitCount
#if (NTDDI_VERSION >= NTDDI_VISTA)
WINSCARDAPI LONG WINAPI
pHookSCardGetTransmitCount(
	_In_ SCARDHANDLE hCard,
	_Out_ LPDWORD pcTransmitCount)
{
	if (logger) {
		logger->TraceInfo("SCardGetTransmitCount");
	}
	return pOrigSCardGetTransmitCount(hCard, pcTransmitCount);

}
#endif // (NTDDI_VERSION >= NTDDI_VISTA)


//////////////////////////////////////////////////////////////////////////////////////
//
//	Private Helper Functions
//
//////////////////////////////////////////////////////////////////////////////////////

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
				   pOrigSCardCancel = (PFN_SCARDCANCEL)GetProcAddress(g_hDll, "SCardCancel");
				pOrigSCardReconnect = (PFN_SCARDRECONNECT)GetProcAddress(g_hDll, "SCardReconnect");
				pOrigSCardGetAttrib = (PFN_SCARDGETATTRIB)GetProcAddress(g_hDll, "SCardGetAttrib");
				pOrigSCardSetAttrib = (PFN_SCARDSETATTRIB)GetProcAddress(g_hDll, "SCardSetAttrib");
				  pOrigSCardControl = (PFN_SCARDCONTROL)GetProcAddress(g_hDll, "SCardControl");

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
		Mhook_SetHook((PVOID*)&pOrigSCardCancel, pHookSCardCancel);
		Mhook_SetHook((PVOID*)&pOrigSCardReconnect, pHookSCardReconnect);
		Mhook_SetHook((PVOID*)&pOrigSCardGetAttrib, pHookSCardGetAttrib);
		Mhook_SetHook((PVOID*)&pOrigSCardSetAttrib, pHookSCardSetAttrib);
		Mhook_SetHook((PVOID*)&pOrigSCardControl, pHookSCardControl);

#if (NTDDI_VERSION >= NTDDI_VISTA)
		pOrigSCardGetTransmitCount = (PFN_SCARDGETTRANSMITCOUNT)GetProcAddress(g_hDll, "SCardGetTransmitCount");
		Mhook_SetHook((PVOID*)&pOrigSCardGetTransmitCount, pHookSCardGetTransmitCount);
#endif // (NTDDI_VERSION >= NTDDI_VISTA)
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
		Mhook_Unhook((PVOID*)&pOrigSCardCancel);
		Mhook_Unhook((PVOID*)&pOrigSCardReconnect);
		Mhook_Unhook((PVOID*)&pOrigSCardGetAttrib);
		Mhook_Unhook((PVOID*)&pOrigSCardSetAttrib);
		Mhook_Unhook((PVOID*)&pOrigSCardControl);

#if (NTDDI_VERSION >= NTDDI_VISTA)
		Mhook_Unhook((PVOID*)&pOrigSCardGetTransmitCount);
#endif // (NTDDI_VERSION >= NTDDI_VISTA)
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