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
typedef LONG	(WINAPI *PFN_SCARD_ESTABLISH_CONTEXT)(_In_ DWORD, _Reserved_ LPCVOID, _Reserved_ LPCVOID, _Out_ LPSCARDCONTEXT);
typedef LONG	(WINAPI *PFN_SCARD_RELEASE_CONTEXT)(_In_ SCARDCONTEXT);
typedef LONG	(WINAPI *PFN_SCARD_IS_VALID_CONTEXT)(_In_ SCARDCONTEXT);
typedef LONG	(WINAPI *PFN_SCARD_FREE_MEMORY)(_In_ SCARDCONTEXT, _In_ LPCVOID);
typedef LONG	(WINAPI *PFN_SCARD_DISCONNECT)(_In_ SCARDHANDLE, _In_ DWORD);
typedef LONG	(WINAPI *PFN_SCARD_BEGIN_TRANSACTION)(_In_ SCARDHANDLE);
typedef LONG	(WINAPI *PFN_SCARD_END_TRANSACTION)(_In_ SCARDHANDLE, _In_ DWORD);
typedef LONG	(WINAPI *PFN_SCARD_TRANSMIT)(_In_ SCARDHANDLE, _In_ LPCSCARD_IO_REQUEST, _In_reads_bytes_(cbSendLength) LPCBYTE, _In_ DWORD, _Inout_opt_ LPSCARD_IO_REQUEST, _Out_writes_bytes_(*pcbRecvLength) LPBYTE, _Inout_ LPDWORD);
typedef HANDLE	(WINAPI *PFN_SCARD_ACCESS_STARTED_EVENT)(void);
typedef void	(WINAPI *PFN_SCARD_RELEASE_STARTED_EVENT)(void);
typedef LONG	(WINAPI *PFN_SCARD_CANCEL)(_In_ SCARDCONTEXT);
typedef LONG	(WINAPI *PFN_SCARD_RECONNECT)(_In_ SCARDHANDLE, _In_ DWORD, _In_ DWORD, _In_ DWORD, _Out_opt_ LPDWORD);
typedef LONG	(WINAPI *PFN_SCARD_GET_ATTRIB)(_In_ SCARDHANDLE, _In_ DWORD, _Out_writes_bytes_opt_(*pcbAttrLen) LPBYTE, _Inout_ LPDWORD);
typedef LONG	(WINAPI *PFN_SCARD_SET_ATTRIB)(_In_ SCARDHANDLE, _In_ DWORD, _In_reads_bytes_(cbAttrLen) LPCBYTE, _In_ DWORD);
typedef LONG	(WINAPI *PFN_SCARD_CONTROL)(_In_ SCARDHANDLE, _In_ DWORD, _In_reads_bytes_(cbInBufferSize) LPCVOID, _In_ DWORD, _Out_writes_bytes_(cbOutBufferSize) LPVOID, _In_ DWORD, _Out_ LPDWORD);

#if (NTDDI_VERSION >= NTDDI_VISTA)
typedef LONG	(WINAPI *PFN_SCARD_GET_TRANSMIT_COUNT)(_In_ SCARDHANDLE, _Out_ LPDWORD);
#endif // (NTDDI_VERSION >= NTDDI_VISTA)

//typedef LONG	(WINAPI *PFN_SCARD_CANCEL_TRANSACTION)(_In_ SCARDHANDLE);//CANNOT hook - cause RDP crash


//initialization of WinSCard API function pointers
PFN_SCARD_ESTABLISH_CONTEXT			pOrigSCardEstablishContext = NULL;
PFN_SCARD_RELEASE_CONTEXT			pOrigSCardReleaseContext = NULL;
PFN_SCARD_IS_VALID_CONTEXT			pOrigSCardIsValidContext = NULL;
PFN_SCARD_FREE_MEMORY				pOrigSCardFreeMemory = NULL;
PFN_SCARD_DISCONNECT				pOrigSCardDisconnect = NULL;
PFN_SCARD_BEGIN_TRANSACTION			pOrigSCardBeginTransaction = NULL;
PFN_SCARD_END_TRANSACTION			pOrigSCardEndTransaction = NULL;
PFN_SCARD_TRANSMIT					pOrigSCardTransmit = NULL;
PFN_SCARD_ACCESS_STARTED_EVENT		pOrigSCardAccessStartedEvent = NULL;
PFN_SCARD_RELEASE_STARTED_EVENT		pOrigSCardReleaseStartedEvent = NULL;
PFN_SCARD_CANCEL					pOrigSCardCancel = NULL;
PFN_SCARD_RECONNECT					pOrigSCardReconnect = NULL;
PFN_SCARD_GET_ATTRIB				pOrigSCardGetAttrib = NULL;
PFN_SCARD_SET_ATTRIB				pOrigSCardSetAttrib = NULL;
PFN_SCARD_CONTROL					pOrigSCardControl = NULL;
#if (NTDDI_VERSION >= NTDDI_VISTA)
PFN_SCARD_GET_TRANSMIT_COUNT		pOrigSCardGetTransmitCount = NULL;
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
	LONG ret = 0;
	if (logger) {
		logger->TraceInfo("SCardTransmit");
		if (pioSendPci) {
			logger->TraceInfo("pioSendPci: 0x%p", (void *)&pioSendPci);
			logger->TraceInfo("pioSendPci->dwProtocol: 0x%x		pioSendPci->cbPciLength: 0x%x", pioSendPci->dwProtocol, pioSendPci->cbPciLength);
		}
		logger->TraceInfo("pbSendBuffer:");
		logger->PrintBuffer((void *)pbSendBuffer, cbSendLength);

		ret = pOrigSCardTransmit(hCard, pioSendPci, pbSendBuffer, cbSendLength, pioRecvPci, pbRecvBuffer, pcbRecvLength);

		if (pioRecvPci) {
			logger->TraceInfo("pioRecvPci: 0x%p", (void *)&pioRecvPci);
			logger->TraceInfo("pioRecvPci->dwProtocol: 0x%x		pioRecvPci->cbPciLength: 0x%x", pioRecvPci->dwProtocol, pioRecvPci->cbPciLength);
		}
		logger->TraceInfo("pbRecvBuffer:");
		logger->PrintBuffer((void *)pbRecvBuffer, *pcbRecvLength);
	}
	return ret;
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
		 pOrigSCardEstablishContext = (PFN_SCARD_ESTABLISH_CONTEXT)GetProcAddress(g_hDll, "SCardEstablishContext");
		   pOrigSCardReleaseContext = (PFN_SCARD_RELEASE_CONTEXT)GetProcAddress(g_hDll, "SCardReleaseContext");
		   pOrigSCardIsValidContext = (PFN_SCARD_IS_VALID_CONTEXT)GetProcAddress(g_hDll, "SCardIsValidContext");
			   pOrigSCardFreeMemory = (PFN_SCARD_FREE_MEMORY)GetProcAddress(g_hDll, "SCardFreeMemory");
			   pOrigSCardDisconnect = (PFN_SCARD_DISCONNECT)GetProcAddress(g_hDll, "SCardDisconnect");
		 pOrigSCardBeginTransaction = (PFN_SCARD_BEGIN_TRANSACTION)GetProcAddress(g_hDll, "SCardBeginTransaction");
		   pOrigSCardEndTransaction = (PFN_SCARD_END_TRANSACTION)GetProcAddress(g_hDll, "SCardEndTransaction");
		         pOrigSCardTransmit = (PFN_SCARD_TRANSMIT)GetProcAddress(g_hDll, "SCardTransmit");
	   pOrigSCardAccessStartedEvent = (PFN_SCARD_ACCESS_STARTED_EVENT)GetProcAddress(g_hDll, "SCardAccessStartedEvent");
	  pOrigSCardReleaseStartedEvent = (PFN_SCARD_RELEASE_STARTED_EVENT)GetProcAddress(g_hDll, "SCardReleaseStartedEvent");
				   pOrigSCardCancel = (PFN_SCARD_CANCEL)GetProcAddress(g_hDll, "SCardCancel");
				pOrigSCardReconnect = (PFN_SCARD_RECONNECT)GetProcAddress(g_hDll, "SCardReconnect");
				pOrigSCardGetAttrib = (PFN_SCARD_GET_ATTRIB)GetProcAddress(g_hDll, "SCardGetAttrib");
				pOrigSCardSetAttrib = (PFN_SCARD_SET_ATTRIB)GetProcAddress(g_hDll, "SCardSetAttrib");
				  pOrigSCardControl = (PFN_SCARD_CONTROL)GetProcAddress(g_hDll, "SCardControl");

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
		pOrigSCardGetTransmitCount = (PFN_SCARD_GET_TRANSMIT_COUNT)GetProcAddress(g_hDll, "SCardGetTransmitCount");
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