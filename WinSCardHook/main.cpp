#include "stdafx.h"
#include <stdio.h>
#include <mutex>
#include <winscard.h>
#include "mhook/mhook-lib/mhook.h"
#include "Logger.h"


// Global Variables
#if 0
#define				APP_HOOKING		L"C:\\Windows\\system32\\LogonUI.exe"
#endif
#if 0
#define				APP_HOOKING		L"C:\\pivman\\yubico-piv-tool.exe"
#endif
#if 0
#define				APP_HOOKING		L"C:\\Yubico\\open_src_my\\ykpiv_test\\x64\\Debug\\ykpiv_test.exe"
#endif
#if 1
#define				APP_HOOKING		L"C:\\Yubico\\open_src_my\\SCMiniDriverTest\\x64\\Debug\\SCMiniDriverTest.exe"
#endif

#define				LOG_PATH		"C:\\Logs\\"
#define				DLL_HOOKED_W	L"WinSCard.dll"
#define				DLL_HOOKED		"WinSCard.dll"
LOGGER::CLogger*	logger = NULL;
HMODULE				g_hDll = 0;


//typedef of WinSCard API function pointers
typedef LONG	(WINAPI *PFN_SCARD_ESTABLISH_CONTEXT)(_In_ DWORD, _Reserved_ LPCVOID, _Reserved_ LPCVOID, _Out_ LPSCARDCONTEXT);
typedef LONG	(WINAPI *PFN_SCARD_RELEASE_CONTEXT)(_In_ SCARDCONTEXT);
typedef LONG	(WINAPI *PFN_SCARD_IS_VALID_CONTEXT)(_In_ SCARDCONTEXT);
typedef LONG	(WINAPI *PFN_SCARD_FREE_MEMORY)(_In_ SCARDCONTEXT, _In_ LPCVOID);
typedef LONG	(WINAPI *PFN_SCARD_CONNECT)(_In_ SCARDCONTEXT, _In_ LPCWSTR, _In_ DWORD, _In_ DWORD, _Out_ LPSCARDHANDLE, _Out_ LPDWORD);
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
PFN_SCARD_CONNECT					pOrigSCardConnect = NULL;
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


//scardRetVal2String
const char* scardRetVal2String(DWORD dwRet) {
	switch (dwRet)
	{
	case SCARD_S_SUCCESS:	return "SCARD_S_SUCCESS";
	case ERROR_BROKEN_PIPE:	return "ERROR_BROKEN_PIPE";
	case SCARD_E_BAD_SEEK:	return "SCARD_E_BAD_SEEK";
	case SCARD_E_CANCELLED:	return "SCARD_E_CANCELLED";
	case SCARD_E_CANT_DISPOSE:	return "SCARD_E_CANT_DISPOSE";
	case SCARD_E_CARD_UNSUPPORTED:	return "SCARD_E_CARD_UNSUPPORTED";
	case SCARD_E_CERTIFICATE_UNAVAILABLE:	return "SCARD_E_CERTIFICATE_UNAVAILABLE";
	case SCARD_E_COMM_DATA_LOST:	return "SCARD_E_COMM_DATA_LOST";
	case SCARD_E_DIR_NOT_FOUND:	return "SCARD_E_DIR_NOT_FOUND";
	case SCARD_E_DUPLICATE_READER:	return "SCARD_E_DUPLICATE_READER";
	case SCARD_E_FILE_NOT_FOUND:	return "SCARD_E_FILE_NOT_FOUND";
	case SCARD_E_ICC_CREATEORDER:	return "SCARD_E_ICC_CREATEORDER";
	case SCARD_E_ICC_INSTALLATION:	return "SCARD_E_ICC_INSTALLATION";
	case SCARD_E_INSUFFICIENT_BUFFER:	return "SCARD_E_INSUFFICIENT_BUFFER";
	case SCARD_E_INVALID_ATR:	return "SCARD_E_INVALID_ATR";
	case SCARD_E_INVALID_CHV:	return "SCARD_E_INVALID_CHV";
	case SCARD_E_INVALID_HANDLE:	return "SCARD_E_INVALID_HANDLE";
	case SCARD_E_INVALID_PARAMETER:	return "SCARD_E_INVALID_PARAMETER";
	case SCARD_E_INVALID_TARGET:	return "SCARD_E_INVALID_TARGET";
	case SCARD_E_INVALID_VALUE:	return "SCARD_E_INVALID_VALUE";
	case SCARD_E_NO_ACCESS:	return "SCARD_E_NO_ACCESS";
	case SCARD_E_NO_DIR:	return "SCARD_E_NO_DIR";
	case SCARD_E_NO_FILE:	return "SCARD_E_NO_FILE";
	case SCARD_E_NO_KEY_CONTAINER:	return "SCARD_E_NO_KEY_CONTAINER";
	case SCARD_E_NO_MEMORY:	return "SCARD_E_NO_MEMORY";
	case SCARD_E_NO_PIN_CACHE:	return "SCARD_E_NO_PIN_CACHE";
	case SCARD_E_NO_READERS_AVAILABLE:	return "SCARD_E_NO_READERS_AVAILABLE";
	case SCARD_E_NO_SERVICE:	return "SCARD_E_NO_SERVICE";
	case SCARD_E_NO_SMARTCARD:	return "SCARD_E_NO_SMARTCARD";
	case SCARD_E_NO_SUCH_CERTIFICATE:	return "SCARD_E_NO_SUCH_CERTIFICATE";
	case SCARD_E_NOT_READY:	return "SCARD_E_NOT_READY";
	case SCARD_E_NOT_TRANSACTED:	return "SCARD_E_NOT_TRANSACTED";
	case SCARD_E_PCI_TOO_SMALL:	return "SCARD_E_PCI_TOO_SMALL";
	case SCARD_E_PIN_CACHE_EXPIRED:	return "SCARD_E_PIN_CACHE_EXPIRED";
	case SCARD_E_PROTO_MISMATCH:	return "SCARD_E_PROTO_MISMATCH";
	case SCARD_E_READ_ONLY_CARD:	return "SCARD_E_READ_ONLY_CARD";
	case SCARD_E_READER_UNAVAILABLE:	return "SCARD_E_READER_UNAVAILABLE";
	case SCARD_E_READER_UNSUPPORTED:	return "SCARD_E_READER_UNSUPPORTED";
	case SCARD_E_SERVER_TOO_BUSY:	return "SCARD_E_SERVER_TOO_BUSY";
	case SCARD_E_SERVICE_STOPPED:	return "SCARD_E_SERVICE_STOPPED";
	case SCARD_E_SHARING_VIOLATION:	return "SCARD_E_SHARING_VIOLATION";
	case SCARD_E_SYSTEM_CANCELLED:	return "SCARD_E_SYSTEM_CANCELLED";
	case SCARD_E_TIMEOUT:	return "SCARD_E_TIMEOUT";
	case SCARD_E_UNEXPECTED:	return "SCARD_E_UNEXPECTED";
	case SCARD_E_UNKNOWN_CARD:	return "SCARD_E_UNKNOWN_CARD";
	case SCARD_E_UNKNOWN_READER:	return "SCARD_E_UNKNOWN_READER";
	case SCARD_E_UNKNOWN_RES_MNG:	return "SCARD_E_UNKNOWN_RES_MNG";
	case SCARD_E_UNSUPPORTED_FEATURE:	return "SCARD_E_UNSUPPORTED_FEATURE";
	case SCARD_E_WRITE_TOO_MANY:	return "SCARD_E_WRITE_TOO_MANY";
	case SCARD_F_COMM_ERROR:	return "SCARD_F_COMM_ERROR";
	case SCARD_F_INTERNAL_ERROR:	return "SCARD_F_INTERNAL_ERROR";
	case SCARD_F_UNKNOWN_ERROR:	return "SCARD_F_UNKNOWN_ERROR";
	case SCARD_F_WAITED_TOO_LONG:	return "SCARD_F_WAITED_TOO_LONG";
	case SCARD_P_SHUTDOWN:	return "SCARD_P_SHUTDOWN";
	case SCARD_W_CANCELLED_BY_USER:	return "SCARD_W_CANCELLED_BY_USER";
	case SCARD_W_CACHE_ITEM_NOT_FOUND:	return "SCARD_W_CACHE_ITEM_NOT_FOUND";
	case SCARD_W_CACHE_ITEM_STALE:	return "SCARD_W_CACHE_ITEM_STALE";
	case SCARD_W_CACHE_ITEM_TOO_BIG:	return "SCARD_W_CACHE_ITEM_TOO_BIG";
	case SCARD_W_CARD_NOT_AUTHENTICATED:	return "SCARD_W_CARD_NOT_AUTHENTICATED";
	case SCARD_W_CHV_BLOCKED:	return "SCARD_W_CHV_BLOCKED";
	case SCARD_W_EOF:	return "SCARD_W_EOF";
	case SCARD_W_REMOVED_CARD:	return "SCARD_W_REMOVED_CARD";
	case SCARD_W_RESET_CARD:	return "SCARD_W_RESET_CARD";
	case SCARD_W_SECURITY_VIOLATION:	return "SCARD_W_SECURITY_VIOLATION";
	case SCARD_W_UNPOWERED_CARD:	return "SCARD_W_UNPOWERED_CARD";
	case SCARD_W_UNRESPONSIVE_CARD:	return "SCARD_W_UNRESPONSIVE_CARD";
	case SCARD_W_UNSUPPORTED_CARD:	return "SCARD_W_UNSUPPORTED_CARD";
	case SCARD_W_WRONG_CHV:	return "SCARD_W_WRONG_CHV";
	default: return "DEFINED";
	}
}
//scope2String
const char* scope2String(DWORD dwScope) {
	switch (dwScope)
	{
	case SCARD_AUTOALLOCATE: return "SCARD_AUTOALLOCATE";
	case SCARD_SCOPE_USER: return "SCARD_SCOPE_USER";
	case SCARD_SCOPE_TERMINAL: return "SCARD_SCOPE_TERMINAL";
	case SCARD_SCOPE_SYSTEM: return "SCARD_SCOPE_SYSTEM";
	default: return "DEFINED";
	}
}
//shareMode2String
const char* shareMode2String(DWORD dwShareMode) {
	switch (dwShareMode)
	{
	case SCARD_SHARE_SHARED: return "SCARD_SHARE_SHARED";
	case SCARD_SHARE_EXCLUSIVE: return "SCARD_SHARE_EXCLUSIVE";
	case SCARD_SHARE_DIRECT: return "SCARD_SHARE_DIRECT";
	default: return "DEFINED";
	}
}
//protocols2String
char* protocols2String(char* pbuf, DWORD dwProto) {
	if (dwProto & SCARD_PROTOCOL_T0)
		strcat(pbuf, "SCARD_PROTOCOL_T0");
	if (dwProto & SCARD_PROTOCOL_T1)
		strcat(pbuf, " SCARD_PROTOCOL_T1");
	if (dwProto & SCARD_PROTOCOL_RAW)
		strcat(pbuf, " SCARD_PROTOCOL_RAW");
	if (SCARD_PROTOCOL_UNDEFINED == dwProto)
		strcpy(pbuf, "SCARD_PROTOCOL_UNDEFINED");
	return pbuf;
}
//cardActionTaken2String
const char* cardActionTaken2String(DWORD dwAction) {
	switch (dwAction) {
	case SCARD_LEAVE_CARD: return "SCARD_LEAVE_CARD";
	case SCARD_RESET_CARD: return "SCARD_RESET_CARD";
	case SCARD_UNPOWER_CARD: return "SCARD_UNPOWER_CARD";
	case SCARD_EJECT_CARD: return "SCARD_EJECT_CARD";
	default: return "DEFINED";
	}
}


//SCardEstablishContext
WINSCARDAPI LONG WINAPI
pHookSCardEstablishContext(
	_In_		DWORD			dwScope,
	_Reserved_	LPCVOID			pvReserved1,
	_Reserved_	LPCVOID			pvReserved2,
	_Out_		LPSCARDCONTEXT	phContext
)
{
	LONG ret;
	if (logger) {
		logger->TraceInfo("--- SCardEstablishContext ---");
		logger->TraceInfo("    IN dwScope: %s", scope2String(dwScope));
	}
	ret = pOrigSCardEstablishContext(dwScope, pvReserved1, pvReserved2, phContext);
	if (logger) {
		logger->TraceInfo("    OUT phContext: %x", *phContext);
		logger->TraceInfo("    SCardEstablishContext returns: %s", scardRetVal2String(ret));
	}
	return ret;
}


//SCardReleaseContext
WINSCARDAPI LONG WINAPI
pHookSCardReleaseContext(
	_In_	SCARDCONTEXT	hContext
)
{
	LONG ret;
	if (logger) {
		logger->TraceInfo("=== SCardReleaseContext ===============");
		logger->TraceInfo("    IN hContext: %x", hContext);
	}
	ret = pOrigSCardReleaseContext(hContext);
	if (logger) {
		logger->TraceInfo("    SCardReleaseContext returns: %s", scardRetVal2String(ret));
	}
	return ret;
}


//SCardIsValidContext
WINSCARDAPI LONG WINAPI
pHookSCardIsValidContext(
	_In_	SCARDCONTEXT	hContext
)
{
	LONG ret;
	if (logger) {
		logger->TraceInfo("    SCardIsValidContext");
		logger->TraceInfo("    IN hContext: %x", hContext);
	}
	ret = pOrigSCardIsValidContext(hContext);
	if (logger) {
		logger->TraceInfo("    SCardIsValidContext returns: %s", scardRetVal2String(ret));
	}
	return ret;
}


//SCardFreeMemory
WINSCARDAPI LONG WINAPI
pHookSCardFreeMemory(
	_In_	SCARDCONTEXT	hContext,
	_In_	LPCVOID			pvMem
)
{
	if (logger) {
		logger->TraceInfo("    SCardFreeMemory");
	}
	return pOrigSCardFreeMemory(hContext, pvMem);
}


//SCardConnect
WINSCARDAPI LONG WINAPI
pHookSCardConnect(
	_In_    SCARDCONTEXT hContext,
	_In_    LPCWSTR szReader,
	_In_    DWORD dwShareMode,
	_In_    DWORD dwPreferredProtocols,
	_Out_   LPSCARDHANDLE phCard,
	_Out_   LPDWORD pdwActiveProtocol
)
{
	if (logger) {
		logger->TraceInfo("    SCardConnect");
	}
	return pOrigSCardConnect(hContext, szReader, dwShareMode, dwPreferredProtocols, phCard, pdwActiveProtocol);
}


//SCardDisconnect
WINSCARDAPI LONG WINAPI
pHookSCardDisconnect(
	_In_	SCARDHANDLE	hCard,
	_In_	DWORD		dwDisposition
)
{
	LONG ret;
	if (logger) {
		logger->TraceInfo("    SCardDisconnect");
		logger->TraceInfo("    IN hCard: %x", hCard);
		logger->TraceInfo("    IN dwDisposition: %s", cardActionTaken2String(dwDisposition));
	}
	ret = pOrigSCardDisconnect(hCard, dwDisposition);
	if (logger) {
		logger->TraceInfo("    SCardDisconnect returns: %s", scardRetVal2String(ret));
	}
	return ret;
}


//SCardBeginTransaction
WINSCARDAPI LONG WINAPI
pHookSCardBeginTransaction(
	_In_	SCARDHANDLE	hCard
)
{
	if (logger) {
		logger->TraceInfo("    SCardBeginTransaction");
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
		logger->TraceInfo("    SCardEndTransaction");
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
		logger->TraceInfo("    SCardTransmit");
		logger->TraceInfo("    IN hCard: %x", hCard);
		if (pioSendPci) {
			logger->TraceInfo("    IN pioSendPci: 0x%p", (void *)&pioSendPci);
			logger->TraceInfo("    IN pioSendPci->dwProtocol: 0x%x		pioSendPci->cbPciLength: 0x%x", pioSendPci->dwProtocol, pioSendPci->cbPciLength);
		}
		logger->TraceInfo("    IN pbSendBuffer:");
		logger->PrintBuffer((void *)pbSendBuffer, cbSendLength);

		ret = pOrigSCardTransmit(hCard, pioSendPci, pbSendBuffer, cbSendLength, pioRecvPci, pbRecvBuffer, pcbRecvLength);

		if (pioRecvPci) {
			logger->TraceInfo("    OUT pioRecvPci: 0x%p", (void *)&pioRecvPci);
			logger->TraceInfo("    OUT pioRecvPci->dwProtocol: 0x%x		pioRecvPci->cbPciLength: 0x%x", pioRecvPci->dwProtocol, pioRecvPci->cbPciLength);
		}
		logger->TraceInfo("    OUT pbRecvBuffer:");
		logger->PrintBuffer((void *)pbRecvBuffer, *pcbRecvLength);
		logger->TraceInfo("    SCardTransmit returns: %s", scardRetVal2String(ret));
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
		logger->TraceInfo("    SCardAccessStartedEvent");
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
		logger->TraceInfo("    SCardReleaseStartedEvent");
	}
	pOrigSCardReleaseStartedEvent();
}


//SCardCancel
WINSCARDAPI LONG WINAPI
pHookSCardCancel(
	_In_	SCARDCONTEXT hContext
)
{
	LONG ret = 0;
	if (logger) {
		logger->TraceInfo("    SCardCancel");
		logger->TraceInfo("    IN hContext: %x", hContext);
	}
	ret = pOrigSCardCancel(hContext);
	if (logger) {
		logger->TraceInfo("    SCardCancel returns: %s", scardRetVal2String(ret));
	}
	return ret;
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
	LONG ret;
	if (logger) {
		logger->TraceInfo("    SCardReconnect");
		logger->TraceInfo("    IN hCard: %x", hCard);
		logger->TraceInfo("    IN dwShareMode: %s", shareMode2String(dwShareMode));
		char buf[MAX_PATH];
		memset(buf, 0, sizeof(buf));
		logger->TraceInfo("    IN dwPreferredProtocols: %s", protocols2String(&buf[0], dwPreferredProtocols));
		logger->TraceInfo("    IN dwInitialization: %s", cardActionTaken2String(dwInitialization));
	}
	ret = pOrigSCardReconnect(hCard, dwShareMode, dwPreferredProtocols, dwInitialization, pdwActiveProtocol);
	if (logger) {
		char buf[MAX_PATH];
		memset(buf, 0, sizeof(buf));
		logger->TraceInfo("    OUT pdwActiveProtocol: %s", protocols2String(&buf[0], *pdwActiveProtocol));
		logger->TraceInfo("    SCardReconnect returns: %s", scardRetVal2String(ret));
	}
	return ret;
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
		logger->TraceInfo("    SCardGetAttrib");
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
		logger->TraceInfo("    SCardSetAttrib");
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
		logger->TraceInfo("    SCardControl");
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
	LONG ret;
	if (logger) {
		logger->TraceInfo("    SCardGetTransmitCount");
		logger->TraceInfo("    IN hCard: %x", hCard);
	}
	ret = pOrigSCardGetTransmitCount(hCard, pcTransmitCount);
	if (logger) {
		logger->TraceInfo("    OUT pcTransmitCount: %d", *pcTransmitCount);
		logger->TraceInfo("    SCardGetTransmitCount returns: %s", scardRetVal2String(ret));
	}
	return ret;
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
		logger = LOGGER::CLogger::getInstance(LOGGER::LogLevel_Info, LOG_PATH, "");
		if (logger) { logger->TraceInfo("%s is calling %s", strProcessName.c_str(), DLL_HOOKED); }
		return true;
	}
	return false;
}


//hookInitialize
void hookInitialize() {
		g_hDll = LoadLibrary(DLL_HOOKED_W);

		//GetProcAddress
		 pOrigSCardEstablishContext = (PFN_SCARD_ESTABLISH_CONTEXT)GetProcAddress(g_hDll, "SCardEstablishContext");
		   pOrigSCardReleaseContext = (PFN_SCARD_RELEASE_CONTEXT)GetProcAddress(g_hDll, "SCardReleaseContext");
		   pOrigSCardIsValidContext = (PFN_SCARD_IS_VALID_CONTEXT)GetProcAddress(g_hDll, "SCardIsValidContext");
			   pOrigSCardFreeMemory = (PFN_SCARD_FREE_MEMORY)GetProcAddress(g_hDll, "SCardFreeMemory");
			      pOrigSCardConnect = (PFN_SCARD_CONNECT)GetProcAddress(g_hDll, "SCardConnect");
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
		//Mhook_SetHook((PVOID*)&pOrigSCardConnect, pHookSCardConnect);
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


//hookFinalize
void hookFinalize() {
		//Mhook_Unhook
		Mhook_Unhook((PVOID*)&pOrigSCardEstablishContext);
		Mhook_Unhook((PVOID*)&pOrigSCardReleaseContext);
		Mhook_Unhook((PVOID*)&pOrigSCardIsValidContext);
		Mhook_Unhook((PVOID*)&pOrigSCardFreeMemory);
		//Mhook_Unhook((PVOID*)&pOrigSCardConnect);
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


//DllMain
BOOL WINAPI DllMain(
    __in HINSTANCE  hInstance,
    __in DWORD      Reason,
    __in LPVOID     Reserved
    )
{
	switch (Reason) {
		case DLL_PROCESS_ATTACH:
			if (shouldHook()) {
				hookInitialize();
			} else {
				return FALSE;
			}
		break;

		case DLL_PROCESS_DETACH:
			hookFinalize();
		break;
	}
    return TRUE;
}