#ifndef _LOGGER_H_
#define _LOGGER_H_
#include <Windows.h>
#include <stdio.h>
#include <string>

namespace LOGGER
{
	static const std::string strFatalPrefix = "FATAL\t";
	static const std::string strErrorPrefix = "ERROR\t";
	static const std::string strWarningPrefix = "WARN\t";
	static const std::string strInfoPrefix = "INFO\t";

	typedef enum _EnumLogLevel
	{
		LogLevel_Stop = 0,
		LogLevel_Fatal,
		LogLevel_Error,
		LogLevel_Warning,
		LogLevel_Info
	} EnumLogLevel;

	class CriticalSection
	{
		CRITICAL_SECTION m_cs;
	public:
		CriticalSection()
		{
			::InitializeCriticalSection(&m_cs);
		}
		virtual ~CriticalSection()
		{
			::DeleteCriticalSection(&m_cs);
		}
		void Lock()
		{
			::EnterCriticalSection(&m_cs);
		}
		void Unlock()
		{
			::LeaveCriticalSection(&m_cs);
		}
	};

	class CLogger
	{
	public:
		static CLogger *getInstance(
							const EnumLogLevel nLogLevel,
							const std::string strLogPath = "",
							const std::string strLogName = "");
		virtual ~CLogger();
	public:
		void TraceEx(const char *lpcszFormat, ...);
		void TraceInfo(const char *lpcszFormat, ...);
		void TraceInfoEx(const std::string msg = "");
		void ChangeLogLevel(EnumLogLevel nLevel);
		void PrintBuffer(const void* value, const long size);
	private:
		CLogger(const EnumLogLevel nLogLevel = EnumLogLevel::LogLevel_Info,
				const std::string strLogPath = "",
				const std::string strLogName = "");
		void Trace(const std::string &strLog);
		std::string getProcessName();
		std::string GetTime();
		std::string GetAppPathA();
		std::string FormatString(const char *lpcszFormat, ...);
		const char* path_file(const char *path, char splitter);
		const char* buf_spec(const void* buf_addr, const long buf_len);
	private:
		static CLogger*			m_Instance;
		static CriticalSection	m_csInstance;
		static CriticalSection	m_csLog;

		FILE*			m_pFileStream;
		EnumLogLevel	m_nLogLevel;
		std::string		m_strLogPath;
		std::string		m_strLogName;
		std::string		m_strLogFilePath;
	};
}
#endif