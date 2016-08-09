#include "stdafx.h"
#include "logger.h"
#include <time.h>
#include <stdarg.h>
#include <direct.h>
#include <string.h>
#include <vector>
#include <Dbghelp.h>
#pragma comment(lib,"Dbghelp.lib")

using namespace std;


namespace LOGGER
{
	CLogger*		CLogger::m_Instance = NULL;
	CriticalSection	CLogger::m_csInstance;


	CLogger *CLogger::getInstance(
						EnumLogLevel nLogLevel,
						const std::string strLogPath,
						const std::string strLogName)
	{
		if (m_Instance == NULL) {
			m_csInstance.Lock();
			if (m_Instance == NULL) {
				m_Instance = new CLogger(nLogLevel, strLogPath, strLogName);
			}
			m_csInstance.Unlock();
		}
		return m_Instance;
	}


	CLogger::CLogger(
				EnumLogLevel nLogLevel,
				const std::string strLogPath,
				const std::string strLogName)
		:m_nLogLevel(nLogLevel),
		m_strLogPath(strLogPath),
		m_strLogName(strLogName)
	{
		//log file path
		m_pFileStream = NULL;
		if (m_strLogPath.empty()) {
			m_strLogPath = GetAppPathA();
		}
		if (m_strLogPath.back() != '\\') {
			m_strLogPath.append("\\");
		}
		MakeSureDirectoryPathExists(m_strLogPath.c_str());

		//process name
		//char szProcess[MAX_PATH] = { 0 };
		//GetModuleFileNameA(NULL, szProcess, MAX_PATH);

		//process ID
		DWORD dwProcessID = GetCurrentProcessId();

		//log file name
		if (m_strLogName.empty()) {
			time_t curTime;
			time(&curTime);
			tm tm1;
			localtime_s(&tm1, &curTime);
			m_strLogName = FormatString(
							"%04d%02d%02d%02d%02d_%04d.log",
							tm1.tm_year + 1900,
							tm1.tm_mon + 1,
							tm1.tm_mday,
							tm1.tm_hour,
							tm1.tm_min,
							dwProcessID
							);
		}
		m_strLogFilePath = m_strLogPath.append(m_strLogName);
		fopen_s(&m_pFileStream, m_strLogFilePath.c_str(), "a+");
	}


	CLogger::~CLogger()
	{
		delete m_Instance;
		if (m_pFileStream) {
			fclose(m_pFileStream);
			m_pFileStream = NULL;
		}
	}


	const char *CLogger::path_file(const char *path, char splitter)
	{
		return strrchr(path, splitter) ? strrchr(path, splitter) + 1 : path;
	}


	void CLogger::TraceInfoEx(const string msg)
	{
		TraceInfo(msg.c_str());
	}


	void CLogger::TraceInfo(const char *lpcszFormat, ...)
	{
		if (EnumLogLevel::LogLevel_Info > m_nLogLevel)
			return;
		string strResult;
		if (NULL != lpcszFormat) {
			va_list marker = NULL;
			va_start(marker, lpcszFormat);
			size_t nLength = _vscprintf(lpcszFormat, marker) + 1;
			std::vector<char> vBuffer(nLength, '\0');
			int nWritten = _vsnprintf_s(&vBuffer[0], vBuffer.size(), nLength, lpcszFormat, marker);
			if (nWritten > 0) {
				strResult = &vBuffer[0];
			}
			va_end(marker);
		}
		if (strResult.empty()) {
			return;
		}
		string strFileLine = FormatString("%s:%d\t", path_file(__FILE__, '\\'), __LINE__);
		string strLog = strInfoPrefix;
		strLog.append(GetTime());
		strLog.append(strFileLine);
		strLog.append(strResult);
		Trace(strLog);
	}


	string CLogger::GetTime()
	{
		time_t curTime;
		time(&curTime);
		tm tm1;
		localtime_s(&tm1, &curTime);
		string strTime = FormatString("%04d-%02d-%02d %02d:%02d:%02d ", tm1.tm_year + 1900, tm1.tm_mon + 1, tm1.tm_mday, tm1.tm_hour, tm1.tm_min, tm1.tm_sec);
		return strTime;
	}


	void CLogger::ChangeLogLevel(EnumLogLevel nLevel)
	{
		m_nLogLevel = nLevel;
	}


	void CLogger::Trace(const string &strLog)
	{
		try {
			if (NULL == m_pFileStream) {
				m_csInstance.Lock();
				fopen_s(&m_pFileStream, m_strLogFilePath.c_str(), "a+");
				if (NULL == m_pFileStream) {
					m_csInstance.Unlock();
					return;
				}
			}
			fprintf(m_pFileStream, "%s\n", strLog.c_str());
			fflush(m_pFileStream);
			m_csInstance.Unlock();
		}
		catch (...) {
			m_csInstance.Unlock();
		}
	}


	string CLogger::GetAppPathA()
	{
		char szFilePath[MAX_PATH] = { 0 };
		char szDrive[MAX_PATH] = { 0 };
		char szDir[MAX_PATH] = { 0 };
		char szFileName[MAX_PATH] = { 0 };
		char szExt[MAX_PATH] = { 0 };

		GetModuleFileNameA(NULL, szFilePath, sizeof(szFilePath));
		_splitpath_s(szFilePath, szDrive, szDir, szFileName, szExt);
		string str(szDrive);
		str.append(szDir);
		return str;
	}


	string CLogger::FormatString(const char *lpcszFormat, ...)
	{
		string strResult;
		if (NULL != lpcszFormat) {
			va_list marker = NULL;
			va_start(marker, lpcszFormat);
			size_t nLength = _vscprintf(lpcszFormat, marker) + 1;
			std::vector<char> vBuffer(nLength, '\0');
			int nWritten = _vsnprintf_s(&vBuffer[0], vBuffer.size(), nLength, lpcszFormat, marker);
			if (nWritten > 0) {
				strResult = &vBuffer[0];
			}
			va_end(marker);
		}
		return strResult;
	}
}