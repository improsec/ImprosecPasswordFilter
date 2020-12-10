#include <Windows.h>
#include <NTSecAPI.h>

#include "adler32.hpp"
#include "blacklist.hpp"
#include "logger.hpp"

#include <iostream>
#include <vector>

/*
	Password Filter reference used throughout this project can be found here:
	https://docs.microsoft.com/da-dk/windows/win32/secmgmt/password-filters
*/

#define STATUS_SUCCESS 0x00000000

static constexpr LPCWSTR lpDirectory = L"C:\\improsec";
static constexpr LPCWSTR lpConfigFile = L"enabled.txt";
static constexpr LPCWSTR lpListFile = L"blacklist.txt";
static constexpr LPCWSTR lpLogFile = L"errorlog.txt";

void HandleFilterEnabling(std::vector<uint8_t> const& data)
{
	if (!data.empty() && data[0] == '0')
		filter::blacklist::get().disable();
	else
		filter::blacklist::get().enable();
}

bool RetrieveFileData(std::wstring const& path, std::vector<uint8_t>& data)
{
	HANDLE hFile = CreateFile(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile != INVALID_HANDLE_VALUE && hFile != NULL)
	{
		DWORD dwSize = GetFileSize(hFile, NULL); // We don't expect blacklists to exceed 4 GB.
		DWORD dwRead = 0;

		if (dwSize != INVALID_FILE_SIZE && dwSize != 0)
		{
			data.resize(dwSize);

			while (dwRead < dwSize)
			{
				DWORD dwBytes = 0;

				if (!ReadFile(hFile, &data[dwRead], static_cast<DWORD>(data.size()) - dwRead, &dwBytes, NULL))
					break;

				dwRead += dwBytes;
			}

			return (dwRead == dwSize);
		}
	}

	return false;
}

bool CompareFileInfo(std::wstring const& directory, LPCWSTR lpFile, FILE_NOTIFY_INFORMATION* info, DWORD* adler, std::vector<uint8_t>& data)
{
	DWORD dwLength = static_cast<DWORD>(wcslen(lpFile));

	if (info->FileNameLength == dwLength * sizeof(WCHAR) &&
		_wcsnicmp(info->FileName, lpFile, dwLength) == 0)
	{
		data.clear();

		if (RetrieveFileData(directory + lpFile, data))
		{
			DWORD crc = adler32(0, &data[0], static_cast<uint32_t>(data.size()));

			if (crc != *adler)
			{
				*adler = crc;
				return true;
			}
		}
	}

	return false;
}

void ValidateModification(std::wstring const& directory, FILE_NOTIFY_INFORMATION* info)
{
	if (info == NULL)
		filter::logger::get().write("[warning] null-pointer given for file change information");
	else
	{
		static DWORD adler_conf = 0;
		static DWORD adler_list = 0;

		do
		{
			if (info->Action == FILE_ACTION_MODIFIED)
			{
				std::vector<uint8_t> data;

				/* Check if modifications were made to the blacklist file */
				if (CompareFileInfo(directory, lpListFile, info, &adler_list, data))
					filter::blacklist::get().load_file(directory + lpListFile);
				/* Check if modifications were made to the configuration file */
				else if (CompareFileInfo(directory, lpConfigFile, info, &adler_conf, data))
					HandleFilterEnabling(data);
			}

			info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(reinterpret_cast<uint8_t*>(info) + info->NextEntryOffset);
		}
		while (info->NextEntryOffset != 0);
	}
}

void MonitorThread()
{
	std::wstring directory = std::wstring(lpDirectory) + L'\\';

	/* Load configuration file to check if the password filter should be active */
	std::vector<uint8_t> data;

	filter::blacklist::get().enable();
	filter::logger::get().open(directory + lpLogFile);

	if (!RetrieveFileData(directory + lpConfigFile, data))
		filter::logger::get().write("[warning] failed to read 'enabled.txt' file - disabling might be problematic");
	else
		HandleFilterEnabling(data);

	/* Load blacklist entries from file */
	filter::blacklist::get().load_file(directory + lpListFile);

	/* Start monitoring changes to files in the root directory */
	HANDLE hDirectory = CreateFile(lpDirectory, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

	if (hDirectory == INVALID_HANDLE_VALUE || hDirectory == NULL)
		filter::logger::get().write("[error] could not create monitoring handle for improsec root folder");
	else
	{
		while (true)
		{
			DWORD bytes = 0;
			std::vector<uint8_t> buf(4096);

			if (!ReadDirectoryChangesW(hDirectory, &buf[0], static_cast<DWORD>(buf.size()), FALSE, FILE_NOTIFY_CHANGE_LAST_WRITE, &bytes, NULL, NULL))
				filter::logger::get().write("[error] failed to read directory changes from improsec root folder");
			else if (bytes > 0)
				ValidateModification(directory, reinterpret_cast<FILE_NOTIFY_INFORMATION*>(&buf[0]));

			Sleep(1000);
		}

		CloseHandle(hDirectory);
	}
}

/*
	The InitializeChangeNotify function is implemented by a password filter DLL. This function initializes the DLL.
	InitializeChangeNotify is called by the Local Security Authority (LSA) to verify that the password notification DLL is loaded and initialized.
*/
extern "C" __declspec(dllexport) BOOLEAN NTAPI InitializeChangeNotify()
{
	// TRUE = The password filter DLL is initialized
	// FALSE = The password filter DLL is not initialized

	return TRUE;
}

/*
	The PasswordChangeNotify function is implemented by a password filter DLL. It notifies the DLL that a password was changed.
	The PasswordChangeNotify function is called after the PasswordFilter function has been called successfully and the new password has been stored.
*/
extern "C" __declspec(dllexport) NTSTATUS NTAPI PasswordChangeNotify(UNICODE_STRING* UserName, ULONG RelativeId, UNICODE_STRING* NewPassword)
{
	if (NewPassword != NULL && NewPassword->Buffer != NULL)
		SecureZeroMemory(NewPassword->Buffer, NewPassword->Length);

	return STATUS_SUCCESS;
}

/*
	The PasswordFilter function is implemented by a password filter DLL. 
	The value returned by this function determines whether the new password is accepted by the system.
	All of the password filters installed on a system must return TRUE for the password change to take effect.
	Password change requests may be made when users specify a new password, accounts are created and when administrators override a password.
		=> SetOperation = TRUE if the password was set rather than changed
*/
extern "C" __declspec(dllexport) BOOLEAN NTAPI PasswordFilter(UNICODE_STRING* AccountName, UNICODE_STRING* FullName, UNICODE_STRING* Password, BOOLEAN SetOperation)
{
	BOOL fResult = filter::blacklist::get().contains(Password) ? TRUE : FALSE;

	//if (Password != NULL && Password->Buffer != NULL)
	//	SecureZeroMemory(Password->Buffer, Password->Length);

	// TRUE = The password is accepted by the filter (LSA evaluates the rest of the filter chain)
	// FALSE = The password is rejected by the filter (LSA returns the ERROR_ILL_FORMED_PASSWORD (1324) status code to the source of the password change request)

	return (fResult != TRUE);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpvReserved)
{
	static HANDLE hThread = NULL;

	if (dwReason == DLL_PROCESS_ATTACH)
		return ((hThread = CreateThread(NULL, 0, LPTHREAD_START_ROUTINE(&MonitorThread), NULL, 0, NULL)) != NULL);
	else if (dwReason == DLL_PROCESS_DETACH)
		return TerminateThread(hThread, 0);

	return TRUE;
}