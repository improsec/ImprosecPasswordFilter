#include "hash_scanner.hpp"
#include "adler32.hpp"
#include "blacklist.hpp"
#include "logger.hpp"

#include <Windows.h>

#include <iostream>
#include <vector>

/*
	Password Filter reference used throughout this project can be found here:
	https://docs.microsoft.com/da-dk/windows/win32/secmgmt/password-filters
*/

#define STATUS_SUCCESS 0x00000000

static bool fIncludeLeaked = false;
static wchar_t lpDirectory[256] = { 0 };

static constexpr LPCWSTR lpDirectoryPath = L"C:\\improsec-filter";
static constexpr LPCWSTR lpLogFile = L"errorlog.txt";

static constexpr LPCWSTR lpListFile1 = L"weak-phrases.txt";
static constexpr LPCWSTR lpConfFile1 = L"weak-enabled.txt";
static constexpr LPCWSTR lpListFile2 = L"leaked-passwords.bin";
static constexpr LPCWSTR lpConfFile2 = L"leaked-enabled.txt";

void HandleFilterEnabling(std::vector<uint8_t> const& data, bool weak)
{
	if (weak)
	{
		if (!data.empty() && data[0] == '1')
			filter::blacklist::get().enable();
		else
			filter::blacklist::get().disable();
	}
	else if (fIncludeLeaked)
	{
		if (!data.empty() && data[0] == '1')
			filter::hash_scanner::get().enable();
		else
			filter::hash_scanner::get().disable();
	}
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

		CloseHandle(hFile);
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
				if (CompareFileInfo(directory, lpListFile1, info, &adler_list, data))
					filter::blacklist::get().load_file(directory + lpListFile1);
				else if (CompareFileInfo(directory, lpListFile2, info, &adler_conf, data))
					filter::hash_scanner::get().open(directory + lpListFile2);
				else if (CompareFileInfo(directory, lpConfFile1, info, &adler_conf, data))
					HandleFilterEnabling(data, true);
				else if (CompareFileInfo(directory, lpConfFile2, info, &adler_conf, data))
					HandleFilterEnabling(data, false);
			}

			info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(reinterpret_cast<uint8_t*>(info) + info->NextEntryOffset);
		}
		while (info->NextEntryOffset != 0);
	}
}

void MonitorThread()
{
	/* Start monitoring changes to files in the root directory */
	HANDLE hDirectory = CreateFile(lpDirectory, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	
	if (hDirectory == NULL || hDirectory == INVALID_HANDLE_VALUE)
	{
		do
		{
			Sleep(2000);
			hDirectory = CreateFile(lpDirectory, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
		} while (hDirectory == NULL || hDirectory == INVALID_HANDLE_VALUE);
	}

	std::wstring directory = std::wstring(lpDirectory) + L'\\';
	filter::logger::get().open(directory + lpLogFile);

	/* Load configuration file to check if the password filter should be active */
	std::vector<uint8_t> data;

	if (RetrieveFileData(directory + lpConfFile1, data))
		HandleFilterEnabling(data, true);
	else
	{
		filter::blacklist::get().disable();
		filter::logger::get().write("[warning] failed to read 'weak-enabled.txt' file - enabling might be problematic");
	}

	if (RetrieveFileData(directory + lpConfFile2, data))
		HandleFilterEnabling(data, false);
	else
	{
		filter::hash_scanner::get().disable();
		filter::logger::get().write("[warning] failed to read 'leaked-enabled.txt' file - enabling might be problematic");
	}

	/* Load filter list */
	auto start = std::chrono::high_resolution_clock::now();
	std::cout << "Loading filter list" << std::endl;

	try
	{
		filter::blacklist::get().load_file(directory + lpListFile1);
	}
	catch (std::exception const& e)
	{
		std::cout << "Exception: " << e.what() << std::endl;
	}

	auto end = std::chrono::high_resolution_clock::now();
	auto time_span = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);

	std::cout << "Finished in " << time_span.count() << " seconds" << std::endl;
	
	/* Load leaked list */
	if (fIncludeLeaked)
	{
		start = std::chrono::high_resolution_clock::now();
		std::cout << "Loading leaked list" << std::endl;

		try
		{
			filter::hash_scanner::get().open(directory + lpListFile2);
		}
		catch (std::exception const& e)
		{
			std::cout << "Exception: " << e.what() << std::endl;
		}

		end = std::chrono::high_resolution_clock::now();
		time_span = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);

		std::cout << "Finished in " << time_span.count() << " seconds" << std::endl;
	}

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

	if (fResult == FALSE && fIncludeLeaked)
		fResult = filter::hash_scanner::get().test(Password) ? TRUE : FALSE;

	// TRUE = The password is accepted by the filter (LSA evaluates the rest of the filter chain)
	// FALSE = The password is rejected by the filter (LSA returns the ERROR_ILL_FORMED_PASSWORD (1324) status code to the source of the password change request)

	return (fResult != TRUE);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpvReserved)
{
	static HANDLE hThread = NULL;

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		ExpandEnvironmentStrings(lpDirectoryPath, lpDirectory, sizeof(lpDirectory) / sizeof(wchar_t));
		return ((hThread = CreateThread(NULL, 0, LPTHREAD_START_ROUTINE(&MonitorThread), NULL, 0, NULL)) != NULL);
	}
	else if (dwReason == DLL_PROCESS_DETACH)
		return TerminateThread(hThread, 0);

	return TRUE;
}
