#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <Windows.h>
#include <NTSecAPI.h>

#include <chrono>
#include <functional>
#include <iostream>
#include <string>

typedef BOOLEAN (WINAPI* InitializeChangeNotify_t)();
typedef BOOLEAN (WINAPI* Passwordfilter_t)(PUNICODE_STRING  AccountName, PUNICODE_STRING  FullName, PUNICODE_STRING Password, BOOLEAN SetOperation);

void timed_event(std::string const& description, std::function<void()> functor)
{
	auto start = std::chrono::high_resolution_clock::now();
	std::cout << description << std::endl;

	try
	{
		functor();
	}
	catch (std::exception const& e)
	{
		std::cout << "Exception: " << e.what() << std::endl;
	}

	auto end = std::chrono::high_resolution_clock::now();
	auto time_span = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);

	std::cout << "Finished in " << time_span.count() << " seconds" << std::endl;
}

#include <vector>
#include <array>
#include <utility>

bool nthash(std::wstring const& input, std::array<uint8_t, 16>& digest)
{
	HCRYPTPROV hCryptProvider = NULL;
	HCRYPTHASH hCryptHash = NULL;

	bool result = false;

	if (CryptAcquireContextW(&hCryptProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		if (CryptCreateHash(hCryptProvider, CALG_MD4, 0, 0, &hCryptHash))
		{
			if (CryptHashData(hCryptHash, reinterpret_cast<BYTE const*>(input.c_str()), input.size() * 2, 0))
			{
				uint8_t md4_hash[16];
				memset(&md4_hash[0], 0, sizeof(md4_hash));

				uint32_t md4_length = sizeof(md4_hash);

				if (CryptGetHashParam(hCryptHash, HP_HASHVAL, &md4_hash[0], reinterpret_cast<DWORD*>(&md4_length), 0))
				{
					memcpy(&digest[0], md4_hash, sizeof(md4_hash));
					result = true;
				}
			}

			CryptDestroyHash(hCryptHash);
		}

		CryptReleaseContext(hCryptProvider, 0);
	}

	return result;
}

int wmain(int argc, wchar_t* argv[])
{
	HMODULE hModule = LoadLibrary(L"ipf.dll");
	
	if (hModule == NULL)
		std::cout << "Cannot load 'filter.dll'" << std::endl;
	else
	{
		InitializeChangeNotify_t initialize = reinterpret_cast<InitializeChangeNotify_t>(GetProcAddress(hModule, "InitializeChangeNotify"));

		if (initialize == nullptr)
			std::cerr << "Failed to locate initialization function" << std::endl;
		else if (!initialize())
			std::cerr << "Failed to initialize filter" << std::endl;

		std::cin.get();
		
		timed_event("Scanning for password", [&]() -> void {
			Passwordfilter_t filter = reinterpret_cast<Passwordfilter_t>(GetProcAddress(hModule, "PasswordFilter"));

			if (filter == nullptr)
				std::cerr << "Failed to locate filter function" << std::endl;
			else
			{
				wchar_t const* v = L"fakepassword";

				UNICODE_STRING p = { 0 };
				p.Buffer = const_cast<wchar_t*>(v);
				p.Length = wcslen(v) * sizeof(WCHAR);
				p.MaximumLength = p.Length + sizeof(WCHAR);

				if (filter(NULL, NULL, &p, FALSE))
					std::cout << "ALLOWED" << std::endl;
				else
					std::cout << "FILTERED" << std::endl;
			}
		});
		
		timed_event("Scanning for password", [&]() -> void {
			Passwordfilter_t filter = reinterpret_cast<Passwordfilter_t>(GetProcAddress(hModule, "PasswordFilter"));

			if (filter == nullptr)
				std::cerr << "Failed to locate filter function" << std::endl;
			else
			{
				wchar_t const* v = L"Pa$$w0rd";

				UNICODE_STRING p = { 0 };
				p.Buffer = const_cast<wchar_t*>(v);
				p.Length = wcslen(v) * sizeof(WCHAR);
				p.MaximumLength = p.Length + sizeof(WCHAR);

				if (filter(NULL, NULL, &p, FALSE))
					std::cout << "ALLOWED" << std::endl;
				else
					std::cout << "FILTERED" << std::endl;
			}
		});
	}
	
	return 0;
}