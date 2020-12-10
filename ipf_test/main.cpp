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
#include <utility>

int main()
{
	HMODULE hModule = LoadLibrary(L"ipf.dll");
	
	if (hModule != NULL)
	{
		timed_event("Initializing filter...", [&]() -> void
		{
			InitializeChangeNotify_t initialize = reinterpret_cast<InitializeChangeNotify_t>(GetProcAddress(hModule, "InitializeChangeNotify"));

			if (initialize == nullptr)
				std::cerr << "Failed to locate initialization function" << std::endl;
			else if (!initialize())
				std::cerr << "Failed to initialize filter" << std::endl;
		});

		std::vector<std::wstring> v;

		for (std::size_t i = 0; i < 20000; i++)
		{
			v.push_back(L"Password123");
		}

		Sleep(5000);

		for (int i = 0; i < 1; i++)
		{
			UNICODE_STRING p;

			timed_event("Testing filter...", [&]() -> void
			{
				Passwordfilter_t filter = reinterpret_cast<Passwordfilter_t>(GetProcAddress(hModule, "Passwordfilter"));

				if (filter == nullptr)
					std::cerr << "Failed to locate filter function" << std::endl;
				else
				{
					for (std::size_t i = 0; i < v.size(); i++)
					{
						p.Buffer = const_cast<wchar_t*>(v[i].data());
						p.Length = static_cast<USHORT>(v[i].size() * sizeof(WCHAR));
						p.MaximumLength = p.Length + sizeof(WCHAR);

						if (filter(NULL, NULL, &p, FALSE))
							std::cout << "ALLOWED" << std::endl;
						else
							std::cout << "FILTERED" << std::endl;
					}
				}
			});
		}
	}

	std::cin.ignore();
	std::cin.get();
	return 0;
}