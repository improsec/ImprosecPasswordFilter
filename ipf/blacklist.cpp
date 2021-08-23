#include "blacklist.hpp"
#include "logger.hpp"
#include <shlwapi.h>

#include <algorithm>
#include <fstream>
#include <iostream>

#pragma comment(lib, "Shlwapi.lib")

namespace filter {

blacklist::blacklist() :
	ready_(false),
	enabled_(false)
{

}

void blacklist::enable()
{
	enabled_ = true;
}

void blacklist::disable()
{
	enabled_ = false;
}

bool blacklist::load_file(std::wstring const& path)
{
	std::lock_guard<std::mutex> lg(mtx_);

	try
	{
		list_.clear();

		std::wifstream file(path);
		std::wstring line;

		while (std::getline(file, line))
			list_.push_back(line);

		return (ready_ = true);
	}
	catch (std::exception const& e)
	{
		filter::logger::get().write("[error] an exception occured while loading blacklist wildcard file");
		filter::logger::get().write("[except] " + std::string(e.what()));
		return (ready_ = false);
	}
}

bool blacklist::contains(UNICODE_STRING* p)
{
	std::lock_guard<std::mutex> lg(mtx_);

	if (ready_ && enabled_ && p != NULL && p->Buffer != NULL)
	{
		auto iter = std::find_if(list_.begin(), list_.end(),
			[&](std::wstring const& w) -> bool
		{
			USHORT dwLength = static_cast<USHORT>(w.length() * sizeof(WCHAR));
			USHORT dwLength2 = static_cast<USHORT>(p->Length / sizeof(WCHAR));

			return (p->Length == dwLength && _wcsnicmp(p->Buffer, w.data(), w.length()) == 0) || 
				(p->Length >= dwLength && StrStrIW(p->Buffer, w.data()) != NULL);
		});

		return iter != list_.end();
	}

	return false;
}

} // namespace filter
