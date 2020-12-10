#pragma once

#include <Windows.h>
#include <NTSecAPI.h>

#include <mutex>
#include <string>
#include <vector>

namespace filter {

class blacklist
{
	bool ready_;
	bool enabled_;
	std::mutex mtx_;
	std::vector<std::wstring> list_;

private:
	blacklist();

public:
	static blacklist& get()
	{
		static blacklist instance;
		return instance;
	}

	void enable();
	void disable();

	bool load_file(std::wstring const& path);
	bool contains(UNICODE_STRING* p);
};

} // namespace filter