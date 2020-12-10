#pragma once

#include <mutex>
#include <string>

namespace filter {

class logger
{
	std::mutex mtx_;
	std::wstring file_;

private:
	logger() = default;

public:
	static logger& get()
	{
		static logger instance;
		return instance;
	}

	void open(std::wstring const& path);
	void write(std::string const& message);
};

} // namespace filter