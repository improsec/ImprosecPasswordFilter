#include "logger.hpp"

#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>

namespace filter {

void logger::open(std::wstring const& path)
{
	file_ = path;
}

void logger::write(std::string const& message)
{
	std::lock_guard<std::mutex> lg(mtx_);

	if (!file_.empty())
	{
		std::ofstream f(file_, std::ios_base::out | std::ios_base::app);

		if (f.good())
		{
			time_t t = std::time(nullptr);

			tm tt;
			memset(&tt, 0, sizeof(tm));

			if (localtime_s(&tt, &t) == 0)
				f << std::put_time(&tt, "[%d-%m-%Y %T]") << message << std::endl;

			f.close();
		}
	}
}

} // namespace filter