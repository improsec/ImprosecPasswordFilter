#pragma once

#include <Windows.h>
#include <winternl.h>

#include "hash_file.hpp"

#include <array>
#include <vector>
#include <mutex>

namespace filter {

class hash_scanner
{
	using hash_data = std::array<uint8_t, 16>;

	bool ready_;
	bool enabled_;
	std::mutex mtx_;

private:
	hash_scanner();

public:
	static hash_scanner& get()
	{
		static hash_scanner instance;
		return instance;
	}

	void enable();
	void disable();

	bool open(std::wstring const& path);
	bool test(UNICODE_STRING* password);

private:
	bool find(std::array<uint8_t, 16> const& entry) const;
	bool nthash(UNICODE_STRING* input, std::array<uint8_t, 16>& digest) const;

private:
	std::vector<hash_data> data_;
};

} // namespace filter