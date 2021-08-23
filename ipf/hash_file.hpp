#pragma once

#include <string>

namespace filter {

class hash_file
{
public:
	hash_file();
	~hash_file();

	void open(std::wstring const& filename);
	void close();
	void reset() const;

	uint32_t read(void* const buffer, std::size_t length) const;

	uint64_t size() const;
	uint64_t elements() const;

private:
	void* handle_;
	uint64_t size_;
	uint64_t elements_;
};

} // namespace filter