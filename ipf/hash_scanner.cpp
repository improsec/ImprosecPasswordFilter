#include "hash_scanner.hpp"
#include "logger.hpp"

#include <Wincrypt.h>
#include <winternl.h>

#include <algorithm>
#include <stdexcept>

#include <iomanip>
#include <sstream>
#include <iostream>

namespace filter {

hash_scanner::hash_scanner() :
	ready_(false),
	enabled_(false)
{

}

void hash_scanner::enable()
{
	enabled_ = true;
}

void hash_scanner::disable()
{
	enabled_ = false;
}

bool hash_scanner::open(std::wstring const& path)
{
	std::lock_guard<std::mutex> lg(mtx_);

	try
	{
		hash_file file;
		file.open(path);
		file.reset();

		if ((file.size() % 16) != 0)
			throw std::logic_error("cannot read hashes to a non-aligned buffer");
		else
		{
			data_.clear();
			data_.reserve(file.elements());

			std::vector<uint8_t> buffer;
			std::array<uint8_t, 8192> temp;

			for (uint64_t remains = file.size(), length = 0; remains > 0;)
			{
				if ((length = file.read(&temp[0], std::min<std::size_t>(temp.size(), remains - buffer.size()))) != 0)
				{
					buffer.insert(buffer.end(), temp.begin(), temp.begin() + length);
					std::vector<uint8_t>::const_iterator iter = buffer.cbegin();

					while (iter != buffer.cend() && std::distance(iter, buffer.cend()) >= 16)
					{
						data_.push_back(hash_data());
						std::copy(iter, iter + 16, data_.back().data());

						std::advance(iter, 16);
						remains -= 16;
					}

					buffer.erase(buffer.begin(), iter);
				}
			}
		}

		return (ready_ = true);
	}
	catch (std::exception const& e)
	{
		filter::logger::get().write("[error] an exception occured while loading leaked list file");
		filter::logger::get().write("[except] " + std::string(e.what()));
		return (ready_ = false);
	}
}

bool hash_scanner::test(UNICODE_STRING* password)
{
	std::lock_guard<std::mutex> lg(mtx_);

	if (ready_ && enabled_)
	{
		std::array<uint8_t, 16> hash;
		nthash(password, hash);
		return find(hash);
	}

	return false;
}

bool hash_scanner::find(std::array<uint8_t, 16> const& entry) const
{
	return std::binary_search(data_.begin(), data_.end(), entry);
}

bool hash_scanner::nthash(UNICODE_STRING* input, std::array<uint8_t, 16>& digest)  const
{
	HCRYPTPROV hCryptProvider = NULL;
	HCRYPTHASH hCryptHash = NULL;

	bool result = false;

	if (CryptAcquireContextW(&hCryptProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		if (CryptCreateHash(hCryptProvider, CALG_MD4, 0, 0, &hCryptHash))
		{
			if (CryptHashData(hCryptHash, reinterpret_cast<BYTE const*>(input->Buffer), static_cast<DWORD>(input->Length), 0))
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

} //  namespace filter