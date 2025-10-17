//NobPacker by AlSch092 @ Github
#include <Windows.h>
#include <fstream>
#include <vector>
#include <string>
#include "zlib.h"
#include <algorithm>

#ifdef _DEBUG
#pragma comment(lib, "zlibd.lib")
#else
#pragma comment(lib, "zlib.lib")
#endif

struct PackedSectionInfo
{
	char name[8];
	DWORD originalSize;
	DWORD packedSize;
	DWORD originalRVA;
	DWORD packedOffset;
};

const std::string SectionsToPack[] = { ".text", ".rdata", ".data" }; // sections we will attempt to pack, add your own if you want

std::vector<uint8_t> ReadFileBytes(const std::wstring& path)
{
	if (path.empty())
		return {};

	std::ifstream f(path, std::ios::binary);
	return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), {});
}

bool WriteFileBytes(const std::wstring& path, const std::vector<uint8_t>& data)
{
	if (path.empty() || data.empty())
		return false;

	std::ofstream f(path, std::ios::binary | std::ios::trunc);

	if (!f)
	{
		wprintf(L"Failed to open output file.\n");
		return false;
	}

	f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
	if (!f.good())
	{
		wprintf(L"Write failed after %zu bytes.\n", (size_t)f.tellp());
		return false;
	}

	f.flush();
	f.close();

	wprintf(L"Wrote %zu bytes\n", data.size());
	return true;
}

bool CompressBuffer(const uint8_t* in, size_t inSize, std::vector<uint8_t>& out)
{
	uLongf destLen = compressBound(inSize);
	out.resize(destLen);

	if (compress2(out.data(), &destLen, in, inSize, Z_BEST_COMPRESSION) != Z_OK)
		return false;

	out.resize(destLen);
	return true;
}

void EncryptBuffer(__in std::vector<uint8_t>& buffer, __in uintptr_t key) // we can add a better cipher later on if desired
{
	std::transform(buffer.begin(), buffer.end(), buffer.begin(), [key](uint8_t c) { return c ^ (key & 0xFF); });
}

bool PackFile(std::wstring inputPath, std::wstring outputPath, bool shouldEncrypt = false, uintptr_t encryptKey = 0)
{
	if (inputPath.empty() || outputPath.empty())
	{
		wprintf(L"[ERROR] Input or output path is empty.\n");
		return false;
	}

	auto buf = ReadFileBytes(inputPath.c_str());

	uint8_t* base = buf.data();

	if (buf.size() < sizeof(IMAGE_DOS_HEADER))
		return -1;

	auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);

	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return -1;

	if (buf.size() < dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER))
		return -1;

	size_t nt_off = dos->e_lfanew; // offset of "PE\0\0"
	const uint8_t* nt = base + nt_off;
	if (*reinterpret_cast<const DWORD*>(nt) != IMAGE_NT_SIGNATURE)
		return -1;

	const IMAGE_FILE_HEADER* fh = reinterpret_cast<const IMAGE_FILE_HEADER*>(nt + 4);
	WORD numSecs = fh->NumberOfSections;
	WORD optSize = fh->SizeOfOptionalHeader;


	size_t sec_table_off = nt_off + 4 + sizeof(IMAGE_FILE_HEADER) + optSize;

	size_t sec_table_size = size_t(numSecs) * sizeof(IMAGE_SECTION_HEADER);

	if (buf.size() < sec_table_off + sec_table_size)
		return -1;

	size_t worst_append = 0;
	for (WORD i = 0; i < numSecs; ++i)
	{
		const auto* s = reinterpret_cast<const IMAGE_SECTION_HEADER*>(base + sec_table_off + i * sizeof(IMAGE_SECTION_HEADER));

		for (const std::string& section : SectionsToPack)
		{
			if (strncmp(reinterpret_cast<const char*>(s->Name), section.c_str(), section.size()) == 0)
			{
				worst_append += size_t(s->SizeOfRawData) + (s->SizeOfRawData / 16384) * 6 + 64;
				break;
			}
		}
	}

	buf.reserve(buf.size() + worst_append + 4096); // prevent reallocation from vector.insert

	std::vector<PackedSectionInfo> packedInfo;

	for (WORD i = 0; i < numSecs; ++i)
	{
		// re-read base each iteration in case vector moved (reserve should prevent it anyway)
		base = buf.data();

		auto* s = reinterpret_cast<IMAGE_SECTION_HEADER*>(base + sec_table_off + i * sizeof(IMAGE_SECTION_HEADER));

		// Safe name extraction
		char nm[9] = {}; memcpy(nm, s->Name, 8);
		std::string name(nm);

		for (const std::string& section : SectionsToPack)
		{
			if (name == section)
			{
				uint32_t off = s->PointerToRawData;
				uint32_t sz = s->SizeOfRawData;

				if (sz == 0) // already packed or empty
					continue;

				if (size_t(off) + size_t(sz) > buf.size())  // corrupt/out-of-bounds
					continue;

				const uint8_t* src = base + off;

				std::vector<uint8_t> compressed;

				if (!CompressBuffer(src, sz, compressed))
					continue;

				if (shouldEncrypt)
				{
					printf("Encrypting packed section %s with key 0x%p\n", name.c_str(), (void*)encryptKey);
					EncryptBuffer(compressed, encryptKey);
				}

				PackedSectionInfo info{};  //pack record metadata
				memcpy(info.name, s->Name, 8);
				info.originalSize = sz;
				info.packedSize = static_cast<DWORD>(compressed.size());
				info.originalRVA = s->VirtualAddress;
				info.packedOffset = static_cast<DWORD>(buf.size()); // where we’re about to append
				packedInfo.push_back(info);

				buf.insert(buf.end(), compressed.begin(), compressed.end()); // if `insert` forces a realloc, it will corrupt the job and crash the program after the current loop

				base = buf.data(); //zero original range (does not reallocate)
				memset(const_cast<uint8_t*>(base) + off, 0, sz);

				s->SizeOfRawData = 0;
			}
		}
	}

	//append metadata + signature at the very end of the output file
	DWORD metaOffset = static_cast<DWORD>(buf.size());
	if (!packedInfo.empty())
	{
		buf.insert(buf.end(), reinterpret_cast<const uint8_t*>(packedInfo.data()), reinterpret_cast<const uint8_t*>(packedInfo.data()) + packedInfo.size() * sizeof(PackedSectionInfo));
		static const char sig[] = "MICROSOFT"; //rather than using something too obvious like "PACKINFO"
		buf.insert(buf.end(), sig, sig + sizeof(sig));
	}

	if (WriteFileBytes(outputPath.c_str(), buf))
	{
		wprintf(L"Successfully packed %zu sections.\n", packedInfo.size());
		return true;
	}
	else
	{
		wprintf(L"[ERROR] Failed to write packed sections to file: %s\n", outputPath.c_str());
		return false;
	}
}

int wmain(int argc, wchar_t** argv)
{
	if (argc < 3)
	{
		wprintf(L"Usage: packer.exe input.dll output.dll\n");
		return 0;
	}

	std::wstring inputPath;
	std::wstring outputPath;

	if (argc >= 3)
	{
		inputPath = argv[1];
		outputPath = argv[2];
	}

	return PackFile(inputPath, outputPath, true, 0x80) ? 0 : -1;
}
