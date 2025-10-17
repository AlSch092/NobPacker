//Part of NobPacker repository by AlSch092 - https://github.com/AlSch092/NobPacker
#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "zlib.h"
#include <algorithm>

#ifdef min
#undef min
#endif

#ifdef _DEBUG
#pragma comment(lib, "zlibd.lib")
#else
#pragma comment(lib, "zlib.lib")
#endif

#pragma pack(push,1)
struct PackedSectionInfo {
    char name[8];
    DWORD originalSize;
    DWORD packedSize;
    DWORD originalRVA;
    DWORD packedOffset;
};
#pragma pack(pop)

bool DecompressZlib(__in const uint8_t* src, __in size_t srcSize, __out std::vector<uint8_t>& out, __in  size_t expectedSize);
intptr_t FindPackDataSignature(__in const uint8_t* buf, __in size_t bufSize, __in const char* sig, __in  size_t sigLen, __in  size_t maxSearch);
bool UnpackSections(__in const uint8_t* fileBuf, __in size_t fileSize, __in  uint8_t* imageBase, __in size_t imageSize, __in  bool shouldDecrypt = false, __in uintptr_t decryptKey = 0);