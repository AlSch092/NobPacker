//Part of NobPacker repository by AlSch092 - https://github.com/AlSch092/NobPacker
#include "Unpack.h"

void DecryptBuffer(__in uint8_t* buffer, __in size_t size, __in uintptr_t key)
{
    if (buffer == nullptr || size == 0)
        return;

    for (size_t i = 0; i < size; i++)
    {
        buffer[i] ^= (key & 0xFF);
    }
}

bool DecompressZlib(__in const uint8_t* src, __in  size_t srcSize, __out std::vector<uint8_t>& out, __in size_t expectedSize)
{
    if (expectedSize == 0 || src == nullptr || srcSize == 0)  
        return false;

    out.resize(expectedSize);
    uLongf destLen = (uLongf)expectedSize;
    int r = uncompress(out.data(), &destLen, src, (uLong)srcSize);
    if (r != Z_OK) 
    {
        // try to handle if the expected size was wrong: attempt to grow dest buffer heuristically
        // but by default we fail
        return false;
    }
    if (destLen != expectedSize) 
    {
        // still accept if smaller (but typically expectedSize should match)
        out.resize(destLen);
    }
    return true;
}

intptr_t FindPackDataSignature(__in const uint8_t* buf, __in  size_t bufSize, __in const char* sig, __in  size_t sigLen, __in  size_t maxSearch)
{
    if (bufSize < sigLen || buf == nullptr || bufSize == 0 || sig == nullptr || sigLen == 0 || maxSearch == 0) 
        return -1;

    size_t searchLen = std::min(bufSize, maxSearch);
    size_t start = bufSize - sigLen;
    size_t minPos = (bufSize >= searchLen) ? (bufSize - searchLen) : 0;
    for (intptr_t pos = (intptr_t)start; pos >= (intptr_t)minPos; --pos) 
    {
        if (memcmp(buf + pos, sig, sigLen) == 0) 
            return pos;
    }
    return -1;
}

/*
  UnpackPackedSections:
    - fileBuf,fileSize: bytes of the packed file (on-disk image)
    - imageBase,imageSize: memory image where sections are mapped (target process image memory)
	- shouldDecrypt, decryptKey: whether to decrypt packed blobs before decompressing, and the key to use
    - returns true on success (at least one section unpacked), false otherwise
*/
bool UnpackSections(const uint8_t* fileBuf, size_t fileSize, uint8_t* imageBase, size_t imageSize, bool shouldDecrypt, uintptr_t decryptKey) 
{
    if (!fileBuf || fileSize < 16 || !imageBase || imageSize == 0) 
        return false;

	const char SIG[] = "MICROSOFT"; //distinctive signature to locate the pack metadata
    const size_t SIG_LEN = 9;
    const size_t MAX_SEARCH = 1 << 20; // search last 1MiB for signature (adjust if needed)

    intptr_t sigPos = FindPackDataSignature(fileBuf, fileSize, SIG, SIG_LEN, MAX_SEARCH);
    
    if (sigPos < 0) 
    {
        return false;
    }

    const size_t ENTRY_SZ = sizeof(PackedSectionInfo); //we're reading an array of PackedSectionInfo immediately before the signature
    const size_t MAX_ENTRIES = 128; //no more than 128 sections, which is more than reasonable
    std::vector<PackedSectionInfo> entries;

    for (size_t i = 1; i <= MAX_ENTRIES; ++i) //walk backwards from the signature for each entry
    {
        size_t candidate_offset = (size_t)sigPos - i * ENTRY_SZ;
        if (candidate_offset + ENTRY_SZ > (size_t)sigPos) 
            break; // overflow/safety

        if (candidate_offset + ENTRY_SZ > fileSize) 
            break;

        const PackedSectionInfo* p = reinterpret_cast<const PackedSectionInfo*>(fileBuf + candidate_offset);

        bool name_ok = false;
        
        for (int k = 0; k < 8; ++k) 
        {
            unsigned char c = (unsigned char)p->name[k];
            if (c >= 0x20 && c <= 0x7E) 
            { 
                name_ok = true; 
                break; 
            }
        }

        if (!name_ok) 
        {
            if (!entries.empty()) //an invalid entry when we already have entries means we're likely unpacked all entries
                break;

            continue;
        }

        if (p->originalSize == 0 || p->packedSize == 0) 
        {
            if (!entries.empty()) 
                break;

            continue;
        }
        
        if ((size_t)p->packedOffset + (size_t)p->packedSize > fileSize) //packed region must fit in the file and should be located earlier than signature
        {
            if (!entries.empty()) 
                break;

            continue;
        }

        if ((size_t)p->packedOffset + (size_t)p->packedSize > (size_t)sigPos) 
        {
            if (!entries.empty()) //pack data is beyond the signature, and there should be none past the sig
                break;

            continue;
        }

        if ((size_t)p->originalRVA >= imageSize) 
        {
            if (!entries.empty()) 
                break;

            continue;
        }

        entries.insert(entries.begin(), *p);
    }

    if (entries.empty()) 
        return false;

    bool anyUnpacked = false;
    for (const auto& e : entries)  //decompress each entry and write into the mapped image
    {
        if (e.packedSize == 0 || e.packedOffset + (size_t)e.packedSize > fileSize) 
            continue;

        if (e.originalRVA >= imageSize)
            continue;

        const uint8_t* packedPtr = fileBuf + e.packedOffset;

        if (shouldDecrypt)
        {
            DecryptBuffer((uint8_t*)packedPtr, static_cast<size_t>(e.packedSize), decryptKey);
        }

        std::vector<uint8_t> decompressed;

        if (!DecompressZlib(packedPtr, e.packedSize, decompressed, e.originalSize)) 
        {
            printf("Decompress failed for section %.8s (RVA 0x%X)\n", e.name, e.originalRVA);
            continue;
        }

        size_t writeSize = decompressed.size();

        if (writeSize > e.originalSize) 
            writeSize = e.originalSize;

        uint8_t* dest = imageBase + e.originalRVA;

        if ((size_t)(dest - imageBase) + writeSize > imageSize) 
        {
            printf("[WARNING] Destination out of bounds for section %.8s\n", e.name);
            continue;
        }

        SYSTEM_INFO si;
        GetSystemInfo(&si); //compute page granularity
        
        SIZE_T pageSize = si.dwPageSize;
        uintptr_t pageBase = ((uintptr_t)dest) & ~(pageSize - 1);
        SIZE_T changeSize = (((uintptr_t)dest + writeSize + pageSize - 1) & ~(pageSize - 1)) - pageBase;
        //changeSize -= pageBase;
        DWORD oldProt = 0;

        if (!VirtualProtect((LPVOID)pageBase, changeSize, PAGE_READWRITE, &oldProt)) 
        {
            printf("[WARNING] VirtualProtect failed: %lu for section  %.8s - attempting to write `dest` anyways, program may or may not crash here\n", GetLastError(), e.name);
            memcpy(dest, decompressed.data(), writeSize); //! this is dangerous and can be treated as an error if you desire !
        }
        else 
        {
            memcpy(dest, decompressed.data(), writeSize);
            DWORD tmp;
            VirtualProtect((LPVOID)pageBase, changeSize, oldProt, &tmp);
        }

        FlushInstructionCache(GetCurrentProcess(), dest, writeSize); //flush cache in cpu for address of dest since we've unpacked it

        printf("Unpacked section %.8s -> RVA 0x%X (%zu bytes)\n", e.name, e.originalRVA, writeSize);
        anyUnpacked = true;
    }

    return anyUnpacked;
}