<img width="850" height="388" alt="Capture" src="https://github.com/user-attachments/assets/7b5dc735-0901-4448-a4fe-20fc0e93ab1b" />

PE Sections Packer + Loader for x64 Windows - Packs a DLL/EXE file and maps it into the loader

# NobPacker
Packs the sections of a DLL or EXE file, by default .text, .rdata and .data are packed. It can be run as:

`./NobPacker.exe <inputFile> <outputFile>`  

The program makes use of the zlib library for compression, and the output file will then have all 00's for their section's data when viewed in a disassembler. Packed metadata is added to the end of the file, with a default signature "MICROSOFT" added to act as a spot for unpackers to find the packed metadata (feel free to change the signature to whatever you want). The output file can no longer work properly after being loaded unless the loader properly decrypts and unpacks any sections which were packed. A simple xor cipher is applied to the packed sections since zlib compression is probably the first thing people will think of when trying to unpack the file; by default the key is 0x80 (you can of course change this, just make sure both the packed + unpacker use the same key).

# NobLoader
The loader is a program which manually maps the PE into its current address space, decrypting and unpacking the file as it maps it. The loaded module can be a .exe or a .dll. If the file is properly unpacked and mapped, a thread will be created on its entry point address, and the module will begin execution. The packed file does not contain a self-unpacking stub/function. It can be run as:

`./NobLoader.exe` , and has no command line arguments available by default.  

The loader makes use of the project found at: https://github.com/TheCruZ/Simple-Manual-Map-Injector , with some modifications made to add the unpacking logic. Packed files will likely be larger than their originals due to the compression algorithms not being optimal for usage on raw PE sections. Future additions to this repo will likely see adding sections to pack as command line arguments, along with the option of placing the cipher key as packed metadata, rather than needing the packer + loader to share a key.   




