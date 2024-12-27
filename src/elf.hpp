#pragma once

#include <vector>
#include <iostream>

#include "util.hpp"

namespace ELF {

struct Elf64_Ehdr {
    u8 e_ident[16];
    u16 e_type;
    u16 e_machine;
    u32 e_version;
    u64 e_entry;
    u64 e_phoff;
    u64 e_shoff;
    u32 e_flags;
    u16 e_ehsize;
    u16 e_phentsize;
    u16 e_phnum;
    u16 e_shentsize;
    u16 e_shnum;
    u16 e_shstrndx;
};

struct Elf64_Shdr {
    u32 sh_name;
    u32 sh_type;
    u64 sh_flags;
    u64 sh_addr;
    u64 sh_offset;
    u64 sh_size;
    u32 sh_link;
    u32 sh_info;
    u64 sh_addralign;
    u64 sh_entsize;
};

struct Section {
    std::vector<u8> data;
    std::string name;
    u32 type;
    u8 alignment;

    inline u32 get_16_byte_aligned_size() const {
        if(this->data.size() % 16 == 0) {
            return this->data.size();
        } else {
            return (this->data.size() / 16) * 16 + 16;
        }
    }
};

// constexpr u8 SECTION_NULL = 0;
// constexpr u8 SECTION_TEXT = 0;
// constexpr u8 SECTION_RODATA = 1;
// constexpr u8 SECTION_DATA = 2;
// constexpr u8 SECTION_BSS = 3;
// constexpr u8 SECTION_SHSTRTAB = 4;
// constexpr u8 SECTION_STRTAB = 5;

constexpr u8 SECTION_COUNT = 6;

constexpr u32 SHT_NULL = 0;
constexpr u32 SHT_PROGBITS = 1;
constexpr u32 SHT_SYMTAB = 2;
constexpr u32 SHT_STRTAB = 3;
constexpr u32 SHT_RELA = 4;
constexpr u32 SHT_HASH = 5;
constexpr u32 SHT_DYNAMIC = 6;
constexpr u32 SHT_NOTE = 7;
constexpr u32 SHT_NOBITS = 8;
constexpr u32 SHT_REL = 9;
constexpr u32 SHT_SHLIB = 10;
constexpr u32 SHT_DYNSYM = 11;
constexpr u32 SHT_NUM = 12;
constexpr u32 SHT_LOPROC = 0x70000000;
constexpr u32 SHT_HIPROC = 0x7fffffff;
constexpr u32 SHT_LOUSER = 0x80000000;
constexpr u32 SHT_HIUSER = 0xffffffff;

struct ElfFile {
    Elf64_Ehdr header;
    // std::vector<Elf64_Shdr> sht;
    // Section sections[SECTION_COUNT];
    std::vector<Section> sections;
};

ElfFile init_elf();

void write(std::string filename, ElfFile &elf);

}