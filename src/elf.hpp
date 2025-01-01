#pragma once

#include <vector>
#include <iostream>
#include <unordered_map>

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

struct Elf64_Rela {
    u64 r_offset;
    u64 r_info;
    u64 r_addend;
};

struct Elf64_Sym {
    u32 st_name;
    u8 st_info;
    u8 st_other;
    u16 str_shndx;
    u64 st_value;
    u64 st_size;
};

struct Section {
    std::vector<u8> data;
    std::string name;
    u32 type;
    u32 alignment;
    u32 flags;
    u64 entry_size;
    u32 link;
    u32 info;
    u8 index;

    inline u32 get_16_byte_aligned_size() const {
        if(this->data.size() % 16 == 0) {
            return this->data.size();
        } else {
            return (this->data.size() / 16) * 16 + 16;
        }
    }
};

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

constexpr u8 STB_LOCAL = 0;
constexpr u8 STB_GLOBAL = 1;

constexpr u8 STT_NOTYPE = 0;
constexpr u8 STT_OBJECT = 1;
constexpr u8 STT_FUNC = 2;
constexpr u8 STT_SECTION = 3;
constexpr u8 STT_FILE = 4;

constexpr u8 SHF_WRITE = 0x1;
constexpr u8 SHF_ALLOC = 0x2;
constexpr u8 SHF_EXECINSTR = 0x4;

#define ELF_ST_BIND(x) ((x) >> 4)
#define ELF_ST_TYPE(x) ((x) & 0xf)
#define ELF64_ST_BIND(x) ELF_ST_BIND(x)
#define ELF64_ST_TYPE(x) ELF_ST_TYPE(x)

#define	ELF64_ST_INFO(bind, type) (((bind) << 4) + ((type) & 0xf))

struct Symbol {
    std::string name;
    std::string section;
    u8 type;
    u8 other;
    u64 addr;
    u32 index;
};

class ElfFile {
    Elf64_Ehdr header;

    /* Ordered maps */
    struct {
        std::unordered_map<std::string, Section> section_map;
        std::vector<std::string> insertion_order;
    } sections;
    struct {
        std::unordered_map<std::string, Symbol> symbol_map;
        std::vector<std::string> insertion_order;
    } symbols;

public:
    ElfFile();

    void append_section(std::string name, u32 type, u32 alignment, u32 flags, u64 entry_size, u32 link, u32 info);

    Section *get_section_by_name(std::string name);

    Symbol *get_symbol_by_name(std::string name);

    u32 get_first_nonlocal_symbol_index() const;

    void append_symbol(const Symbol &symbol);

    void append_reloc(std::string sym_name, u32 type, u64 reloc_addr, u64 addend);

    void write(std::string filename);
};

Symbol make_symbol(std::string name, std::string section_name, u8 bind, u8 type, u64 value);

}