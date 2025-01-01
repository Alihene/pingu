#include "elf.hpp"

#include <fstream>

static constexpr ELF::Elf64_Ehdr BASE_ELF_HEADER = {
    {
        0x7F, 0x45, 0x4c, 0x46, /* ELF magic */
        2,                      /* 64 bit */
        1,                      /* Little endian */
        1,                      /* Current version */
        0,                      /* System V ABI */
        0,                      /* ABI version */
        0, 0, 0, 0, 0, 0, 0     /* Reverse padding bytes */
    },
    1,                          /* Relocatable file type */
    0x3E,                       /* x86_64 */
    1,                          /* Original ELF version */
    0,                          /* Entry point address */
    0,                          /* Program header table address */
    sizeof(ELF::Elf64_Ehdr),    /* Section header table address */
    0,                          /* Flags */
    sizeof(ELF::Elf64_Ehdr),    /* Size of this header */
    0,                          /* Program header size */
    0,                          /* Number of program header entries */
    sizeof(ELF::Elf64_Shdr),    /* Size of section header entry */
    0,                          /* Section header count */
    0,                          /* .shstrtab index */
};

ELF::ElfFile ELF::init_elf() {
    ELF::ElfFile elf;
    ELF::Elf64_Ehdr header = BASE_ELF_HEADER;
    elf.header = header;
    return elf;
}

void ELF::append_symbol(ELF::ElfFile &elf, const ELF::Symbol &symbol) {
    elf.symbols.symbol_map[symbol.name] = symbol;
    elf.symbols.symbol_map[symbol.name].index = elf.symbols.insertion_order.size();
    elf.symbols.insertion_order.push_back(symbol.name);

    u32 name_index = 0;
    u16 section_index = 0;

    auto &strtab_section = *elf.get_section_by_name(".strtab");
    name_index = strtab_section.data.size();
    for(u32 i = 0; i < symbol.name.size(); i++) {
        strtab_section.data.push_back(symbol.name[i]);
    }
    strtab_section.data.push_back(0);

    if(symbol.section == "undef") {
        section_index = 0;
    } else if(symbol.section == "abs") {
        section_index = 0xFFF1;
    } else {
        section_index = elf.get_section_by_name(symbol.section)->index;
    }

    auto &symtab_section = *elf.get_section_by_name(".symtab");
    ELF::Elf64_Sym sym = {
        name_index,
        symbol.type,
        symbol.other,
        section_index,
        symbol.addr,
        0, /* TODO needs to change */
    };
    u8 *sym_bytes = reinterpret_cast<u8*>(&sym);
    for(u32 i = 0; i < sizeof(ELF::Elf64_Sym); i++) {
        symtab_section.data.push_back(sym_bytes[i]);
    }
}

void ELF::write(std::string filename, ELF::ElfFile &elf) {
    std::fstream file;
    file.open(filename, std::ios::app | std::ios::binary);

    elf.header.e_shnum = elf.sections.insertion_order.size();
    /* TODO: we need an assert here */
    elf.header.e_shstrndx = elf.get_section_by_name(".shstrtab")->index;

    file.write(reinterpret_cast<const char*>(&elf.header), sizeof(ELF::Elf64_Ehdr));

    std::vector<ELF::Elf64_Shdr> sht;

    u32 offset = sizeof(ELF::Elf64_Ehdr) + elf.sections.insertion_order.size() * sizeof(ELF::Elf64_Shdr);
    u32 name_offset = 0;

    std::vector<u8> shstrtab_bytes;

    for(auto &section_name : elf.sections.insertion_order) {
        const auto &section = *elf.get_section_by_name(section_name);

        sht.push_back({
            name_offset,
            section.type,
            section.flags,
            0,
            0, /* Overwritten later on */
            0, /* Overwritten later on */
            section.link,
            section.info,
            section.alignment,
            section.entry_size,
        });

        name_offset += section.name.length() + 1;
        
        for(u32 j = 0; j < section.name.length(); j++) {
            shstrtab_bytes.push_back(section.name[j]);
        }
        shstrtab_bytes.push_back(0);
    }

    /* Push section names to .shstrtab */
    auto &shstrtab_section = *elf.get_section_by_name(".shstrtab");
    for(u32 i = 0; i < shstrtab_bytes.size(); i++) {
        shstrtab_section.data.push_back(shstrtab_bytes[i]);
    }

    /* Finalise the section sizes */
    for(auto &section_name : elf.sections.insertion_order) {
        const auto &section = *elf.get_section_by_name(section_name);
        sht[section.index].sh_size = section.data.size();
    }

    for(auto &section_name : elf.sections.insertion_order) {
        const auto &section = *elf.get_section_by_name(section_name);
        if(section.type != ELF::SHT_NULL) {
            sht[section.index].sh_offset = offset;
            offset += section.get_16_byte_aligned_size();
        }
    }

    file.write(reinterpret_cast<const char*>(sht.data()), sizeof(ELF::Elf64_Shdr) * sht.size());


    for(auto &section_name : elf.sections.insertion_order) {
        auto &section = *elf.get_section_by_name(section_name);

        if(section.data.size() == 0) {
            continue;
        }

        file.write(reinterpret_cast<const char*>(&section.data[0]), section.data.size());

        /* Resolve 16 byte alignment */
        if(section.data.size() < section.get_16_byte_aligned_size()) {
            for(u32 i = section.data.size(); i < section.get_16_byte_aligned_size(); i++) {
                u8 c = 0;
                file.write(reinterpret_cast<const char*>(&c), 1);
            }
        }
    }

    file.close();
}

ELF::Symbol ELF::make_symbol(std::string name, std::string section_name, u8 bind, u8 type, u64 value) {
    return {name, section_name, ELF64_ST_INFO(bind, type), 0, value, 0};
}