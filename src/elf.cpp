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

    // ELF::Section null_section;
    // null_section.name = "";
    // null_section.type = ELF::SHT_NULL;
    // null_section.alignment = 0;
    // null_section.flags = 0;
    // null_section.entry_size = 0;
    // elf.sections.push_back(null_section);

    // ELF::Section text_section;
    // text_section.name = ".text";
    // text_section.type = ELF::SHT_PROGBITS;
    // text_section.alignment = 16;
    // text_section.flags = ELF::SHF_ALLOC | ELF::SHF_EXECINSTR;
    // text_section.entry_size = 0;
    // elf.sections.push_back(text_section);

    // ELF::Section data_section;
    // data_section.name = ".data";
    // data_section.type = ELF::SHT_PROGBITS;
    // data_section.alignment = 4;
    // data_section.flags = ELF::SHF_ALLOC | ELF::SHF_WRITE;
    // data_section.entry_size = 0;
    // elf.sections.push_back(data_section);

    // ELF::Section symtab_section;
    // symtab_section.name = ".symtab";
    // symtab_section.type = ELF::SHT_SYMTAB;
    // symtab_section.alignment = 8;
    // symtab_section.flags = 0;
    // symtab_section.entry_size = sizeof(ELF::Elf64_Sym);
    // elf.sections.push_back(symtab_section);

    // ELF::Section shstrtab_section;
    // u32 shstrtab_section_index = elf.sections.size();
    // shstrtab_section.type = ELF::SHT_STRTAB;
    // shstrtab_section.name = ".shstrtab";
    // shstrtab_section.alignment = 1;
    // shstrtab_section.flags = 0;
    // shstrtab_section.entry_size = 0;
    // elf.sections.push_back(shstrtab_section);

    // ELF::Section strtab_section;
    // strtab_section.type = ELF::SHT_STRTAB;
    // strtab_section.name = ".strtab";
    // strtab_section.alignment = 1;
    // strtab_section.flags = 0;
    // strtab_section.entry_size = 0;
    // elf.sections.push_back(strtab_section);

    // ELF::Section rela_text_section;
    // rela_text_section.type = ELF::SHT_RELA;
    // rela_text_section.name = ".rela.text";
    // rela_text_section.alignment = 8;
    // rela_text_section.flags = 0;
    // rela_text_section.entry_size = sizeof(ELF::Elf64_Rela);
    // elf.sections.push_back(rela_text_section);

    elf.header = header;
    return elf;
}

void ELF::append_symbol(ELF::ElfFile &elf, const ELF::Symbol &symbol) {
    elf.symbols.push_back(symbol);

    u32 name_index = 0;
    u16 section_index = 0;
    for(auto &section : elf.sections) {
        if(section.name == ".strtab") {
            name_index = section.data.size();
            for(u32 i = 0; i < symbol.name.size(); i++) {
                section.data.push_back(symbol.name[i]);
            }
            section.data.push_back(0);
            break;
        }
    }

    if(symbol.section == "undef") {
        section_index = 0;
    } else if(symbol.section == "abs") {
        section_index = 0xFFF1;
    } else {
        for(auto &section : elf.sections) {
            if(section.name == symbol.section) {
                break;
            }
            section_index++;
        }
    }

    for(auto &section : elf.sections) {
        if(section.name == ".symtab") {
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
                section.data.push_back(sym_bytes[i]);
            }
            break;
        }
    }
}

void ELF::write(std::string filename, ELF::ElfFile &elf) {
    std::fstream file;
    file.open(filename, std::ios::app | std::ios::binary);

    elf.header.e_shnum = elf.sections.size();
    /* TODO: we need an assert here */
    elf.header.e_shstrndx = elf.get_section_by_name(".shstrtab")->index;

    file.write(reinterpret_cast<const char*>(&elf.header), sizeof(ELF::Elf64_Ehdr));

    std::vector<ELF::Elf64_Shdr> sht;

    u32 offset = sizeof(ELF::Elf64_Ehdr) + elf.sections.size() * sizeof(ELF::Elf64_Shdr);
    u32 name_offset = 0;

    std::vector<u8> shstrtab_bytes;

    for(u32 i = 0; i < elf.sections.size(); i++) {
        sht.push_back({
            name_offset,
            elf.sections[i].type,
            elf.sections[i].flags,
            0,
            0, // elf.sections[i].type == ELF::SHT_NULL ? 0 : offset,
            0, /* Overwritten later on */
            elf.sections[i].link,
            elf.sections[i].info,
            elf.sections[i].alignment,
            elf.sections[i].entry_size,
        });

        name_offset += elf.sections[i].name.length() + 1;
        
        for(u32 j = 0; j < elf.sections[i].name.length(); j++) {
            shstrtab_bytes.push_back(elf.sections[i].name[j]);
        }
        shstrtab_bytes.push_back(0);
    }

    /* Push section names to .shstrtab */
    for(u32 i = 0; i < elf.sections.size(); i++) {
        if(elf.sections[i].name == ".shstrtab") {
            for(u32 j = 0; j < shstrtab_bytes.size(); j++) {
                elf.sections[i].data.push_back(shstrtab_bytes[j]);
            }
            break;
        }
    }

    /* Finalise the section sizes */
    for(u32 i = 0; i < elf.sections.size(); i++) {
        sht[i].sh_size = elf.sections[i].data.size();
    }

    for(u32 i = 0; i < elf.sections.size(); i++) {
        const auto &section = elf.sections[i];
        if(section.type != ELF::SHT_NULL) {
            sht[i].sh_offset = offset;
            offset += section.get_16_byte_aligned_size();
        }
    }

    file.write(reinterpret_cast<const char*>(sht.data()), sizeof(ELF::Elf64_Shdr) * sht.size());

    for(u32 i = 0; i < elf.sections.size(); i++) {
        if(elf.sections[i].data.size() > 0) {
            file.write(
                reinterpret_cast<const char*>(elf.sections[i].data.data()),
                elf.sections[i].data.size());

            /* Push extra 0 bytes to ensure 16 byte alignment */
            if(elf.sections[i].data.size() < elf.sections[i].get_16_byte_aligned_size()) {
                // printf("%s size: %u aligned size: %u\n", elf.sections[i].name.c_str(), elf.sections[i].data.size(), elf.sections[i].get_16_byte_aligned_size());
                for(u32 j = elf.sections[i].data.size(); j < elf.sections[i].get_16_byte_aligned_size(); j++) {
                    u8 c = 0;
                    file.write(reinterpret_cast<const char*>(&c), 1);
                }
            }
        }
    }

    file.close();
}