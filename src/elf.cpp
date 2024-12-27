#include "elf.hpp"

#include <fstream>

static constexpr ELF::Elf64_Ehdr BASE_ELF_HEADER = {
    {
        0x7F, 0x45, 0x4c, 0x46,
        2, /* 64 bit */
        1, /* Little endian */
        1, /* Current version */
        0, /* System V ABI */
        0, /* ABI version */
        0, 0, 0, 0, 0, 0, 0 /* Reverse padding bytes */
    },
    1, /* Relocatable file type */
    0x3E, /* x86_64 */
    1, /* Original ELF version */
    0, /* Entry point address */
    0, /* Program header table address */
    sizeof(ELF::Elf64_Ehdr), /* Section header table address */
    0, /* Flags */
    sizeof(ELF::Elf64_Ehdr), /* Size of this header */
    0, /* Program header size */
    0, /* Number of program header entries */
    sizeof(ELF::Elf64_Shdr), /* Size of section header entry */
    0,
    0
};

ELF::ElfFile ELF::init_elf() {
    ELF::ElfFile elf;
    ELF::Elf64_Ehdr header = BASE_ELF_HEADER;

    ELF::Section null_section;
    null_section.name = "";
    null_section.type = ELF::SHT_NULL;
    null_section.alignment = 0;
    elf.sections.push_back(null_section);

    ELF::Section shstrtab_section;
    u32 shstrtab_section_index = elf.sections.size();
    shstrtab_section.type = ELF::SHT_STRTAB;
    shstrtab_section.name = ".shstrtab";
    shstrtab_section.alignment = 1;
    elf.sections.push_back(shstrtab_section);

    header.e_shnum = elf.sections.size();
    header.e_shstrndx = shstrtab_section_index;

    elf.header = header;
    return elf;
}

// TODO: alignment
void ELF::write(std::string filename, ELF::ElfFile &elf) {
    std::fstream file;
    file.open(filename, std::ios::app | std::ios::binary);
    file.write(reinterpret_cast<const char*>(&elf.header), sizeof(ELF::Elf64_Ehdr));

    std::vector<ELF::Elf64_Shdr> sht;

    u32 offset = sizeof(ELF::Elf64_Ehdr) + elf.sections.size() * sizeof(ELF::Elf64_Shdr);
    u32 name_offset = 0;

    std::vector<u8> shstrtab_bytes;

    for(u32 i = 0; i < elf.sections.size(); i++) {
        sht.push_back({
            name_offset,
            ELF::SHT_STRTAB,
            0,
            0,
            elf.sections[i].type == ELF::SHT_NULL ? 0 : offset,
            0, /* Overwritten later on */
            0,
            0,
            elf.sections[i].alignment,
            0,
        });
        name_offset += elf.sections[i].name.length() + 1;
        
        for(u32 j = 0; j < elf.sections[i].name.length(); j++) {
            shstrtab_bytes.push_back(elf.sections[i].name[j]);
        }
        shstrtab_bytes.push_back(0);
    }

    for(u32 i = 0; i < elf.sections.size(); i++) {
        if(elf.sections[i].name == ".shstrtab") {
            for(u32 j = 0; j < shstrtab_bytes.size(); j++) {
                elf.sections[i].data.push_back(shstrtab_bytes[j]);
            }
            break;
        }
    }

    for(u32 i = 0; i < elf.sections.size(); i++) {
        sht[i].sh_size = elf.sections[i].data.size();
    }

    file.write(reinterpret_cast<const char*>(sht.data()), sizeof(ELF::Elf64_Shdr) * sht.size());

    for(u32 i = 0; i < elf.sections.size(); i++) {
        if(elf.sections[i].data.size() > 0) {
            file.write(
                reinterpret_cast<const char*>(elf.sections[i].data.data()),
                elf.sections[i].data.size());

            if(elf.sections[i].data.size() < elf.sections[i].get_16_byte_aligned_size()) {
                for(u32 j = elf.sections[i].data.size(); j < elf.sections[i].get_16_byte_aligned_size(); j++) {
                    u8 c = 0;
                    file.write(reinterpret_cast<const char*>(&c), 1);
                }
            }
        }
    }
    file.close();
}