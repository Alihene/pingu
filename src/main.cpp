#include <iostream>
#include <cstdint>
#include <vector>
#include <iomanip>
#include <cstdio>

#include "x86_64.hpp"
#include "elf.hpp"
#include "tac.hpp"

static void print_bytes(const std::vector<u8> &bytes) {
    for(u8 b : bytes) {
        std::cout << std::setfill('0') << std::setw(2) << std::hex << (u32)b << " ";
    }
    std::cout << std::endl;
}

int main() {
    std::vector<u8> bytes;

    TAC::InstructionGenerator generator;
    generator.push_label("_start");
    generator.push_var("b", 4);
    generator.push_var("c", 4);
    generator.append_instr_enter(0x18);
    generator.push_var("a", 4);
    generator.append_assign("a", TAC::OPC_ADD, "b", "c");
    generator.append_instr_leave();
    generator.print();

    TAC::CodeBuffer buffer;
    generator.encode(buffer);
    bytes.insert(bytes.end(), buffer.bytes.begin(), buffer.bytes.end());
    // print_bytes(bytes);
    // bytes.clear();

    // for(auto &label : buffer.labels) {
    //     std::printf("%08x, %s\n", label.position, label.name.c_str());
    // }


    ELF::ElfFile elf;
    elf.append_section("", ELF::SHT_NULL, 0, 0, 0, 0, 0);
    elf.append_section(".text", ELF::SHT_PROGBITS, 16, ELF::SHF_ALLOC | ELF::SHF_EXECINSTR, 0, 0, 0);
    elf.append_section(".data", ELF::SHT_PROGBITS, 4, ELF::SHF_ALLOC | ELF::SHF_WRITE, 0, 0, 0);
    elf.append_section(".symtab", ELF::SHT_SYMTAB, 8, 0, sizeof(ELF::Elf64_Sym), 0, 0);
    elf.append_section(".shstrtab", ELF::SHT_STRTAB, 1, 0, 0, 0, 0);
    elf.append_section(".strtab", ELF::SHT_STRTAB, 1, 0, 0, 0, 0);
    elf.append_section(".rela.text", ELF::SHT_RELA, 8, 0, sizeof(ELF::Elf64_Rela), 0, 0);

    elf.append_symbol(ELF::make_symbol("", "undef", 0, 0, 0));
    elf.append_symbol(ELF::make_symbol(".text", ".text", ELF::STB_LOCAL, ELF::STT_SECTION, 0));
    elf.append_symbol(ELF::make_symbol(".data", ".data", ELF::STB_LOCAL, ELF::STT_SECTION, 0));
    elf.append_symbol(ELF::make_symbol("exit_code", ".data", ELF::STB_LOCAL, ELF::STT_NOTYPE, 0));
    elf.append_symbol(ELF::make_symbol("msg", ".data", ELF::STB_LOCAL, ELF::STT_NOTYPE, 4));
    elf.append_symbol(ELF::make_symbol("printf", "undef", ELF::STB_GLOBAL, ELF::STT_NOTYPE, 0));
    elf.append_symbol(ELF::make_symbol("_start", ".text", ELF::STB_GLOBAL, ELF::STT_NOTYPE, 0));

    elf.get_section_by_name(".symtab")->link = elf.get_section_by_name(".strtab")->index;
    elf.get_section_by_name(".symtab")->info = elf.get_first_nonlocal_symbol_index();

    elf.get_section_by_name(".rela.text")->link = elf.get_section_by_name(".symtab")->index;
    elf.get_section_by_name(".rela.text")->info = elf.get_section_by_name(".text")->index;

    // elf.get_section_by_name(".data")->data.push_back(0x3C);
    // elf.get_section_by_name(".data")->data.push_back(0x00);
    // elf.get_section_by_name(".data")->data.push_back(0x00);
    // elf.get_section_by_name(".data")->data.push_back(0x00);

    // elf.get_section_by_name(".data")->data.push_back('H');
    // elf.get_section_by_name(".data")->data.push_back('e');
    // elf.get_section_by_name(".data")->data.push_back('l');
    // elf.get_section_by_name(".data")->data.push_back('l');
    // elf.get_section_by_name(".data")->data.push_back('o');
    // elf.get_section_by_name(".data")->data.push_back(',');
    // elf.get_section_by_name(".data")->data.push_back(' ');
    // elf.get_section_by_name(".data")->data.push_back('W');
    // elf.get_section_by_name(".data")->data.push_back('o');
    // elf.get_section_by_name(".data")->data.push_back('r');
    // elf.get_section_by_name(".data")->data.push_back('l');
    // elf.get_section_by_name(".data")->data.push_back('d');
    // elf.get_section_by_name(".data")->data.push_back('!');
    // elf.get_section_by_name(".data")->data.push_back('\n');

    // auto value_offsets = x86_64::encode_ri(x86_64::MOV, x86_64::REG_RDI, x86_64::make_imm<u64>(0)).encode(bytes);
    // elf.append_reloc(".data", 1, value_offsets.second, 4);
    // value_offsets = x86_64::encode_i(x86_64::CALL, x86_64::make_imm<u32>(0)).encode(bytes);
    // elf.append_reloc("printf", 2, value_offsets.second, -4);

    // value_offsets = x86_64::encode_rm(x86_64::MOV, x86_64::REG_EAX, x86_64::make_mem(4, 0, 0, x86_64::ADDR_INVALID_INDEX, x86_64::ADDR_INVALID_BASE)).encode(bytes);
    // elf.append_reloc(".data", 11, value_offsets.first, 0);
    // x86_64::encode_ri(x86_64::MOV, x86_64::REG_EDI, x86_64::make_imm<u32>(0)).encode(bytes);
    // x86_64::encode_zo(x86_64::SYSCALL).encode(bytes);

    for(u8 b : bytes) {
        elf.get_section_by_name(".text")->data.push_back(b);
    }
    elf.write("test.o");
    
    return 0;
}