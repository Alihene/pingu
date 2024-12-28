#include <iostream>
#include <cstdint>
#include <vector>
#include <iomanip>
#include <cstdio>

#include "x86_64.hpp"
#include "elf.hpp"

static void print_bytes(const std::vector<u8> &bytes) {
    for(u8 b : bytes) {
        std::cout << std::setfill('0') << std::setw(2) << std::hex << (u32)b << " ";
    }
    std::cout << std::endl;
}

int main() {
    std::vector<u8> bytes;

    x86_64::encode_rr(x86_64::ADD, x86_64::REG_RAX, x86_64::REG_RCX)
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_ri(
        x86_64::ADD,
        x86_64::REG_R11,
        x86_64::make_imm<u32>(0x12345678))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_rm(
        x86_64::ADD,
        x86_64::REG_RCX,
        x86_64::make_mem(
            4,
            0x1234,
            3,
            x86_64::REG_RDX,
            x86_64::REG_R12))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_mr(
        x86_64::ADD,
        x86_64::make_mem(1, 0x1234, 3, x86_64::REG_RDX, x86_64::REG_R12),
        x86_64::REG_AL)
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_rm(
        x86_64::MOV,
        x86_64::REG_AX,
        x86_64::make_mem(2, 0x1234, 2, x86_64::REG_ECX, x86_64::REG_R12D))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_rr(x86_64::MOV, x86_64::REG_AL, x86_64::REG_BL)
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_ri(
        x86_64::MOV,
        x86_64::REG_ECX,
        x86_64::make_imm<u32>(0x12345678))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_mi(
        x86_64::MOV,
        x86_64::make_mem(4, 0x1234, 2, x86_64::REG_R11, x86_64::REG_R12),
        x86_64::make_imm<u32>(0x12345678))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_mi(
        x86_64::MOV,
        x86_64::make_mem(2, 1, 1, x86_64::REG_R15, x86_64::REG_RDI),
        x86_64::make_imm<u16>(1))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_mi(
        x86_64::MOV,
        x86_64::make_mem(1, 0x12345678, 3, x86_64::REG_R15, x86_64::REG_RDI),
        x86_64::make_imm<u8>(0xFF))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_mr(
        x86_64::MOV,
        x86_64::make_mem(2, 1, 0, x86_64::REG_EAX, x86_64::REG_R15D),
        x86_64::REG_R8W)
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_mi(
        x86_64::MOV,
        x86_64::make_mem(4, 0, 0, x86_64::ADDR_INVALID_INDEX, x86_64::REG_RCX),
        x86_64::make_imm<u32>(0x1234))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_m(
        x86_64::PUSH,
        x86_64::make_mem(8, 0x1234, 2, x86_64::REG_RAX, x86_64::REG_R12))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_r(
        x86_64::PUSH,
        x86_64::REG_RDX)
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_i(
        x86_64::PUSH,
        x86_64::make_imm<u8>(1))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_i(
        x86_64::PUSH,
        x86_64::make_imm<u32>(0x12345678))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_ri(x86_64::MOV, x86_64::REG_EAX, x86_64::make_imm<u32>(1)).encode(bytes);
    x86_64::encode_ri(x86_64::MOV, x86_64::REG_EDI, x86_64::make_imm<u32>(1)).encode(bytes);
    x86_64::encode_ri(x86_64::MOV, x86_64::REG_EDX, x86_64::make_imm<u32>(14)).encode(bytes);
    x86_64::encode_ri(x86_64::MOV, x86_64::REG_RSI, x86_64::make_imm<u64>(0)).encode(bytes);
    x86_64::encode_zo(x86_64::SYSCALL).encode(bytes);

    // x86_64::encode_rm(
    //     x86_64::MOV,
    //     x86_64::REG_RAX,
    //     x86_64::make_mem(4, 0, 0, x86_64::ADDR_INVALID_INDEX, x86_64::ADDR_INVALID_BASE))
    //     .encode(bytes);
    x86_64::encode_ri(x86_64::MOV, x86_64::REG_EAX, x86_64::make_imm<u32>(0x3c)).encode(bytes);
    x86_64::encode_ri(x86_64::MOV, x86_64::REG_EDI, x86_64::make_imm<u32>(0)).encode(bytes);
    x86_64::encode_zo(x86_64::SYSCALL).encode(bytes);

    ELF::ElfFile elf = ELF::init_elf();
    elf.append_section("", ELF::SHT_NULL, 0, 0, 0, 0, 0);
    elf.append_section(".text", ELF::SHT_PROGBITS, 16, ELF::SHF_ALLOC | ELF::SHF_EXECINSTR, 0, 0, 0);
    elf.append_section(".data", ELF::SHT_PROGBITS, 4, ELF::SHF_ALLOC | ELF::SHF_WRITE, 0, 0, 0);
    elf.append_section(".symtab", ELF::SHT_SYMTAB, 8, 0, sizeof(ELF::Elf64_Sym), 5, 4);
    elf.append_section(".shstrtab", ELF::SHT_STRTAB, 1, 0, 0, 0, 0);
    elf.append_section(".strtab", ELF::SHT_STRTAB, 1, 0, 0, 0, 0);
    elf.append_section(".rela.text", ELF::SHT_RELA, 8, 0, sizeof(ELF::Elf64_Rela), 3, 1);

    ELF::Symbol symbol1 = {"", "undef", 0, 0, 0};
    ELF::append_symbol(elf, symbol1);

    ELF::Symbol symbol2 = {".text", ".text", ELF64_ST_INFO(ELF::STB_LOCAL, ELF::STT_SECTION), 0, 0};
    ELF::append_symbol(elf, symbol2);

    ELF::Symbol symbol3 = {".data", ".data", ELF64_ST_INFO(ELF::STB_LOCAL, ELF::STT_SECTION), 0, 0};
    ELF::append_symbol(elf, symbol3);

    // ELF::Symbol symbol4 = {"exit_code", ".data", ELF64_ST_INFO(ELF::STB_LOCAL, ELF::STT_NOTYPE), 0, 0};
    // ELF::append_symbol(elf, symbol4);

    ELF::Symbol symbol5 = {"msg", ".data", ELF64_ST_INFO(ELF::STB_LOCAL, ELF::STT_NOTYPE), 0, 0};
    ELF::append_symbol(elf, symbol5);

    ELF::Symbol symbol6 = {"_start", ".text", ELF64_ST_INFO(ELF::STB_GLOBAL, ELF::STT_NOTYPE), 0, 0};
    ELF::append_symbol(elf, symbol6);

    elf.get_section_by_name(".data")->data.push_back(0x3C);

    elf.get_section_by_name(".data")->data.push_back('H');
    elf.get_section_by_name(".data")->data.push_back('e');
    elf.get_section_by_name(".data")->data.push_back('l');
    elf.get_section_by_name(".data")->data.push_back('l');
    elf.get_section_by_name(".data")->data.push_back('o');
    elf.get_section_by_name(".data")->data.push_back(',');
    elf.get_section_by_name(".data")->data.push_back(' ');
    elf.get_section_by_name(".data")->data.push_back('W');
    elf.get_section_by_name(".data")->data.push_back('o');
    elf.get_section_by_name(".data")->data.push_back('r');
    elf.get_section_by_name(".data")->data.push_back('l');
    elf.get_section_by_name(".data")->data.push_back('d');
    elf.get_section_by_name(".data")->data.push_back('!');
    elf.get_section_by_name(".data")->data.push_back('\n');

    // ELF::Elf64_Rela rela2 = {
    //     0x1F,
    //     14ULL + (2ULL << 32),
    //     0
    // };
    // u8 *rela_bytes = reinterpret_cast<u8*>(&rela2);
    // for(u32 i = 0; i < sizeof(ELF::Elf64_Rela); i++) {
    //     elf.get_section_by_name(".rela.text")->data.push_back(rela_bytes[i]);
    // }

    ELF::Elf64_Rela rela = {
        0x11,
        1ULL + (2ULL << 32),
        1
    };
    u8 *rela_bytes = reinterpret_cast<u8*>(&rela);
    for(u32 i = 0; i < sizeof(ELF::Elf64_Rela); i++) {
        elf.get_section_by_name(".rela.text")->data.push_back(rela_bytes[i]);
    }

    for(u8 b : bytes) {
        elf.sections[1].data.push_back(b);
    }
    ELF::write("test.o", elf);
    
    return 0;
}