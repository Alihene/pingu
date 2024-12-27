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

    x86_64::encode_ri(x86_64::MOV, x86_64::REG_EAX, x86_64::make_imm<u32>(60)).encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_ri(x86_64::MOV, x86_64::REG_EDI, x86_64::make_imm<u32>(0)).encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_zo(x86_64::SYSCALL).encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    ELF::ElfFile elf = ELF::init_elf();
    ELF::write("test.o", elf);
    
    return 0;
}