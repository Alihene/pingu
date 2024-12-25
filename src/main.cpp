#include <iostream>
#include <cstdint>
#include <vector>
#include <iomanip>
#include <cstdio>

#include "x86_64.hpp"

static void print_bytes(const std::vector<u8> &bytes) {
    for(u8 b : bytes) {
        std::cout << std::setfill('0') << std::setw(2) << std::hex << (u32)b << " ";
    }
    std::cout << std::endl;
}

int main() {
    x86_64::init();

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
        x86_64::make_addr(
            0x1234,
            3,
            x86_64::REG_RDX,
            x86_64::REG_R12))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_mr(
        x86_64::ADD,
        x86_64::make_addr(0x1234, 3, x86_64::REG_RDX, x86_64::REG_R12),
        x86_64::REG_AL)
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    // x86_64::AddressValue addr3;
    // addr3.base = x86_64::REG_R12D;
    // addr3.index = x86_64::REG_ECX;
    // addr3.scale = 2;
    // addr3.displacement = 0x1234;
    x86_64::encode_rm(
        x86_64::MOV,
        x86_64::REG_AX,
        x86_64::make_addr(0x1234, 2, x86_64::REG_ECX, x86_64::REG_R12D))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_rr(x86_64::MOV, x86_64::REG_AL, x86_64::REG_BL)
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    // x86_64::ImmediateValue imm2 = {0};
    // imm2.size = 4;
    // imm2.val.dword = 0x12345678;
    x86_64::encode_ri(
        x86_64::MOV,
        x86_64::REG_ECX,
        x86_64::make_imm<u32>(0x12345678))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    // x86_64::AddressValue addr4;
    // addr4.base = x86_64::REG_R12;
    // addr4.index = x86_64::REG_R11;
    // addr4.scale = 2;
    // addr4.displacement = 0x1234;
    // x86_64::ImmediateValue imm3 = {0};
    // imm3.size = 4;
    // imm3.val.dword = 0x12345678;
    x86_64::encode_mi(
        x86_64::MOV,
        x86_64::make_addr(0x1234, 2, x86_64::REG_R11, x86_64::REG_R12),
        x86_64::make_imm<u32>(0x12345678))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    // x86_64::AddressValue addr5;
    // addr5.base = x86_64::REG_RDI;
    // addr5.index = x86_64::REG_R15;
    // addr5.scale = 1;
    // addr5.displacement = 1;
    // x86_64::ImmediateValue imm4 = {0};
    // imm4.size = 2;
    // imm4.val.word = 1;
    x86_64::encode_mi(
        x86_64::MOV,
        x86_64::make_addr(1, 1, x86_64::REG_R15, x86_64::REG_RDI),
        x86_64::make_imm<u16>(1))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    // x86_64::AddressValue addr6;
    // addr6.base = x86_64::REG_RDI;
    // addr6.index = x86_64::REG_R15;
    // addr6.scale = 3;
    // addr6.displacement = 0x12345678;
    // x86_64::ImmediateValue imm5 = {0};
    // imm5.size = 1;
    // imm5.val.byte = 0xFF;
    x86_64::encode_mi(
        x86_64::MOV,
        x86_64::make_addr(0x12345678, 3, x86_64::REG_R15, x86_64::REG_RDI),
        x86_64::make_imm<u8>(0xFF))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    // x86_64::AddressValue addr7;
    // addr7.base = x86_64::REG_R15D;
    // addr7.index = x86_64::REG_EAX;
    // addr7.scale = 0;
    // addr7.displacement = 1;
    x86_64::encode_mr(
        x86_64::MOV,
        x86_64::make_addr(1, 0, x86_64::REG_EAX, x86_64::REG_R15D),
        x86_64::REG_R8W)
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    return 0;
}