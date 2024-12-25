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

    x86_64::encode_ri(
        x86_64::MOV,
        x86_64::REG_ECX,
        x86_64::make_imm<u32>(0x12345678))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_mi(
        x86_64::MOV,
        x86_64::make_addr(0x1234, 2, x86_64::REG_R11, x86_64::REG_R12),
        x86_64::make_imm<u32>(0x12345678))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_mi(
        x86_64::MOV,
        x86_64::make_addr(1, 1, x86_64::REG_R15, x86_64::REG_RDI),
        x86_64::make_imm<u16>(1))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_mi(
        x86_64::MOV,
        x86_64::make_addr(0x12345678, 3, x86_64::REG_R15, x86_64::REG_RDI),
        x86_64::make_imm<u8>(0xFF))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_mr(
        x86_64::MOV,
        x86_64::make_addr(1, 0, x86_64::REG_EAX, x86_64::REG_R15D),
        x86_64::REG_R8W)
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::encode_mi(
        x86_64::MOV,
        x86_64::make_addr(0, 0, x86_64::ADDR_INVALID_INDEX, x86_64::REG_RCX),
        x86_64::make_imm<u32>(0x1234))
        .encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    return 0;
}