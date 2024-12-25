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
    x86_64::InstructionData insn;

    insn = x86_64::encode_rr(x86_64::ADD, x86_64::REG_RAX, x86_64::REG_RCX);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::ImmediateValue imm = {0};
    imm.type = x86_64::ImmediateValue::IMM_INT;
    imm.size = 4;
    imm.val.dword = 0x12345678;
    insn = x86_64::encode_ri(x86_64::ADD, x86_64::REG_R11, imm);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::AddressValue addr;
    addr.base = x86_64::REG_R12;
    addr.index = x86_64::REG_RDX;
    addr.scale = 3;
    addr.displacement = 0x1234;
    insn = x86_64::encode_rm(x86_64::ADD, x86_64::REG_RCX, addr);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::AddressValue addr2;
    addr2.base = x86_64::REG_R12;
    addr2.index = x86_64::REG_RDX;
    addr2.scale = 3;
    addr2.displacement = 0x1234;
    insn = x86_64::encode_mr(x86_64::ADD, addr2, x86_64::REG_AL);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::AddressValue addr3;
    addr3.base = x86_64::REG_R12D;
    addr3.index = x86_64::REG_ECX;
    addr3.scale = 2;
    addr3.displacement = 0x1234;
    insn = x86_64::encode_rm(x86_64::MOV, x86_64::REG_AX, addr3);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    insn = x86_64::encode_rr(x86_64::MOV, x86_64::REG_AL, x86_64::REG_BL);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::ImmediateValue imm2 = {0};
    imm2.type = x86_64::ImmediateValue::IMM_INT;
    imm2.size = 4;
    imm2.val.qword = 0x12345678;
    insn = x86_64::encode_ri(x86_64::MOV, x86_64::REG_ECX, imm2);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::AddressValue addr4;
    addr4.base = x86_64::REG_R12;
    addr4.index = x86_64::REG_R11;
    addr4.scale = 2;
    addr4.displacement = 0x1234;
    x86_64::ImmediateValue imm3 = {0};
    imm3.type = x86_64::ImmediateValue::IMM_INT;
    imm3.size = 4;
    imm3.val.dword = 0x12345678;
    insn = x86_64::encode_mi(x86_64::MOV, addr4, imm3);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    x86_64::AddressValue addr5;
    addr5.base = x86_64::REG_RDI;
    addr5.index = x86_64::REG_R15;
    addr5.scale = 1;
    addr5.displacement = 1;
    x86_64::ImmediateValue imm4 = {0};
    imm4.type = x86_64::ImmediateValue::IMM_INT;
    imm4.size = 2;
    imm4.val.word = 1;
    insn = x86_64::encode_mi(x86_64::MOV, addr5, imm4);
    insn.encode(bytes);
    print_bytes(bytes);
    bytes.clear();

    return 0;
}