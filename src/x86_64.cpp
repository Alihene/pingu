#include "x86_64.hpp"

static x86_64::OperatingMode current_mode = x86_64::MODE_64_BIT;

x86_64::InstructionData x86_64::encode_i(x86_64::EncodingData data, x86_64::ImmediateValue imm) {
    x86_64::InstructionData insn;

    insn.set_opcode_3b(
        data.enc_opcode[0],
        data.enc_opcode[1],
        data.enc_opcode[2]);

    switch(imm.size) {
        case 1:
        {
            insn.set_immediate(imm.val.byte, 1);
            break;
        }
        case 2:
        {
            insn.set_immediate(imm.val.word, 2);
            break;
        }
        case 4:
        {
            insn.set_immediate(imm.val.dword, 4);
            break;
        }
        case 8:
        {
            insn.set_immediate(imm.val.qword, 8);
            break;
        }
        default:
        {
            break;
        }
    }
    return insn;
}

x86_64::InstructionData x86_64::encode_rr(x86_64::EncodingData data, x86_64::Reg r1, x86_64::Reg r2) {
    x86_64::InstructionData insn;

    if(IS_REG_16_BIT(r1) || IS_REG_16_BIT(r2)) {
        insn.push_prefix(0x66);
    }

    bool rex_needed = false;
    u8 rex = REX_BASE;
    if(IS_REG_64_BIT(r1) || IS_REG_64_BIT(r2)) {
        rex |= REX_W;
        rex_needed = true;
    }
    if(IS_REG_EXTENDED(r1)) {
        rex |= REX_R;
        rex_needed = true;
    }
    if(IS_REG_EXTENDED(r2)) {
        rex |= REX_B;
        rex_needed = true;
    }
    if(r1 == x86_64::REG_SPL || r2 == x86_64::REG_SPL
        || r1 == x86_64::REG_BPL || r2 == x86_64::REG_BPL
        || r1 == x86_64::REG_SIL || r2 == x86_64::REG_SIL
        || r1 == x86_64::REG_DIL || r2 == x86_64::REG_DIL) {
        // These need a REX prefix to access
        rex_needed = true;
    }
    
    if(rex_needed) {
        insn.set_rex(rex);
    }

    insn.set_opcode_3b(
        data.enc_opcode[0],
        data.enc_opcode[1],
        data.enc_opcode[2]);

    insn.set_modrm(3, r1 % 8, r2 % 8);
    return insn;
}

x86_64::InstructionData x86_64::encode_ri(x86_64::EncodingData data, x86_64::Reg r1, x86_64::ImmediateValue imm) {
    x86_64::InstructionData insn;

    if(IS_REG_16_BIT(r1)) {
        insn.push_prefix(0x66);
    }

    bool rex_needed = false;
    u8 rex = REX_BASE;
    if(IS_REG_64_BIT(r1)) {
        rex |= REX_W;
        rex_needed = true;
    }
    if(IS_REG_EXTENDED(r1)) {
        rex |= REX_R;
        rex_needed = true;
    }
    if(r1 == x86_64::REG_SPL
        || r1 == x86_64::REG_BPL
        || r1 == x86_64::REG_SIL
        || r1 == x86_64::REG_DIL) {
        // These need a REX prefix to access
        rex_needed = true;
    }
    
    if(rex_needed) {
        insn.set_rex(rex);
    }

    insn.set_opcode_3b(
        data.enc_opcode[0],
        data.enc_opcode[1],
        data.enc_opcode[2]);

    insn.set_modrm(3, 0, r1 % 8);

    switch(imm.size) {
        case 1:
        {
            insn.set_immediate(imm.val.byte, 1);
            break;
        }
        case 2:
        {
            insn.set_immediate(imm.val.word, 2);
            break;
        }
        case 4:
        {
            insn.set_immediate(imm.val.dword, 4);
            break;
        }
        case 8:
        {
            insn.set_immediate(imm.val.qword, 8);
            break;
        }
        default:
        {
            break;
        }
    }
    return insn;
}

x86_64::InstructionData x86_64::encode_rm(x86_64::EncodingData data, x86_64::Reg r1, x86_64::AddressValue addr) {
    x86_64::InstructionData insn;

    if(IS_REG_16_BIT(r1)) {
        insn.push_prefix(0x66);
    }

    if(IS_REG_32_BIT(addr.base) || IS_REG_32_BIT(addr.index)) {
        insn.push_prefix(0x67);
    }

    bool rex_needed = false;
    u8 rex = REX_BASE;
    if(IS_REG_64_BIT(r1)) {
        rex |= REX_W;
        rex_needed = true;
    }
    if(IS_REG_EXTENDED(r1)) {
        rex |= REX_R;
        rex_needed = true;
    }
    if(addr.is_index_valid() && IS_REG_EXTENDED(addr.index)) {
        rex |= REX_X;
        rex_needed = true;
    }
    if(addr.is_base_valid() && IS_REG_EXTENDED(addr.base)) {
        rex |= REX_B;
        rex_needed = true;
    }
    if(r1 == x86_64::REG_SPL
        || r1 == x86_64::REG_BPL
        || r1 == x86_64::REG_SIL
        || r1 == x86_64::REG_DIL) {
        // These need a REX prefix to access
        rex_needed = true;
    }

    if(rex_needed) {
        insn.set_rex(rex);
    }

    insn.set_opcode_3b(
        data.enc_opcode[0],
        data.enc_opcode[1],
        data.enc_opcode[2]);
    
    bool has_sib = addr.is_index_valid(); // We only need an SIB byte if we have a scaled index
    bool has_displacement = addr.displacement > 0;

    insn.set_modrm(
        has_displacement && addr.is_base_valid() ? 2 : 0, // If we have no base, we omit mod 10
        ENCODE_REG(r1),
        has_sib ? 4 : ENCODE_REG(addr.base));

    has_displacement |= (!addr.is_base_valid() && addr.is_index_valid()); // Edge case

    if(has_sib) {
        insn.set_sib(addr.scale, ENCODE_REG(addr.index), !addr.is_base_valid() ? 0b101 : ENCODE_REG(addr.base));
        if(((insn.sib & 3) == 0b101) || has_displacement) {
            insn.set_displacement(addr.displacement, 4);
        }
    } else {
        if(has_displacement) {
            insn.set_displacement(addr.displacement, 4);
        }
    }

    return insn;
}

void x86_64::set_mode(x86_64::OperatingMode mode) {
    current_mode = mode;
}

x86_64::OperatingMode x86_64::get_current_mode() {
    return current_mode;
}