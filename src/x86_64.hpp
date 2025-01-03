#pragma once

#include <vector>
#include <utility>
#include <span>
#include <type_traits>
#include <cstdio>

#include "util.hpp"
#include "elf.hpp"

namespace x86_64 {

using Reg = u8;

using imm8 = u8;
using imm16 = u16;
using imm32 = u32;
using imm64 = u64;

enum Registers : Reg {
    REG_AL = 0x0,
    REG_CL = 0x1,
    REG_DL = 0x2,
    REG_BL = 0x3,
    REG_SPL = 0x4,
    REG_BPL = 0x5,
    REG_SIL = 0x6,
    REG_DIL = 0x7,
    REG_R8B = 0x8,
    REG_R9B = 0x9,
    REG_R10B = 0xA,
    REG_R11B = 0xB,
    REG_R12B = 0xC,
    REG_R13B = 0xD,
    REG_R14B = 0xE,
    REG_R15B = 0xF,

    REG_AX = 0x10,
    REG_CX = 0x11,
    REG_DX = 0x12,
    REG_BX = 0x13,
    REG_SP = 0x14,
    REG_BP = 0x15,
    REG_SI = 0x16,
    REG_DI = 0x17,
    REG_R8W = 0x18,
    REG_R9W = 0x19,
    REG_R10W = 0x1A,
    REG_R11W = 0x1B,
    REG_R12W = 0x1C,
    REG_R13W = 0x1D,
    REG_R14W = 0x1E,
    REG_R15W = 0x1F,

    REG_EAX = 0x20,
    REG_ECX = 0x21,
    REG_EDX = 0x22,
    REG_EBX = 0x23,
    REG_ESP = 0x24,
    REG_EBP = 0x25,
    REG_ESI = 0x26,
    REG_EDI = 0x27,
    REG_R8D = 0x28,
    REG_R9D = 0x29,
    REG_R10D = 0x2A,
    REG_R11D = 0x2B,
    REG_R12D = 0x2C,
    REG_R13D = 0x2D,
    REG_R14D = 0x2E,
    REG_R15D = 0x2F,

    REG_RAX = 0x30,
    REG_RCX = 0x31,
    REG_RDX = 0x32,
    REG_RBX = 0x33,
    REG_RSP = 0x34,
    REG_RBP = 0x35,
    REG_RSI = 0x36,
    REG_RDI = 0x37,
    REG_R8 = 0x38,
    REG_R9 = 0x39,
    REG_R10 = 0x3A,
    REG_R11 = 0x3B,
    REG_R12 = 0x3C,
    REG_R13 = 0x3D,
    REG_R14 = 0x3E,
    REG_R15 = 0x3F,

    REG_AH = 0x44,
    REG_CH = 0x45,
    REG_DH = 0x46,
    REG_BH = 0x47,
};

constexpr u8 REX_BASE = 0x40;
constexpr u8 REX_W = 8;
constexpr u8 REX_R = 4;
constexpr u8 REX_X = 2;
constexpr u8 REX_B = 1;

/* 
 * These types are taken from the Intel SDM volume 2 to remove any ambiguity.
 * https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
 */
constexpr u32 OP_EN_ZO = 0;
constexpr u32 OP_EN_MR = 1;
constexpr u32 OP_EN_RM = 2;
constexpr u32 OP_EN_OI = 3;
constexpr u32 OP_EN_MI = 4;
constexpr u32 OP_EN_M = 5;
constexpr u32 OP_EN_O = 6;
constexpr u32 OP_EN_I = 7;
constexpr u32 OP_EN_R = 8;
constexpr u32 OP_EN_MRI = 9;
constexpr u32 OP_EN_RMI = 10;
/* Note: this is basically the same as OP_EN_I */
constexpr u32 OP_EN_D = 11;

struct alignas(16) InstructionData {
    std::vector<u8> prefixes;
    std::pair<bool, u8> opcode[3];
    u8 modrm;
    u8 sib;
    u8 displacement_value_size;
    u64 displacement_value;
    u8 immediate_value_size;
    u64 immediate_value;
    bool has_rex;
    bool has_modrm;
    bool has_sib;
    bool has_displacement_value;
    bool has_immediate_value;

    inline InstructionData() :
        opcode{std::make_pair(false, 0)},
        modrm(0),
        sib(0),
        displacement_value_size(0),
        displacement_value(0),
        immediate_value_size(0),
        immediate_value(0),
        has_rex(0),
        has_modrm(0),
        has_sib(0),
        has_displacement_value(0),
        has_immediate_value(0) {}

    inline void set_rex(bool w, bool r, bool x, bool b) {
        this->has_rex = true;
        u8 rex = 0b01000000;
        if(w) {
            rex |= 8;
        }
        if(r) {
            rex |= 4;
        }
        if(x) {
            rex |= 2;
        }
        if(b) {
            rex |= 1;
        }

        this->prefixes.push_back(rex);
    }

    inline void set_rex(u8 rex) {
        this->has_rex = true;
        this->prefixes.push_back(rex);
    }

    inline void push_prefix(u8 prefix) {
        this->prefixes.push_back(prefix);
    }

    inline void set_opcode(const u8 *opc, u8 size) {
        u32 k = 0;
        for(i32 i = 0; i < size; i++) {
            this->opcode[i] = std::make_pair(true, opc[i]);
            k++;
        }

        for(u32 j = k; j < 3; j++) {
            this->opcode[j] = std::make_pair(false, (u8) 0);
        }
    }

    inline void set_modrm(u8 mod, u8 reg, u8 rm) {
        this->has_modrm = true;
        this->modrm = (mod << 6) | (reg << 3) | rm;
    }

    inline void set_sib(u8 scale, u8 index, u8 base) {
        this->has_sib = true;
        this->sib = (scale << 6) | (index << 3) | base;
    }

    inline void set_displacement(u64 x, u8 size) {
        this->has_displacement_value = true;
        this->displacement_value_size = size;
        this->displacement_value = x;
    }

    inline void set_immediate(u64 x, u8 size) {
        this->has_immediate_value = true;
        this->immediate_value_size = size;
        this->immediate_value = x;
    }

    /* Returns a pair of the offsets of the displacement and immediate values respectively. Used for relocations. */
    inline std::pair<u32, u32> encode(std::vector<u8> &out_bytes) const {
        std::pair<u32, u32> value_offsets = std::make_pair<u32, u32>(0, 0);

        for(u32 i = 0; i < this->prefixes.size(); i++) {
            out_bytes.push_back(this->prefixes[i]);
        }

        if(this->opcode[0].first) out_bytes.push_back(this->opcode[0].second);
        if(this->opcode[1].first) out_bytes.push_back(this->opcode[1].second);
        if(this->opcode[2].first) out_bytes.push_back(this->opcode[2].second);
        if(this->has_modrm) out_bytes.push_back(this->modrm);
        if(this->has_sib) out_bytes.push_back(this->sib);

        if(this->has_displacement_value) {
            value_offsets.first = out_bytes.size();
            for(u32 i = 0; i < this->displacement_value_size; i++) {
                out_bytes.push_back((this->displacement_value & (0xFFULL << (i * 8))) >> (i * 8));
            }
        }
        if(this->has_immediate_value) {
            value_offsets.second = out_bytes.size();
            for(u32 i = 0; i < this->immediate_value_size; i++) {
                out_bytes.push_back((this->immediate_value & (0xFFULL << (i * 8))) >> (i * 8));
            }
        }
        return value_offsets;
    }
};

constexpr u8 ADDR_INVALID_BASE = 0xFF;
constexpr u8 ADDR_INVALID_INDEX = 0xFF;

struct AddressValue {
    u32 displacement;

    /* An index or base with a value of 0xFF means they are invalid. */
    u8 scale, index, base;

    ELF::Symbol *sym;

    inline AddressValue(): displacement(0), scale(0), index(0xFF), base(0xFF), sym(nullptr) {}

    inline bool is_displacement_8_bit() const {
        return (this->displacement & 0xFFFFFF00) == 0;
    }

    inline bool is_index_valid() const {
        return this->index != ADDR_INVALID_INDEX;
    }

    inline bool is_base_valid() const {
        return this->base != ADDR_INVALID_BASE;
    }
};

struct alignas(16) ImmediateValue {
    u8 size;
    union {
        imm8 byte;
        imm16 word;
        imm32 dword;
        imm64 qword;
    } val;
};

template<typename T>
inline ImmediateValue make_imm(T value) {
    ImmediateValue imm;
    if constexpr(std::is_same<T, u8>::value) {
        imm.size = 1;
        imm.val.byte = value;
    } else if constexpr(std::is_same<T, u16>::value) {
        imm.size = 2;
        imm.val.word = value;
    } else if constexpr(std::is_same<T, u32>::value) {
        imm.size = 4;
        imm.val.dword = value;
    } else if constexpr(std::is_same<T, u64>::value) {
        imm.size = 8;
        imm.val.qword = value;
    }
    return imm;
}

struct MemoryValue {
    u8 size;
    AddressValue addr;
};

inline AddressValue make_addr(u32 displacement, u8 scale, u8 index, u8 base) {
    AddressValue addr;
    addr.displacement = displacement;
    addr.scale = scale;
    addr.index = index;
    addr.base = base;
    return addr;
}

inline MemoryValue make_mem(u8 size, u32 displacement, u8 scale, u8 index, u8 base) {
    MemoryValue mem;
    mem.size = size;
    mem.addr = make_addr(displacement, scale, index, base);
    return mem;
}

struct EncodingData {
    u8 opcode;

    u8 prefix[4];

    u8 enc_opcode[3];

    u8 opcode_size;

    /* Operand encoding (Op/En in the intel SDM) */
    u32 op_en;

    u8 default_modrm_reg;

    bool is_8_bit;

    inline bool encode_operand_in_opcode() const {
        return this->op_en == OP_EN_O || this->op_en == OP_EN_OI;
    }
};

enum OperatingMode {
    /* Real/virtual 8086 mode */
    MODE_16_BIT,

    /* Protected/compatibility mode */
    MODE_32_BIT,

    /* Long mode */
    MODE_64_BIT,
};

enum Opcodes : u8 {
    NOP = 0x00,
    ADD = 0x01,
    SUB = 0x02,
    IMUL = 0x03,
    DIV = 0x04,
    IDIV = 0x05,
    MOV = 0x06,
    CALL = 0x07,
    JMP = 0x08,
    PUSH = 0x09,
    POP = 0x0A,
    RET = 0x0B,
    SYSCALL = 0x0C,
};

using EncodingList = std::vector<EncodingData>;

InstructionData encode_zo(EncodingData data);
InstructionData encode_r(EncodingData data, Reg reg);
InstructionData encode_i(EncodingData data, ImmediateValue imm);
InstructionData encode_m(EncodingData data, MemoryValue mem);
InstructionData encode_rr(EncodingData data, Reg reg, Reg rm);
InstructionData encode_ri(EncodingData data, Reg r, bool is_rm, ImmediateValue imm);
InstructionData encode_rm(EncodingData data, Reg reg, MemoryValue mem);
InstructionData encode_mi(EncodingData data, MemoryValue mem, ImmediateValue imm);

InstructionData encode_zo(u8 opcode);
InstructionData encode_r(u8 opcode, Reg r1);
InstructionData encode_i(u8 opcode, ImmediateValue imm);
InstructionData encode_m(u8 opcode, MemoryValue mem);
InstructionData encode_rr(u8 opcode, Reg r1, Reg r2);
InstructionData encode_ri(u8 opcode, Reg r1, ImmediateValue imm);
InstructionData encode_rm(u8 opcode, Reg r1, MemoryValue mem);
InstructionData encode_mr(u8 opcode, MemoryValue mem, Reg r1);
InstructionData encode_mi(u8 opcode, MemoryValue mem, ImmediateValue imm);

void set_mode(OperatingMode mode);
OperatingMode get_current_mode();

}

#define ENCODE_REG(r) ((r) % 8)
#define IS_REG_EXTENDED(r) ( \
    ((r) >= x86_64::REG_R8B && (r) <= x86_64::REG_R15B) \
    || ((r) >= x86_64::REG_R8W && (r) <= x86_64::REG_R15W) \
    || ((r) >= x86_64::REG_R8D && (r) <= x86_64::REG_R15D) \
    || ((r) >= x86_64::REG_R8 && (r) <= x86_64::REG_R15))
#define IS_REG_8_BIT(r) ((r) <= x86_64::REG_R15B || (r) >= x86_64::REG_AH)
#define IS_REG_16_BIT(r) ((r) >= x86_64::REG_AX && (r) <= x86_64::REG_R15W)
#define IS_REG_32_BIT(r) ((r) >= x86_64::REG_EAX && (r) <= x86_64::REG_R15D)
#define IS_REG_64_BIT(r) ((r) >= x86_64::REG_RAX && (r) <= x86_64::REG_R15)
#define IS_REG_HIGHER_HALF_8_BIT(r) ((r) >= x86_64::REG_AH)

#define REG_MATCHING_SIZES(r1, r2) ( \
    (IS_REG_8_BIT(r1) && IS_REG_8_BIT(r2))\
    || (IS_REG_16_BIT(r1) && IS_REG_16_BIT(r2)) \
    || (IS_REG_32_BIT(r1) && IS_REG_32_BIT(r2)) \
    || (IS_REG_64_BIT(r1) && IS_REG_64_BIT(r2)))