#pragma once

#include <vector>
#include <iostream>
#include <unordered_map>

#include "util.hpp"

namespace TAC {

enum Operation : u8 {
    OPC_NOP = 0x00,
    OPC_INC = 0x01,
    OPC_DEC = 0x02,
    OPC_ADD = 0x03,
    OPC_SUB = 0x04,
    OPC_MUL = 0x05,
    OPC_DIV = 0x06,
    OPC_LSHIFT = 0x07,
    OPC_RSHIFT = 0x08,
};

struct Operand {
    enum {
        OPERAND_VAR,
        OPERAND_CONSTANT,
    } type;

    union {
        u32 var_index;
        u64 constant;
    } value;
};

struct Instruction {
    enum {
        INSTR_ASSIGN,
        INSTR_GOTO,
        INSTR_CALL,
        INSTR_ENTER, /* Enter function */
        INSTR_LEAVE, /* Leave function */
    } type;

    u8 operation;

    /* Used when type is INSTR_ASSIGN */
    u32 dest;

    /* Used when type is INSTR_GOTO or INSTR_CALL */
    std::string label_name;
    
    struct {
        Operand first;
        Operand second;
    } operands;

    /* Used when type is INSTR_ENTER */
    u32 stack_size;
};

struct Variable {
    std::string name;
    u32 size;
};

struct Label {
    std::string name;
    u32 position;
};

struct CodeBuffer {
    std::vector<u8> bytes;
    std::vector<Label> labels;
};

class InstructionGenerator {
public:
    std::vector<Variable> variables;
    std::unordered_map<std::string, u32> stack_offsets;

    std::vector<Label> labels;
    std::vector<Instruction> instructions;

    InstructionGenerator();

    void push_var(std::string name, u32 size);
    
    void push_label(std::string name);

    void append_assign(u32 dst, u8 op, Operand first, Operand second);
    void append_assign(std::string dst, u8 op, std::string var_first, std::string var_second);
    void append_assign(std::string dst, u8 op, std::string var, u64 constant);
    void append_assign(std::string dst, u8 op, u64 constant, std::string var);
    void append_assign(std::string dst, u8 op, u64 constant1, u64 constant2);
    void append_goto(const std::string &label);
    void append_instr_enter(u32 stack_size);
    void append_instr_leave();

    /* Encoding to native machine code */
    void encode(CodeBuffer &buffer) const;

    void print() const;

private:
    void encode_assign_instr(const Instruction &insn, std::vector<u8> &bytes) const;
};

}