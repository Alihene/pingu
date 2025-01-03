#include "tac.hpp"
#include "x86_64.hpp"

#include <cstdio>

TAC::InstructionGenerator::InstructionGenerator() {
    this->push_var("nullvar", 8); /* Invalid variable */
}

void TAC::InstructionGenerator::push_var(std::string name, u32 size) {
    /* TODO: remove hardcoded 8 byte alignment */
    this->stack_offsets[name] = this->stack_offsets.size() == 0 ? 0 : (this->stack_offsets.size() - 1) * 8;
    this->variables.push_back((TAC::Variable){name, size});
}

void TAC::InstructionGenerator::push_label(std::string name) {
    this->labels.push_back((TAC::Label){name, this->instructions.size()});
}

void TAC::InstructionGenerator::append_assign(u32 dst, u8 op, TAC::Operand first, TAC::Operand second) {
    TAC::Instruction insn;
    insn.type = TAC::Instruction::INSTR_ASSIGN;
    insn.dest = dst;
    insn.operation = op;
    insn.operands.first = first;
    insn.operands.second = second;
    this->instructions.push_back(insn);
}

void TAC::InstructionGenerator::append_assign(std::string dst, u8 op, std::string var_first, std::string var_second) {
    u32 dst_index;
    u32 first_index;
    u32 second_index;

    for(u32 i = 0; i < this->variables.size(); i++) {
        const auto &variable = this->variables[i];

        if(variable.name == dst) {
            dst_index = i;
        } else if(variable.name == var_first) {
            first_index = i;
        } else if(variable.name == var_second) {
            second_index = i;
        }
    }

    Operand operand_first;
    operand_first.type = TAC::Operand::OPERAND_VAR;
    operand_first.value.var_index = first_index;

    Operand operand_second;
    operand_second.type = TAC::Operand::OPERAND_VAR;
    operand_second.value.var_index = second_index;

    return this->append_assign(dst_index, op, operand_first, operand_second);
}

void TAC::InstructionGenerator::append_assign(std::string dst, u8 op, std::string var, u64 constant) {
    u32 dst_index;
    u32 var_index;

    for(u32 i = 0; i < this->variables.size(); i++) {
        const auto &variable = this->variables[i];

        if(variable.name == dst) {
            dst_index = i;
        } else if(variable.name == var) {
            var_index = i;
        }
    }

    Operand operand_first;
    operand_first.type = TAC::Operand::OPERAND_VAR;
    operand_first.value.var_index = var_index;

    Operand operand_second;
    operand_second.type = TAC::Operand::OPERAND_CONSTANT;
    operand_second.value.constant = constant;

    return this->append_assign(dst_index, op, operand_first, operand_second);
}

void TAC::InstructionGenerator::append_assign(std::string dst, u8 op, u64 constant, std::string var) {
    u32 dst_index;
    u32 var_index;

    for(u32 i = 0; i < this->variables.size(); i++) {
        const auto &variable = this->variables[i];

        if(variable.name == dst) {
            dst_index = i;
        } else if(variable.name == var) {
            var_index = i;
        }
    }

    Operand operand_first;
    operand_first.type = TAC::Operand::OPERAND_CONSTANT;
    operand_first.value.constant = constant;

    Operand operand_second;
    operand_second.type = TAC::Operand::OPERAND_VAR;
    operand_second.value.var_index = var_index;

    return this->append_assign(dst_index, op, operand_first, operand_second);
}

void TAC::InstructionGenerator::append_assign(std::string dst, u8 op, u64 constant1, u64 constant2) {
    u32 dst_index;

    for(u32 i = 0; i < this->variables.size(); i++) {
        const auto &variable = this->variables[i];

        if(variable.name == dst) {
            dst_index = i;
        }
    }

    Operand operand_first;
    operand_first.type = TAC::Operand::OPERAND_CONSTANT;
    operand_first.value.constant = constant1;

    Operand operand_second;
    operand_second.type = TAC::Operand::OPERAND_CONSTANT;
    operand_second.value.constant = constant2;

    return this->append_assign(dst_index, op, operand_first, operand_second);
}

void TAC::InstructionGenerator::append_goto(const std::string &label) {
    TAC::Instruction insn;
    insn.type = TAC::Instruction::INSTR_GOTO;
    insn.label_name = label;
    this->instructions.push_back(insn);
}

void TAC::InstructionGenerator::append_instr_enter(u32 stack_size) {
    TAC::Instruction insn;
    insn.type = TAC::Instruction::INSTR_ENTER;
    insn.stack_size = stack_size;
    this->instructions.push_back(insn);
}

void TAC::InstructionGenerator::append_instr_leave() {
    TAC::Instruction insn;
    insn.type = TAC::Instruction::INSTR_LEAVE;
    this->instructions.push_back(insn);
}

void TAC::InstructionGenerator::encode_assign_instr(const TAC::Instruction &insn, std::vector<u8> &bytes) const {
    u32 stack_offset_a = this->stack_offsets.at(this->variables[insn.dest].name);
    u32 stack_offset_b = this->stack_offsets.at(this->variables[insn.operands.first.value.var_index].name);
    u32 stack_offset_c = this->stack_offsets.at(this->variables[insn.operands.second.value.var_index].name);

    switch(insn.operation) {
        case TAC::OPC_NOP: {
            /* TODO */
            break;
        }
        case TAC::OPC_INC: {
            break;
        }
        case TAC::OPC_DEC: {
            break;
        }
        case TAC::OPC_ADD: {
            /* mov rbx, [rsp-offset_b] */
            x86_64::encode_rm(
                x86_64::MOV,
                x86_64::REG_RBX,
                x86_64::make_mem(
                    8,
                    stack_offset_b,
                    0,
                    x86_64::ADDR_INVALID_INDEX, x86_64::REG_RSP)).encode(bytes);
            /* add rbx, [rsp-offset_c] */
            x86_64::encode_rm(
                x86_64::ADD,
                x86_64::REG_RBX,
                x86_64::make_mem(
                    8,
                    stack_offset_c,
                    0,
                    x86_64::ADDR_INVALID_INDEX, x86_64::REG_RSP)).encode(bytes);
            /* mov [rsp-offset_a], rbx */
            x86_64::encode_mr(
                x86_64::MOV,
                x86_64::make_mem(
                    8,
                    stack_offset_a,
                    0,
                    x86_64::ADDR_INVALID_INDEX, x86_64::REG_RSP),
                x86_64::REG_RBX).encode(bytes);
            break;
        }
        case TAC::OPC_SUB: {
            break;
        }
        case TAC::OPC_MUL: {
            break;
        }
        case TAC::OPC_DIV: {
            break;
        }
        case TAC::OPC_LSHIFT: {
            break;
        }
        case TAC::OPC_RSHIFT: {

            break;
        }
        default: {
            break;
        }
    }
}

void TAC::InstructionGenerator::encode(CodeBuffer &buffer) const {
    std::vector<u8> &bytes = buffer.bytes;

    for(u32 i = 0; i < this->instructions.size(); i++) {
        const auto &insn = this->instructions[i];

        for(const auto &label : this->labels) {
            if(i == label.position) {
                buffer.labels.push_back((TAC::Label){label.name, bytes.size()});
            }
        }

        switch(insn.type) {
            case TAC::Instruction::INSTR_ASSIGN:
            {
                this->encode_assign_instr(insn, bytes);
                break;
            }
            case TAC::Instruction::INSTR_GOTO:
            {
                break;
            }
            case TAC::Instruction::INSTR_ENTER:
            {
                u32 stack_size = insn.stack_size;
                x86_64::encode_r(x86_64::PUSH, x86_64::REG_RBP).encode(bytes);
                x86_64::encode_rr(x86_64::MOV, x86_64::REG_RBP, x86_64::REG_RSP).encode(bytes);
                if(stack_size > 0) {
                    x86_64::encode_ri(x86_64::SUB, x86_64::REG_RSP, x86_64::make_imm<u32>(stack_size)).encode(bytes);
                }
                break;
            }
            case TAC::Instruction::INSTR_LEAVE:
            {
                x86_64::encode_rr(x86_64::MOV, x86_64::REG_RSP, x86_64::REG_RBP).encode(bytes);
                x86_64::encode_r(x86_64::POP, x86_64::REG_RBP).encode(bytes);
                x86_64::encode_zo(x86_64::RET).encode(bytes);
                break;
            }
            default:
            {
                break;
            }
        }
    }
}

static std::string operation_to_str(u8 op) {
    std::string str;
    switch(op) {
        case TAC::OPC_NOP: {
            str = "nop";
            break;
        }
        case TAC::OPC_INC: {
            str = "++";
            break;
        }
        case TAC::OPC_DEC: {
            str = "--";
            break;
        }
        case TAC::OPC_ADD: {
            str = "+";
            break;
        }
        case TAC::OPC_SUB: {
            str = "-";
            break;
        }
        case TAC::OPC_MUL: {
            str = "*";
            break;
        }
        case TAC::OPC_DIV: {
            str = "/";
            break;
        }
        case TAC::OPC_LSHIFT: {
            str = "<<";
            break;
        }
        case TAC::OPC_RSHIFT: {
            str = ">>";
            break;
        }
        default: {
            str = "err";
            break;
        }
    }
    return str;
}

void TAC::InstructionGenerator::print() const {
    for(u32 i = 0; i < this->instructions.size(); i++) {
        const auto &instruction = this->instructions[i];
        for(const auto &label : this->labels) {
            if(i == label.position) {
                std::printf("%s:\n", label.name.c_str());
            }
        }

        std::printf("    ");
        switch(instruction.type) {
            case TAC::Instruction::INSTR_ASSIGN:
            {
                std::string op_str = operation_to_str(instruction.operation);

                std::string op1_str, op2_str;
                op1_str = instruction.operands.first.type == TAC::Operand::OPERAND_VAR ?
                    this->variables[instruction.operands.first.value.var_index].name
                    : std::to_string(instruction.operands.first.value.constant);
                op2_str = instruction.operands.second.type == TAC::Operand::OPERAND_VAR ?
                    this->variables[instruction.operands.second.value.var_index].name
                    : std::to_string(instruction.operands.second.value.constant);

                if(op1_str == "nullvar") {
                    op1_str = "";
                }
                if(op2_str == "nullvar") {
                    op2_str = "";
                }

                std::printf(
                    "%s = %s %s %s\n",
                    this->variables[instruction.dest].name.c_str(),
                    op1_str.c_str(),
                    op_str.c_str(),
                    op2_str.c_str());
                break;
            }
            case TAC::Instruction::INSTR_GOTO:
            {
                std::printf("goto %s\n", instruction.label_name.c_str());
                break;
            }
            case TAC::Instruction::INSTR_ENTER:
            {
                std::printf("enter %x\n", instruction.stack_size);
                break;
            }
            case TAC::Instruction::INSTR_LEAVE:
            {
                std::printf("leave\n");
                break;
            }
            default:
            {
                break;
            }
        }
    }
}