from collections import namedtuple
import sys
import string
from pwn import *
import z3
from z3 import *

reg_names = ('r0', 'r1', 'rlibc', 'rexe', 'r4', 'r5', 'r6', 'r7', 'r8',
             'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'rsp')

syscall_names = dict([(
                int(getattr(constants.linux.amd64,v)),v) 
                for v in dir(constants.linux.amd64) if v.startswith('SYS_')
                ])

Halt = namedtuple('Halt',['addr'])
MovImm = namedtuple('MovImm',['addr','reg','imm'])
MovReg = namedtuple('MovReg',['addr','dst','src'])

Mov = namedtuple('Mov',['addr','dst','src'])
Add = namedtuple('Add',['addr','dst','src'])
Sub = namedtuple('Sub',['addr','dst','src'])
Mul = namedtuple('Mul',['addr','dst','src'])
Mod = namedtuple('Mod',['addr','dst','src'])
And = namedtuple('And',['addr','dst','src'])
Or  = namedtuple('Or', ['addr','dst','src'])
Xor = namedtuple('Xor',['addr','dst','src'])
Shr = namedtuple('Shr',['addr','dst','src'])
alu_ops = (Add,Sub,Mul,Mod,And,Or,Xor,Shr)

MemLoad = namedtuple('MemLoad', ['addr','dst','src'])
MemStore = namedtuple('MemStore', ['addr','dst','src'])
RomLoad = namedtuple('RomLoad', ['addr','dst', 'src'])
Jump = namedtuple('Jump', ['addr','target'])
JumpReg = namedtuple('JumpReg', ['addr','reg'])
JumpEq = namedtuple('JumpEq', ['addr','target','lhs','rhs'])
PrintReg = namedtuple('Print', ['addr','reg'])

# Artifical instructions
PushImm = namedtuple('PushImm', ['addr', 'imm'])
PushReg = namedtuple('PushReg', ['addr', 'reg'])
Pop = namedtuple('Pop', ['addr', 'reg'])

Call = namedtuple('Call', ['addr', 'target'])
Ret = namedtuple('Ret', ['addr'])

CallSyscall = namedtuple('CallSyscall', ['addr', 'target', 'syscall'])

ExPushReg = namedtuple('ExPushReg', ['addr', 'reg'])
ExPushImm = namedtuple('ExPushImm', ['addr', 'imm'])
ExAdd = namedtuple('ExAdd', ['addr'])
ExMul = namedtuple('ExMul', ['addr'])
ExXor = namedtuple('ExXor', ['addr'])
ExEqz = namedtuple('ExEqz', ['addr'])
ExAnd = namedtuple('ExAnd', ['addr'])
ExPop = namedtuple('ExPop', ['addr', 'reg'])
ExReset = namedtuple('ExReset', ['addr'])

def get_libc_rop(addr):
    addr_as_str = f'0x{addr:016x}'
    # Built with: ROPgadget --all --binary breach > libc-rops.txt
    with open('libc-rops.txt') as rop_file:
        for line in rop_file:
            if line.startswith(addr_as_str):
                return line[len(addr_as_str)+3:].strip()
    return ''

def parse(buffer):
    instructions = []

    offset = 0
    while offset < len(buffer):
        opcode = buffer[offset] & 0xf

        match opcode:
            case 0:
                instructions.append(Halt(offset))
                offset += 1
            case 1:
                reg = buffer[offset] >> 4
                imm = u64(buffer[offset+1:offset+9])
                instructions.append(MovImm(offset, reg, imm))
                offset += 9
            case 2:
                reg1 = buffer[offset+1] & 0xf
                reg2 = buffer[offset+1] >> 4
                instructions.append(MovReg(offset, reg1, reg2))
                offset += 2
            case 3:
                aluop = buffer[offset] >> 4
                reg1 = buffer[offset+1] & 0xf
                reg2 = buffer[offset+1] >> 4
                Op = alu_ops[aluop]
                instructions.append(Op(offset, reg1, reg2))
                offset += 2
            case 4:
                reg1 = buffer[offset+1] & 0xf
                reg2 = buffer[offset+1] >> 4
                instructions.append(MemStore(offset, reg1, reg2))
                offset += 2
            case 5:
                reg1 = buffer[offset+1] & 0xf
                reg2 = buffer[offset+1] >> 4
                instructions.append(MemLoad(offset, reg2, reg1))
                offset += 2
            case 6:
                reg1 = buffer[offset+1] & 0xf
                reg2 = buffer[offset+1] >> 4
                instructions.append(RomLoad(offset, reg2, reg1))
                offset += 2
            case 7:
                target = u64(buffer[offset+1:offset+9])
                instructions.append(Jump(offset, target))
                offset += 9
            case 8:
                reg = buffer[offset] >> 4
                instructions.append(JumpReg(offset, reg))
                offset += 1
            case 9:
                reg1 = buffer[offset+1] & 0xf
                reg2 = buffer[offset+1] >> 4
                target = u64(buffer[offset+2:offset+10])
                instructions.append(JumpEq(offset, target, reg1, reg2))
                offset += 10
            case 10:
                inst = buffer[offset] >> 4
                other = buffer[offset+1]
                match inst:
                    case 0:
                        instructions.append(ExPushReg(offset, other))
                    case 1:
                        instructions.append(ExPushImm(offset, other))
                    case 2:
                        instructions.append(ExAdd(offset))
                    case 3:
                        instructions.append(ExMul(offset))
                    case 4:
                        instructions.append(ExXor(offset))
                    case 5:
                        instructions.append(ExEqz(offset))
                    case 6:
                        instructions.append(ExAnd(offset))
                    case 7:
                        instructions.append(ExPop(offset, other))
                    case 8:
                        instructions.append(ExReset(offset))
                offset += 2
            case _:
                print(f'Unknown instruction {opcode:x} @ {offset:x}', file=sys.stderr)
                break

    return instructions


def dump(instructions, labels):
    for opcode in instructions:
        if opcode.addr in labels:
            print(f'{labels[opcode.addr]}:')
        #print(f'{opcode.addr:04x} ', end='')
        match opcode:
            case Halt(addr):
                print('\thalt')
            case MovImm(addr, reg, imm):
                if imm in labels:
                    print(f'\tmov {reg_names[reg]}, {labels[imm]} ; 0x{imm:x}')
                else:
                    print(f'\tmov {reg_names[reg]}, 0x{imm:x}')
            case MovReg(addr, reg1, reg2):
                print(f'\tmov {reg_names[reg1]}, {reg_names[reg2]}')
            case Add(addr, reg1, reg2) | Sub(addr, reg1, reg2) | Mul(addr, reg1, reg2) | Mod(addr, reg1, reg2) | \
                 And(addr, reg1, reg2) | Or(addr, reg1, reg2) | Xor(addr, reg1, reg2) | Shr(addr, reg1, reg2):
                op_index = alu_ops.index(type(opcode))
                alu_op = ('add','sub','mul','mod','and','or','xor', 'shr')[op_index]
                print(f'\t{alu_op} {reg_names[reg1]}, {reg_names[reg2]}')
            case MemStore(addr, reg1, reg2):
                print(f'\tstore mem[{reg_names[reg1]}], {reg_names[reg2]}')
            case MemLoad(addr, reg1, reg2):
                print(f'\tmov {reg_names[reg1]}, mem[{reg_names[reg2]}]')
            case RomLoad(addr, reg1, reg2):
                print(f'\tmov {reg_names[reg1]}, rom[{reg_names[reg2]}]')
            case Jump(addr, target):
                print(f'\tjump {labels[target]}')
                print()
            case JumpReg(addr, reg):
                print(f'\tjump {reg_names[reg]}')
                print()
            case JumpEq(addr, target, reg1, reg2):
                print(f'\tjumpeq {reg_names[reg1]}, {reg_names[reg2]}, {labels[target]}')
                print()
            #case PrintReg(addr, reg):
            #    print(f'\tprintreg {reg_names[reg]}')
            case ExPushReg(addr, reg):
                print(f'\tex.push {reg_names[reg]}')
            case ExPushImm(addr, imm):
                print(f'\tex.push 0x{imm:x}')
            case ExAdd(addr):
                print(f'\tex.add')
            case ExMul(addr):
                print(f'\tex.mul')
            case ExXor(addr):
                print(f'\tex.xor')
            case ExEqz(addr):
                print(f'\tex.eqz')
            case ExAnd(addr):
                print(f'\tex.and')
            case ExPop(addr,reg):
                print(f'\tex.pop {reg_names[reg]}')
            case ExReset(addr):
                print(f'\tex.reset')
            ## Artifical instructions
            case PushImm(addr, imm):
                if imm in labels:
                    print(f'\tpush {labels[imm]} ; 0x{imm:x}')
                else:
                    print(f'\tpush 0x{imm:x}')
            case PushReg(addr, reg):
                print(f'\tpush {reg_names[reg]}')
            case Pop(addr, reg):
                print(f'\tpop {reg_names[reg]}')
            case Call(addr, target):
                print(f'\tcall {labels[target]}')
                print()
            case Ret(addr):
                print(f'\tret')
                print()
            case CallSyscall(addr, target, syscall):
                print(f'\tcall {labels[target]} ; {syscall_names[syscall]}')
                print()
            case _:
                print(f'Unknown instruction {opcode}', file=sys.stderr)
                exit()

def dump_data(start_of_data, data, labels, magic_blocks):
    printable = bytes(string.printable, 'ascii')
    offset = 0
    while offset < len(data):
        byte = data[offset]
        data_offset = start_of_data + offset
        if data_offset in labels:
            print()
            print(f'{labels[data_offset]}:')
        #print(f'{data_offset:04x} ', end='')
        if data_offset in magic_blocks:
            start_of_magic = offset
            while True:
                sub_data = data[offset:offset+8]
                val = u64(sub_data)
                offset += 8
                val ^= 0x676e614765636944
                if val == 0xdeadbeefdeadbeef:
                    print('\t.magicend')
                    break
                key = val >> 0x38
                val = val & 0xffffffffffffff
                if key == 0:
                    print(f'\t.mraw  0x{val:x}')
                elif key == 0x34:
                    print(f'\t.mlibc 0x{val:x} ; {get_libc_rop(val)}')
                elif key == 0x56:
                    print(f'\t.mexe  0x{val:x}')
                else:
                    print(f'\t.munchanged ; offset 0x{(offset - 8 - start_of_magic):x}')
        else:
            if byte > 0x20 and byte in printable:
                print(f'\t.db 0x{byte:x} ; {chr(byte)}')
            else:
                print(f'\t.db 0x{byte:x}')
            offset += 1

def find_labels(instructions, start_of_data, end_of_data):
    labels = {}
    for opcode in instructions:
        match opcode:
            case Jump(target=target):
                labels[target] = f'LAB_{target:x}'
            case JumpEq(target=target):
                labels[target] = f'LAB_{target:x}'
            case MovImm(imm=imm) if imm >= start_of_data and imm < end_of_data:
                labels[imm] = f'DAT_{imm:x}'
            case Call(target=target):
                labels[target] = f'FUNC_{target:x}'
    return labels

def pass_push_pop_inst(instructions):
    idx = 0
    while idx < len(instructions):
        match instructions[idx:]:
            case [MovImm(addr=addr, reg=0, imm=8), Sub(dst=15, src=0), MovImm(reg=0, imm=imm), MemStore(dst=15, src=0), *_]:
                instructions[idx:idx+4] = (PushImm(addr, imm),)
            case [MovImm(addr=addr, reg=0, imm=8), Sub(dst=15, src=0), MemStore(dst=15, src=src), *_]:
                instructions[idx:idx+3] = (PushReg(addr, src),)
            case [MemLoad(addr, dst=dst, src=15), MovImm(reg=0, imm=8), Add(dst=15, src=0), *_]:
                instructions[idx:idx+3] = (Pop(addr, dst),)
        idx += 1

def pass_call_ret_inst(instructions):
    idx = 0
    while idx < len(instructions):
        match instructions[idx:]:
            case [PushImm(addr, imm), Jump(target=target), *_] if imm == instructions[idx+2].addr:
                instructions[idx:idx+2] = (Call(addr, target),)
            case [Pop(addr=addr, reg=1), JumpReg(reg=1), *_]:
                instructions[idx:idx+2] = (Ret(addr),)
        idx += 1

def pass_syscall_inst(instructions):
    total_instructions = len(instructions)
    for idx, instruction in enumerate(instructions):
        match instruction:
            case Call(addr=addr, target=0x2353):
                for prev_inst in reversed(instructions[max(0,idx-10):idx]):
                    match prev_inst:
                        case MovImm(reg=8, imm=imm):
                            instructions[idx] = CallSyscall(addr, 0x2353, imm)
                            break

def identify_magic_blocks(instructions):
    total_instructions = len(instructions)
    idx = 0
    magic_blocks = []
    while idx < len(instructions):
        # Limit to 3 to avoid picking up unexpected instructions in the middle
        match instructions[idx:idx+3]:
            case [*_, MovImm(reg=5, imm=imm), Call(target=0x2667)] | \
                 [MovImm(reg=5, imm=imm), *_, Call(target=0x2667)]:
                magic_blocks.append(imm)
            case [*_, MovImm(reg=4, imm=imm), Call(target=0x2504)]:
                magic_blocks.append(imm)
        idx += 1
    return magic_blocks

def solve(instructions):
    flag = [BitVec('f%d' % i, 8) for i in range(100)]
    def do_op(op, a, b):
        match op:
            case ExAdd():
                return a + b
            case ExMul():
                return a * b
            case ExXor():
                return a ^ b
            case ExAnd():
                return a & b
            case _:
                raise Exception('Unexpected operation')

    ops = []
    idx = 0
    while idx < len(instructions):
        match instructions[idx:idx+24]:
            case [MovImm(imm=a), RomLoad(), MovImm(imm=b), RomLoad(),
                  MovImm(imm=c), RomLoad(), MovImm(imm=d), RomLoad(),
                  ExPushReg(), ExPushReg(),
                  (ExAdd() | ExMul() | ExXor() | ExAnd()) as op0,
                  ExPushImm(imm=r0),
                  (ExAdd() | ExMul() | ExXor() | ExAnd()) as op1,
                  
                  ExPushReg(), ExPushReg(),
                  (ExAdd() | ExMul() | ExXor() | ExAnd()) as op2,
                  ExPushImm(imm=r1),
                  (ExAdd() | ExMul() | ExXor() | ExAnd()) as op3,
                  
                  (ExAdd() | ExMul() | ExXor() | ExAnd()) as op4,
                  ExPushImm(imm=r2),
                  (ExAdd() | ExMul() | ExXor() | ExAnd()) as op5,
                  
                  ExPushImm(imm=expected),
                  ExXor(),
                  ExEqz(),
                  ]:
                
                result1 = do_op(op0, flag[a], flag[b])
                result1 = do_op(op1, result1, r0)
                result2 = do_op(op2, flag[c], flag[d])
                result2 = do_op(op3, result2, r1)
                result = do_op(op4, result1, result2)
                result = do_op(op5, result, r2)
                
                ops.append(result == expected)

        idx += 1
    s = Solver()
    s.add(z3.And(ops))
    assert s.check() == sat
    m = s.model()
    print(bytes([m[x].as_long() for x in flag if m[x] != None]), file=sys.stderr)

def main():
    buffer = open(sys.argv[1], 'rb').read()
    start_of_data = 0x27f3
    instructions  = parse(buffer[:start_of_data])
    pass_push_pop_inst(instructions)
    pass_call_ret_inst(instructions)
    pass_syscall_inst(instructions)
    magic_blocks = identify_magic_blocks(instructions)
    labels = find_labels(instructions, start_of_data, len(buffer))

    labels[0x2584] = 'init'
    labels[0x276d] = 'init_set_stack'
    labels[0x2667] = 'magic_copy'
    labels[0x27f3] = 'ROP_continue_loop'
    labels[0x2504] = 'execute_rop'
    labels[0x2353] = 'syscall'
    labels[0x287b] = 'ROP_syscall'
    labels[0x19e] = 'child_program'
    labels[0x126] = 'parent_program'
    labels[0x2093] = 'close_ptr'
    labels[0x20da] = 'close'
    labels[0x223d] = 'init_seccomp'
    labels[0x1dbd] = 'parent_program_cont'
    labels[0x23cb] = 'read_ptr'
    labels[0x2953] = 'ROP_read_ptr'
    labels[0x2417] = 'write_ptr'
    labels[0x299b] = 'ROP_write_ptr'
    labels[0x29d3] = 'DAT_seccomp'
    labels[0x2bf6] = 'str_flag'
    labels[0x2bfc] = 'str_checking'
    labels[0x2463] = 'write_stdout'
    labels[0x1e34] = 'get_flag'
    labels[0x2085] = 'exit_parent'
    labels[0x2c08] = 'str_wrong'
    labels[0x2c0f] = 'str_correct'
    labels[0x375] = 'child_program_cont'
    labels[0x247] = 'patch_printreg'
    labels[0x2112] = 'memcpy_qword'
    labels[0x40b] = 'child_loop'
    labels[0x557] = 'check_flag'

    dump(instructions, labels)
    dump_data(start_of_data, buffer[start_of_data:], labels, magic_blocks)
    solve(instructions)

main()