# DiceCTF 2022: Breach Writeup by Reductor

Unfortunately during the CTF I didn't manage to solve the challenge, however got very far and finished solving it the day after the challenge had closed.

## Examining the package

Inside the zip file there is an 'out' folder which contains all the relevant files

 * `breach` - The executable
 * `breach.bin` - The VM byte code (discussed later)
 * `Dockerfile` - A Dockerfile to establish an environment to run
 * `build.sh` - A script to build the docker image
 * `run.sh` - A script to run the built docker image

Looking at the docker file we can see the following
```docker
FROM ubuntu:20.04

COPY breach /app/breach
COPY breach.bin /app/breach.bin

RUN echo "PWN_FLAG" > /app/flag.txt

CMD /app/breach /app/breach.bin
```

From this we can determine that `breach` will run with the `breach.bin` specified as an argument and additionally there is a `flag.txt` which will be stored next to the application.

## Looking at the breach binary

Let's open up the `breach` binary in [Ghidra](https://ghidra-sre.org/) to better analyze what it's doing when it gets run

The first thing to do is finding the `main` function which is often done by looking at the `entry` point and finding the call to `__libc_start_main` the first argument passed to this function is `main`

```cpp
void entry(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  undefined8 in_stack_00000000;
  undefined auStack8 [8];
  
  __libc_start_main(FUN_00101229,in_stack_00000000,&stack0x00000008,FUN_00101960,FUN_001019d0,
                    param_3,auStack8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```

Now that we know `FUN_00101229` is `main` let's take a look at it and change the name and signature of the function to have the correct arguments as it's fairly well known, and start looking at it

```cpp
__stream = fopen(argv[1],"rb");
fseek(__stream,0,2);
__size = ftell(__stream);
fseek(__stream,0,0);
DAT_001140e0 = malloc(__size);
fread(DAT_001140e0,1,__size,__stream);
```

From this code we can see that the byte code file gets read into `DAT_001140e0` so I'll rename it appropriately to `bytecode` (`rom` is another alternative to be considered) to better indicate that it contains the bytecode.

```cpp
lVar3 = DAT_00104040;
while (DAT_00104040 = lVar3, DAT_00104048 == '\0') {
    bVar4 = *(byte *)(DAT_00104040 + (long)bytecode) & 0xf;
    switch(bVar4) {
    case 0:
    DAT_00104048 = '\x01';
    lVar3 = DAT_00104040 + 1;
    break;
    ...
    default:
    printf("Unknown instruction: %d\n",(ulong)bVar4);
                /* WARNING: Subroutine does not return */
    exit(-1);
    }
}
```

From this code we can determine that `lVar3` and `DAT_00104040` both seem to indicate some sort of offset in the byte code to an instruction so let's rename them to `inst_offset` and `inst_offset`, they are likely independent variables because one is the value in a register and the other is the value in memory.

Looking at `bVar` it looks to be using the lower 4 bytes (nibble) of the byte code as the instruction, so let's rename it to `instruction` and also let's give a type to `bytecode` as a `byte*` so the code becomes a little easier to read.

The while loop appears to continue until `DAT_00104048` gets set to `1` so let's rename this to `should_halt` and make it a `bool` variable as it looks like it only stores `0` and `1`.

The next bit of useful information can be seen in the handling of instruction 10

```cpp
case 10:
printf("r%d = 0x%lx\n",(ulong)(bytecode[inst_offset + 1] & 0xf),
        *(undefined8 *)
        (&DAT_00114060 + (long)(int)(uint)(bytecode[inst_offset + 1] & 0xf) * 8));
inst_offet2 = inst_offset + 2;
```

From this and a bit of knowledge about VMs we can determine that there is likely registers in this VM implementation which are called (`r0` - `r15` -- 15 is the max because of the nibble) they get stored in the `DAT_00114060` variable which is an array of `long`'s meaning that these are 64-bit registers so let's change `DAT_00114060` to be an array of `long[16]` and give it the name `registers`.

Looking through the rest of the instructions the other bit of data that is missing and unnamed is `DAT_00104060` so let's take a look at the usages of it within the VM instruction loop.

```cpp
case 4:
    *(long *)(&DAT_00104060 + registers[(int)(uint)(bytecode[inst_offset + 1] & 0xf)]) =
            registers[(int)(uint)(bytecode[inst_offset + 1] >> 4)];
    inst_offet2 = inst_offset + 2;
    break;
case 5:
    registers[(int)(uint)(bytecode[inst_offset + 1] >> 4)] =
            *(long *)(&DAT_00104060 + registers[(int)(uint)(bytecode[inst_offset + 1] & 0xf)]);
    inst_offet2 = inst_offset + 2;
    break;
```

So it looks like there are two instructions which use this data instruction `4` which stores into the memory at the address of one register from the value of another register and instruction `5` which does the opposite of loading from this memory, while they both appear to be writing `long`'s the offset's appear to be in bytes, this is likely the memory for the VM to work with so let's rename `DAT_00104060` to `mem` and turn it into a `byte` array as this is completely unbounded in checks we can't determine the size so I just use the maximum Ghidra suggests before it overwrites the next symbol (the registers) which is `65536` (`0x10000`).

I won't bore you with going into every individual instruction now that we have established the core parts of the VM (some VMs also have an inbuilt stack but this one doesn't _appear_ to), here is a summary of all the instructions and the operands.

| Opcode | Instruction | Notes |
| ------ | -------- | ----- |
| 0 | `halt` | Stop the VM |
| 1 | `mov src, imm` | `imm` is an 8-byte immediate value |
| 2 | `mov dst, src` | |
| 3 | `aluop dst, src` | `aluop` is based on the other nibble in the instruction and can be `+`,`-`,`*`,`%`,`&`,`|`,`^` and `>>` |
| 4 | `mov mem[dst], src` | This is an 8-byte read |
| 5 | `mov dst, mem[src]` | This is an 8-byte read |
| 6 | `mov dst, rom[src]` | This is an 8-byte read, I use  `rom` here instead of `bytecode` as no other opcode changes these |
| 7 | `jmp imm` | |
| 8 | `jmp reg` | |
| 9 | `jeq reg1, reg2, imm` | If `reg1` and `reg2` are both equal then it will jump to `imm` |
| 10 | `print reg` | This will print the register |

Now that we know all the instructions you might notice something, when we execute the program it appears to print `Flag:` and takes input from the user, but none of these instructions appear to do anything related to this.

## Writing a disassembler

Now that we know the instructions, it's time to start writing something to disassemble the binary, there are few things which we might want to look out for when writing this disassembler

 * Not all of the bytes might be instructions
 * The instruction size isn't fixed so we can't assume we can start at a random place, we need a known start place (we know atleast 0 is an instruction)
 * Instructions might have data or intentionally illegal instructions interleaved to make disassembling harder
 * The instructions might get modified at runtime using things like the `mov mem[dst], src` instruction as `dst` is completely unbounded

While these are all things to be aware of and watch out for I often find it's best to start with the simpliest implementation first of just assume everything is an instruction from the beginning of the file to the end and hope we get lucky.

I'm going to make use of python for doing this so the first thing I'll is establish some types for the instructions, this will make it easier if I want to do matching on them later

```py
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
```

Now that we have the instructions we need to parse the opcodes to turn them into these types

NOTE: I'm using the new `match` functionality in Python 3.10 fairly heavily in the solution to this CTF Challenge, as I wanted to try it, and now that I have I don't think I can live without it (hopefully once seeing how helpful it is you feel the same).

```py
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
                other = buffer[offset+1] & 0xf
                instructions.append(PrintReg(offset, other))
                offset += 2
            case _:
                print(f'Unknown instruction {opcode:x} @ 0x{offset:x}', file=sys.stderr)
                break

    return instructions
```

We also need something to now dump those instructions, while we could rely on python's `repr` it's not as intuitive to read (atleast for someone more familair with looking at typical (dis)assembler output)

```py
def dump(instructions):
    for opcode in instructions:
        print(f'{opcode.addr:04x} ', end='')
        match opcode:
            case Halt(addr):
                print('\thalt')
            case MovImm(addr, reg, imm):
                print(f'\tmov r{reg}, 0x{imm:x}')
            case MovReg(addr, reg1, reg2):
                print(f'\tmov r{reg1}, r{reg2}')
            case Add(addr, reg1, reg2) | Sub(addr, reg1, reg2) | Mul(addr, reg1, reg2) | Mod(addr, reg1, reg2) | \
                 And(addr, reg1, reg2) | Or(addr, reg1, reg2) | Xor(addr, reg1, reg2) | Shr(addr, reg1, reg2):
                op_index = alu_ops.index(type(opcode))
                alu_op = ('add','sub','mul','mod','and','or','xor', 'shr')[op_index]
                print(f'\t{alu_op} r{reg1}, r{reg2}')
            case MemStore(addr, reg1, reg2):
                print(f'\tstore mem[r{reg1}], r{reg2}')
            case MemLoad(addr, reg1, reg2):
                print(f'\tmov r{reg1}, mem[r{reg2}]')
            case RomLoad(addr, reg1, reg2):
                print(f'\tmov r{reg1}, rom[r{reg2}]')
            case Jump(addr, target):
                print(f'\tjump 0x{target:x}')
                print()
            case JumpReg(addr, reg):
                print(f'\tjump r{reg}')
                print()
            case JumpEq(addr, target, reg1, reg2):
                print(f'\tjumpeq r{reg1}, r{reg2}, 0x{target:x}')
                print()
            case PrintReg(addr, reg):
                print(f'\tprintreg r{reg}')
            case _:
                print(f'Unknown instruction {opcode}', file=sys.stderr)
                exit()
```

You'll notice that I include extra lines after anything that jumps this is to make it more easy to see where the instruction pointer might not keep going.

Finally we have a main function
```py
def main():
    buffer = open(sys.argv[1], 'rb').read()
    instructions  = parse(buffer)
    dump(instructions)

main()
```

Now if we run this what do we get
```
$ .\disassemble.py breach.bin >output.asm
Unknown instruction e @ 0x2809
```

Damn, we couldn't get through the whole file but we managed to get to 0x2809 which is a lot considering that for each instruction if it was over 10 for the opcode it would have failed, doing a quick pass over the file it looks like most of it looks like sensile bytecode you would expect to see, except for a few things:

* The instructions at the end from `0x27f3` onwards don't look right (maye this is the start of some data)
* The giant block of `printreg`'s seem pretty strange, we haven't seen any output of these, maybe they happen when we get the right flag answer

So for now let's do some changes to just turn from `0x27f3` onwards into data bytes in the disassembly output, it could include bytecodes but it's also a fairly known pattern for a VM (and non-VM) to have code at the start then data at the end of the file.

The other thing we can do is look at this a hexdump we might see a bit of a change in pattern between the instructions and the suspected data.

```
000027b0  03 0f 18 a1 a8 7f 00 00  00 00 00 00 02 20 11 5a  |............. .Z|
000027c0  2b 03 00 00 00 00 00 03  10 04 0a 01 08 00 00 00  |+...............|
000027d0  00 00 00 00 03 0a 02 3b  01 60 c0 00 00 00 00 00  |.......;.`......|
000027e0  00 03 0b 04 ba 05 1f 01  08 00 00 00 00 00 00 00  |................|
000027f0  03 0f 18 14 cc 67 65 47  61 6e 53 7f 70 63 65 47  |.....geGanS.pceG|
                ^^ 0x27f3 start
00002800  61 6e 31 36 02 61 65 47  61 6e 53 0c 29 63 65 47  |an16.aeGanS.)ceG|
00002810  61 6e 31 66 91 6a 65 47  61 6e 53 44 69 63 65 47  |an1f.jeGanSDiceG|
00002820  61 6e 67 12 c9 68 65 47  61 6e 53 36 02 61 65 47  |ang..heGanS6.aeG|
```

Looking at this, it seems like a fairly nice cut for data and instructions, in-fact if you search the disassembly output for `0x27f3` you'll see things mentioning that same address.

So let's go with a very naive implementation of dumping data from that address onwards.

```py
def dump_data(start_of_data, data):
    printable = bytes(string.printable, 'ascii')
    for data_offset, byte in enumerate(data, start_of_data):
        print(f'{data_offset:04x} ', end='')
        if byte in printable:
            print(f'\t.db 0x{byte:x} ; {chr(byte)}')
        else:
            print(f'\t.db 0x{byte:x}')

def main():
    buffer = open(sys.argv[1], 'rb').read()
    start_of_data = 0x27f3
    instructions  = parse(buffer[:start_of_data])
    dump(instructions)
    dump_data(start_of_data, buffer[start_of_data:])
```

Now let's see how that output looks towards the end of the file.

```
27e5 	mov r1, mem[r15]
27e7 	mov r0, 0x8
27f0 	add r15, r0
27f2 	jump r1

27f3 	.db 0x14
27f4 	.db 0xcc
27f5 	.db 0x67 ; g
27f6 	.db 0x65 ; e
27f7 	.db 0x47 ; G
```

### Adding some labels
Starting to look a lot nicer, we now have something fairly smooth to work with, let's establish some labels to make things a little nicer to read.

```py
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
    return labels
```

Now we need to include them in our output

```py
def dump(instructions, labels):
    for opcode in instructions:
        if opcode.addr in labels:
            print(f'{labels[opcode.addr]}:')
        #print(f'{opcode.addr:04x} ', end='')
        match opcode:
        ...
            case MovImm(addr, reg, imm):
                if imm in labels:
                    print(f'\tmov r{reg}, {labels[imm]} ; 0x{imm:x}')
                else:
                    print(f'\tmov r{reg}, 0x{imm:x}')
            ...
            case Jump(addr, target):
                print(f'\tjump {labels[target]}')
                print()
            ...
            case JumpEq(addr, target, reg1, reg2):
                print(f'\tjumpeq r{reg1}, r{reg2}, {labels[target]}')
                print()
            ...
```

```py
def dump_data(start_of_data, data, labels):
    printable = bytes(string.printable, 'ascii')
    for data_offset, byte in enumerate(data, start_of_data):
        if data_offset in labels:
            print(f'{labels[data_offset]}:')
        #print(f'{data_offset:04x} ', end='')
        ...
```

Now things are really starting to look nice to read and work with
```asm
LAB_2054:
	mov r8, DAT_2c0f ; 0x2c0f
	mov r9, 0x2c18
	mov r0, 0x8
	sub r15, r0
	mov r0, LAB_2085 ; 0x2085
	store mem[r15], r0
	jump LAB_2463
```

Also doing a quick santiy check of all things within the data section to ensure there is no `LAB` or `FUNC` label's meaning we have potential byte code inside where we've assumed it's only data, we don't so this is a good thing, it's reinforcing the earlier assumption.

### Finding the stack pointer

Now if your looking around the code enough you'll start to spot a few patterns, the easy one to spot is what appears to be a stack happening with what register `r15` points to (starts at `0x10000` right at the start)

Doing a bit of a search of the disassembler output for `r15` appears to reiterate this with the common patterns being

<table>
<tr>
<th>Push immediate:</th>
<th>Push register:</th>
<th>Pop</th>
</tr>
<tr>
<td>
<pre>
mov r0, 0x8
sub r15, r0
mov r0, 0x28
store mem[r15], r0
</pre>
</td><td>
<pre>
mov r0, 0x8
sub r15, r0
store mem[r15], r11
</pre>
</td><td>
<pre>
mov r1, mem[r15]
mov r0, 0x8
add r15, r0
<pre>
</td>
</tr>
</table>

You might also notice that these also often get combined with a `jump` instruction we probably means they are a `call`/`ret` pair, let's add some artifical instructions so we can remove this noise and make it easier to read, we'll start with handling the `push` and `pop`

```py
# Artifical instructions
PushImm = namedtuple('PushImm', ['addr', 'imm'])
PushReg = namedtuple('PushReg', ['addr', 'reg'])
Pop = namedtuple('Pop', ['addr', 'reg'])
```

```py
def dump(instructions, labels):
    for opcode in instructions:
        ....
        match opcode:
            ....
            ## Artifical instructions
            case PushImm(addr, imm):
                if imm in labels:
                    print(f'\tpush {labels[imm]} ; 0x{imm:x}')
                else:
                    print(f'\tpush 0x{imm:x}')
            case PushReg(addr, reg):
                print(f'\tpush r{reg}')
            case Pop(addr, reg):
                print(f'\tpop r{reg}')
            case _:
            ...
```

Now we build a matcher to do a pass and create these instructions

```py
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
```

```py
def main():
    ...
    instructions  = parse(buffer[:start_of_data])
    pass_push_pop_inst(instructions)
    ...
```

__NOTE:__ Doing these passes which consolidate instructions the intermediate registers (e.g. `r0`) are also changed so if your reading the assembly output you also need to assume the have changed `r0` too (looking at the output `r0` seems to be a random temporary register which always gets changed)

Now that we have this it starts to look a lot nicer

```
	push LAB_59 ; 0x59
	jump LAB_2353

LAB_59:
	push 0x78
	jump LAB_2584
```

```
	pop r1
	jump r1
```

### Adding call/ret artifical instructions

Now let's build a pass which will create some `Call` and `Ret` instructions to make these even better.

```py
Call = namedtuple('Call', ['addr', 'target'])
Ret = namedtuple('Ret', ['addr'])
```

```py
def dump(instructions, labels):
...
            case Call(addr, target):
                print(f'\tcall {labels[target]}')
                print()
            case Ret(addr):
                print(f'\tret')
                print()
```

As the `Jump` is about to change with these we need to also add `Call` to the `find_labels`

```py
def find_labels(instructions, start_of_data, end_of_data):
    labels = {}
    for opcode in instructions:
        match opcode:
            ...
            case Call(target=target):
                labels[target] = f'FUNC_{target:x}'
    return labels
```

Then we finally we build a pass which goes over it

```py
def pass_call_ret_inst(instructions):
    idx = 0
    while idx < len(instructions):
        match instructions[idx:]:
            case [PushImm(addr, imm), Jump(target=target), *_] if imm == instructions[idx+2].addr:
                instructions[idx:idx+2] = (Call(addr, target),)
            case [Pop(addr=addr, reg=1), JumpReg(reg=1), *_]:
                instructions[idx:idx+2] = (Ret(addr),)
        idx += 1
```

This needs to run after the `push`/`pop` pass as it depends on it

```py
    pass_push_pop_inst(instructions)
    pass_call_ret_inst(instructions)
```

Now let's see how this compares
<table>
<tr>
<th>Original</th>
<th>With push/pop</th>
<th>With call/ret</th>
</tr>
<tr>
<td>
<pre>
mov r0, 0x8
sub r15, r0
mov r0, LAB_59 ; 0x59
store mem[r15], r0
jump LAB_2353
</pre>
</td><td>
<pre>
push LAB_59 ; 0x59
jump LAB_2353
</pre>
</td><td>
<pre>
call FUNC_2353
</pre>
</td>
</tr>
<tr>
<td>
<pre>
mov r1, mem[r15]
mov r0, 0x8
add r15, r0
jump r1
</pre>
</td><td>
<pre>
pop r1
jump r1
</pre>
</td><td>
<pre>ret</pre>
</td>
</tr>
</table>

See how much better it is? Did I tell you matchers in Python are awesome?

## Understanding the disassembly

Now have the code in a much more easy to understand format, let's start digging into the program and how it works.

From the entry point immediately after the stack get's setup then `FUNC_59` get's called which right at the start calls `FUNC_2584`, which is the first big juicy function that we'll be looking at.

Here is the code for it, I've added the disassasmbly here and some comments

```c
FUNC_2584:
    // Get the stdin pointer by reading the address at mem[-0x30]
    mov r2, 0x30
    mov r3, 0x0
    sub r3, r2
    mov r2, mem[r3]

    // Get the libc base address by subtracting 0x1eb980 from stdin (_IO_2_1_stdin_ in libc)
    mov r0, 0x1eb980
    sub r2, r0

    // Get the address where the environ pointer (stack pointer) is stored by adding 0x1ef2e0 to the base 
    mov r0, 0x1ef2e0
    mov r3, r2
    add r3, r0

    // Get the wide_pointer buffer pointer from memory allocated by the file pointer by looking at rom[-0x1150]
    mov r0, 0x1150
    mov r1, 0x0
    sub r1, r0
    mov r4, rom[r1]

    // Get a pointer to the 'rom' calculated based on the wide_pointer
    // This is an important pointer as now it can be used with any calcutions to get an absolute address relative to the rom
    mov r0, 0x1100
    add r4, r0

    // Get the value stored in the 'environ' pointer (the stack abse pointer)
    mov r0, r3
    sub r0, r4
    mov r5, rom[r0]

    // Get the address of 'main' by reading from environ/stackbase-0xe8
    mov r0, 0xe8
    mov r6, r5
    sub r6, r0
    mov r0, r6
    sub r0, r4
    mov r6, rom[r0]

    // Get the base address of 'breach' by subtracting the address of main (0x1229)
    mov r0, 0x1229
    sub r6, r0

    // r7 = stackbase-0x108 (the pointer of return __libc_start_main from main)
    mov r7, r5
    mov r0, 0x108
    sub r7, r0

    // r3 = breach base address
    // r4 = stack pointer for returning from `main`
    mov r3, r6
    mov r4, r7
    call FUNC_276d

	mov r4, 0x8000
	mov r5, DAT_27f3 ; 0x27f3
	call FUNC_2667

	halt
	ret
```

From this function we can tell that it's calculated a bunch of offsets to get the base address of libc and breach along, this is likely initialization code now we have two final functions to look at within `FUNC_2584` which are `FUNC_276d` and `FUNC_2667` then it finally `halt`'s and returns, because it's got addresses which could be used for building a ROP chain you might already suspect that `halt` is going to be used to execute a ROP chain.

Let's dig into `FUNC_276d` now
```cpp
// r2 = libc base address
// r3 = breach base address
// r4 = stack pointer for returning from 'main' (ROP pointer)
FUNC_276d:
    // Get the address of the stack ROP pointer relative to 'mem' (base+0x4060)
	mov r9, r4
	sub r9, r3
	mov r0, 0x4060
	sub r9, r0

    // Store the address of a 'pop rsp' gadget from libc in the return from main address
	mov r0, r2
	mov r1, 0x32b5a
	add r0, r1
	store mem[r9], r0

    // Shift the address it was stored at by 8 (the next pointer)
	mov r0, 0x8
	add r9, r0

    // Store a pointer to &mem[0x8000] (exe base + 0xc060)
	mov r10, r3
	mov r0, 0xc060
	add r10, r0
	store mem[r9], r10
	ret
```

Overall this function modifies the stack where the return from `main` occurs and changes it so that it does the ROP `pop rsp; exe+0xc060` meaning that the stack pointer will now be pointing to `mem[0x8000]`, this likely allows more easy building of ROP chains as it's just a write to `mem` without doing these same offset calculations.

Now let's look at `FUNC_2667`, it's a bit more of a monster (it also get's called in a few places so gives us more benefits then the other two we just looked at which just get called once)

```cpp
// r2 = libc base address
// r3 = breach base address
// r4 = Some destination memory location
// r5 = Some source data address
FUNC_2667:
    // self explainitory -- we pop this before the ret also
	push r6
	push r7

LAB_2681:
    // Read from the source address and xor the value by 0x676e614765636944
	mov r0, rom[r5]
	mov r1, 0x676e614765636944
	xor r0, r1

    // If the value is equal to 0xdeadbeefdeadbeef then return (exit loop)
	mov r1, 0xdeadbeefdeadbeef
	jumpeq r0, r1, LAB_2745

    // r6 = The lower 7 bytes of the value (0x00ffffffffffffff)
    // r7 = The higher byte of the value (0xff00000000000000)
	mov r6, r0
	mov r7, r0
	mov r0, 0xffffffffffffff
	and r6, r0
	mov r0, 0x38
	shr r7, r0

    // If the higher byte is 0 then goto LAB_26fd
	mov r0, 0x0
	jumpeq r7, r0, LAB_26fd

    // If the higher byte is 0x34 then goto LAB_2708
	mov r0, 0x34
	jumpeq r7, r0, LAB_2708

    // If the higher byte is 0x56 then goto LAB_2717
	mov r0, 0x56
	jumpeq r7, r0, LAB_2717

    // else continue looping
	jump LAB_2726

LAB_26fd:
    // Store the value (lower 7 bytes) in r4
	store mem[r4], r6
	jump LAB_2726

LAB_2708:
    // Store (value+libc base) in r4
	mov r0, r2
	add r0, r6
	store mem[r4], r0
	jump LAB_2726

LAB_2717:
    // Store (value+exe base) in r4
	mov r0, r3
	add r0, r6
	store mem[r4], r0
	jump LAB_2726

LAB_2726:
    // Increment r5 and r4 to keep moving down the array
	mov r0, 0x8
	add r5, r0
	mov r0, 0x8
	add r4, r0
	jump LAB_2681

LAB_2745:
	pop r7
	pop r6
	ret
```

This function is a bit of a magic copy function it copies data from `rom+r5` into `mem+r5` until it hits an end marker and depending on the data will either convert it into something which is relative to the libc or the executable's base address. (A nice handy tool for storing ROP chains)

So looking back at the end of `FUNC_2584` we can add some more comments
```cpp
FUNC_2584:
    ...
    // Setup ROP for moving stack to &mem[0x8000]
    mov r3, r6
    mov r4, r7
    call FUNC_276d

    // Copy a rop chain DAT_27f3 into &mem[0x8000]
	mov r4, 0x8000
	mov r5, DAT_27f3 ; 0x27f3
	call FUNC_2667

	halt
	ret
```

Unfortunately if we look at `DAT_27f3` it isn't very useful to understand

```c
DAT_27f3:
	.db 0x14
	.db 0xcc
	.db 0x67 ; g
	.db 0x65 ; e
	.db 0x47 ; G
	.db 0x61 ; a
	.db 0x6e ; n
...
```

Now let's modify the disassembler so that we can more easily determine what these ROP chains.

### Adding ROP chain dumping to the disassembler

The first thing we need to do is identify what blocks might be magic copies, to this we will just look for things which call `FUNC_2667` and extract the `r5` value

```py
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
        idx += 1
    return magic_blocks
```

Now we need to rework our `dump_data` to work with these new magic dumps

```py
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
                    print(f'\t.mlibc 0x{val:x}')
                elif key == 0x56:
                    print(f'\t.mexe  0x{val:x}')
                else:
                    print(f'\t.munchanged ; offset 0x{(offset - 8 - start_of_magic):x}')
        else:
            if byte in printable:
                print(f'\t.db 0x{byte:x} ; {chr(byte)}')
            else:
                print(f'\t.db 0x{byte:x}')
            offset += 1
```

Which gives us a nice output now showing which things are from libc and from the executable
```
DAT_27f3:
	.mlibc 0x4a550
	.mexe  0x193b
	.mlibc 0x26b72
	.mexe  0x4048
	.mlibc 0x9f822
	.mraw  0x0
...
	.mexe  0xc060
	.magicend
```

It looks like we only have one lot of data resolved using this, so let's look at the calls to `FUNC_2667` a little more and it looks like we have covered the calls which use `DAT_27f3` however `FUNC_2504` which uses the `r4` argument as the source is not covered, so let's modify the discovery algorithm for magic copy's to include it as a source.

```py
def identify_magic_blocks(instructions):
    ...
            case [*_, MovImm(reg=4, imm=imm), Call(target=0x2504)]:
                magic_blocks.append(imm)
```

#### Getting ROP gadget instructions

But you know what would be nice? Knowing what these gadgets are, I'll just be grabbing the libc one's for this, if your doing this yourself feel free to do the same for the executable but I found they weren't necessary.

So in order to this we need a way to lookup the gadget at the specified address, I could do this at runtime using pwntools's `ROP` and `raw` however I pick a slightly more efficient and use `ROPgadget` to dump all gadgets then find them when I need them, so first let's dump the gadgets

```
ROPgadget --all  --binary libc-2.31.so > libc-rops.txt
```

And we can look them up in python

```py
def get_libc_rop(addr):
    addr_as_str = f'0x{addr:016x}'
    # Built with: ROPgadget --all --binary breach > libc-rops.txt
    with open('libc-rops.txt') as rop_file:
        for line in rop_file:
            if line.startswith(addr_as_str):
                return line[len(addr_as_str)+3:].strip()
    return ''
```

Then finally we call this function when output `.mlibc`
```py
def dump_data(start_of_data, data, labels, magic_blocks):
    ...
                elif key == 0x34:
                    print(f'\t.mlibc 0x{val:x} ; {get_libc_rop(val)}')
```

Now these dumps look much better to understand the ROP chains
```
DAT_299b:
	.mlibc 0x162866 ; pop rdx ; pop rbx ; ret
	.munchanged ; offset 0x8
	.munchanged ; offset 0x10
	.mlibc 0x26b72 ; pop rdi ; ret
	.munchanged ; offset 0x20
	.mlibc 0x4514d ; mov qword ptr [rdi], rdx ; ret
	.magicend
```

### Looking back at the initialization ROP
Let's go back and look at that ROP which was setup prior to the first `halt` expected to be after the stack first relocates to `&mem[0x8000]`, I have added comments to make it easier to understand

```cpp
DAT_27f3:
	.mlibc 0x4a550 ; pop rax ; ret
	.mexe  0x193b // continuation of instruction pointer loop
	.mlibc 0x26b72 ; pop rdi ; ret
	.mexe  0x4048 // The address of 'should_halt'
	.mlibc 0x9f822 ; pop rcx ; ret
	.mraw  0x0
    // Set 'should_halt' to false
	.mlibc 0xba056 ; mov qword ptr [rdi], rcx ; ret
	.mlibc 0x26b72 ; pop rdi ; ret
	.mexe  0xc060 // &mem[0x8000]
	.mlibc 0x9f822 ; pop rcx ; ret
	.mlibc 0x270b1 ; call rax
    // Set mem[0x8000] to 'call rax; ret' gadget
    // rax is continuation of the instruction pointer loop
	.mlibc 0xba056 ; mov qword ptr [rdi], rcx ; ret
    // Set the base pointer to &mem[0x7FA0]
	.mlibc 0x256c0 ; pop rbp ; ret
	.mexe  0xc000 // &mem[0x7FA0]
    // Set the stack pointer to &mem[0x8000]
	.mlibc 0x32b5a ; pop rsp ; ret
	.mexe  0xc060 // &mem[0x8000]
	.magicend
```

To simplify this it sets `should_halt` back to false (remember this is after a `halt`), and changes the stack so that it's pointing to `mem[0x8000]` and ready's it to continue the loop, meaning this will just keep the loop going after the `halt`.

If you look at `FUNC_2504` you can see this actually get's used with other ROP chains which likely do the actual work.

```
FUNC_2504:
	mov r5, r4
	mov r4, 0x8000
	call FUNC_2667

	mov r5, DAT_27f3 ; 0x27f3
	call FUNC_2667

	call FUNC_27b3

	halt
	ret
```

### Register naming

Earlier we established that `r15` was a stack pointer, and pretty much eliminated it completely aside from initialization.

However there are two other registers which appear to have a global meaning after initialization these are `r2` which is the libc base address and `r3` which is the executable base address, you can verify this by searching all the code for the usages of these registers and find they only ever get read after initialization.

So let's rename these variables that we know to `rexe`, `rlibc` and `rsp` which should make some of the disassembly even easier to read, without having to think about their hidden meaning.

```py
reg_names = ('r0', 'r1', 'rlibc', 'rexe', 'r4', 'r5', 'r6', 'r7', 'r8',
             'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'rsp')
```

I won't show the entire change of the `dump` function, this write-up is already way too long, but the general change is that outputs of registers now look like

```py
print(f'\tmov {reg_names[reg1]}, {reg_names[reg2]}')
```

Now if we look at the result, you can see how easy it is to identify what's an offset with the executable or libc
<table>
<tr>
<th>Before</th>
<th>After</th>
</tr>
<tr>
<td>
<pre>
mov r9, r3
mov r0, 0x6060
add r9, r0
</pre>
</td>
<td>
<pre>
mov r9, rexe
mov r0, 0x6060
add r9, r0
</pre>
</td>
</tr>
</table>

### Naming what was learnt so far

This is already turning into a fairly big project, so let's update our labels with some names for existing functions and data that we know about

```
labels[0x2584] = 'init'
labels[0x276d] = 'init_set_stack'
labels[0x2667] = 'magic_copy'
labels[0x27f3] = 'ROP_continue_loop'
labels[0x2504] = 'execute_rop'
```

### Finding the syscall

Let's continue on from just after `init` and you will see the following call

```
	mov r8, 0x16
	mov r9, rexe
	mov r0, 0x6060
	add r9, r0
	call FUNC_2353
```

Let's dig into `FUNC_2353` (this get's called 18 times so understanding it will solve a lot of things)

```
FUNC_2353:
	mov r0, 0x8008
	store mem[r0], r12
	mov r0, 0x8018
	store mem[r0], r13
	mov r0, 0x8050
	store mem[r0], r8
	mov r0, 0x8060
	store mem[r0], r9
	mov r0, 0x8070
	store mem[r0], r10
	mov r0, 0x8080
	store mem[r0], r11
	mov r4, DAT_287b ; 0x287b
	call execute_rop

	ret
```

It looks like this uses the ROP `DAT_287b` and fills a bunch of things with regiters `r8`-`r13`, remember `execute_rop` stores the ROP at `0x8000` so these are offsets with `DAT_287b`, so let's take a look at this ROP

```c
DAT_287b:
	.mlibc 0x1056fd ; pop rdx ; pop rcx ; pop rbx ; ret
	.munchanged ; offset 0x8 // r12
	.munchanged ; offset 0x10
	.munchanged ; offset 0x18 // r13
	.mlibc 0x4a550 ; pop rax ; ret
	.mlibc 0x25679 ; ret
	.mlibc 0x7b0cb ; mov r10, rdx ; jmp rax
	.mlibc 0x11fdaa ; mov r8, rbx ; mov rax, r8 ; pop rbx ; ret
	.munchanged ; offset 0x40
	.mlibc 0x4a550 ; pop rax ; ret
	.munchanged ; offset 0x50 // r8
	.mlibc 0x26b72 ; pop rdi ; ret
	.munchanged ; offset 0x60 // r9
	.mlibc 0x27529 ; pop rsi ; ret
	.munchanged ; offset 0x70 // r10
	.mlibc 0x1056fd ; pop rdx ; pop rcx ; pop rbx ; ret
	.munchanged ; offset 0x80 // r11
	.munchanged ; offset 0x88
	.munchanged ; offset 0x90
    // (x86) = (VM)
    // rax = r8
    // rdi = r9
    // rsi = r10
    // rdx = r11
    // r10 = r12
    // r8 = r13
	.mlibc 0x66229 ; syscall
	.mlibc 0x331ff ; pop rbx ; ret
	.mexe  0x140a0 // &registers[8]
    // Set VM's r8 to the result of the syscall
	.mlibc 0x162d94 ; mov qword ptr [rbx], rax ; pop rax ; pop rdx ; pop rbx ; ret
	.mraw  0x0
	.mraw  0x0
	.mraw  0x0
	.magicend
````

From all of this we can now label this function and data

```py
labels[0x2353] = 'syscall'
labels[0x287b] = 'ROP_syscall'
```

But considering there are 18 of these calls, we can probably solve a bunch of time with adding a comment for each call to `syscall` with the name of the system call.

The first thing we need to do is build a dictionary which turns the 'rax' register into the syscall name

```py
syscall_names = dict([(
                int(getattr(constants.linux.amd64,v)),v) 
                for v in dir(constants.linux.amd64) if v.startswith('SYS_')
                ])
```

We'll also make use an artifical instruction again

```py
CallSyscall = namedtuple('CallSyscall', ['addr', 'target', 'syscall'])
```

Then finally the pass, first we find a call then look back through the last 10 instructions in reverse for an immediate move into `r8` (not perfect but haven't seen it fail with this code)

```py
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
```

Then finally adding it to `dump` to show this in a comment

```py
case CallSyscall(addr, target, syscall):
    print(f'\tcall {labels[target]} ; {syscall_names[syscall]}')
    print()
```

Looking at the difference afterwards it makes a massive difference in better understanding this disassembled code, especially when the function is so heavily used.

<table>
<tr>
<td>Before</td>
<td>After</td>
</tr>
<tr>
<td>
<pre>
mov r8, 0x16
mov r9, rexe
mov r0, 0x6060
add r9, r0
call FUNC_2353
</pre>
</td>
<td>
<pre>
mov r8, 0x16
mov r9, rexe
mov r0, 0x6060
add r9, r0
call syscall ; SYS_pipe
</pre>
</td>
</tr>
</table>

### Walking through the code

Let's go back to this post-`init` code, and hopefully we can see how clear it is now

```cpp
	call init

	mov r8, 0x16
	mov r9, rexe
	mov r0, 0x6060 // &mem[0x2000]
	add r9, r0
	call syscall ; SYS_pipe

	mov r8, 0x16
	mov r9, rexe
	mov r0, 0x6068 // &mem[0x2008]
	add r9, r0
	call syscall ; SYS_pipe

	mov r8, 0x39
	call syscall ; SYS_fork

    // If child goto child_program
	mov r0, 0x0
	jumpeq r8, r0, child_program // Was LAB_19e

    // If parent goto parent_program
	jump parent_program // Was LAB_126
```

Looking at both `child_program` and `parent_program` they both call `FUNC_2093` with what a look like a paremter in `r8` so let's take a look at it

```c
FUNC_2093:
	mov r0, r8
	mov r0, mem[r0]
	mov r1, 0xffffffff
	and r0, r1
	mov r8, 0x3
	mov r9, r0
	call syscall ; SYS_close

	ret
```

It looks like this dereferences a pointer then calls `close` on it, just below this we can see `FUNC_20da` does the same thing except it has the file descriptor in `r8`, so they can be renamed to `close_ptr` and `close`

### Follwoing the parent path

```cpp
parent_program:
    // Close the first pipe in the pipes at 0x2000
	mov r8, 0x2000
	call close_ptr

    // Close the second pipe in the pipes stored at 0x2008
	mov r8, 0x200c
	call close_ptr

	call init_seccomp // Was FUNC_223d

	jump parent_program_cont // Was LAB_1dbd
```

I won't dig into the `init_seccomp` as it's not necessary to solve this, when treating this as a pwn challenge for contaminated CTF (reuses this binary) it might be become more relevant.

Now the juice of it is primarily in `parent_program_cont`

```cpp
parent_program_cont:
    // Get the second fd from the first pipe and store it in mem[0x2010]
	mov r0, 0x2004
	mov r0, mem[r0]
	mov r1, 0xffffffff
	and r0, r1
	mov r1, 0x2010
	store mem[r1], r0

    // Get the first fd in the second pipe and store it in mem[0x2018]
	mov r0, 0x2008
	mov r0, mem[r0]
	mov r1, 0xffffffff
	and r0, r1
	mov r1, 0x2018
	store mem[r1], r0

    // Get 'rom' address (0x140e0 is bytecode pointer)
	mov r8, 0x140e0
	add r8, rexe
	call read_ptr // was FUNC_23cb

    // Store the rom address in mem[0x2020]
	mov r1, 0x2020
	store mem[r1], r8

get_flag: // was LAB_1e34
	mov r8, DAT_2bf6 ; 0x2bf6 // "Flag:"
	mov r9, DAT_2bfc ; 0x2bfc // End of "Flag:" ... Start of "Checking"
	call write_stdout // was FUNC_2463

	mov r8, 0x0 // SYS_read
	mov r9, 0x0 // fd = stdin
	mov r0, 0x2020
	mov r10, mem[r0] // buf = rom address
	mov r11, 0x60 // count
	call syscall ; SYS_read

    // If one byte was written (aka new line) then exit
	mov r0, 0x1
	jumpeq r8, r0, exit_parent // LAB_2085

    // Store the number of bytes written into mem[0x2028]
	mov r1, 0x2028
	store mem[r1], r8

    /// send a count of th ebytes the user entered
	mov r8, 0x1 // SYS_write
	mov r0, 0x2010
	mov r9, mem[r0] // fd = second fd of first pipe
	mov r10, rexe
	mov r0, 0x6088
	add r10, r0 // buf = &mem[0x2028] (number of bytes written)
	mov r11, 0x8 // size = 0x8
	call syscall ; SYS_write

    /// send the bytes the user entered
	mov r8, 0x1 // SYS_write
	mov r0, 0x2010
	mov r9, mem[r0] // fd = second fd of first pipe
	mov r0, 0x2020
	mov r10, mem[r0] // buf = rom address (where the flag was written)
	mov r1, 0x2028
	mov r11, mem[r1] // size = number of bytes read
	call syscall ; SYS_write

    // Write "Checking...."
	mov r8, DAT_2bfc ; 0x2bfc // "Checking..."
	mov r9, DAT_2c08 ; 0x2c08 // end of "Checking..."
	call write_stdout // was FUNC_2463

    /// read a byte back from the user
	mov r8, 0x0 // SYS_read
	mov r0, 0x2018
	mov r9, mem[r0] // fd = first fd in the second pipe
	mov r0, 0x2020
	mov r10, mem[r0] // buf = rom address
	mov r11, 0x1 // size = 1
	call syscall ; SYS_read

    /// read from the start of the rom address
	mov r0, 0x2020
	mov r8, mem[r0]
	call read_ptr // was FUNC_23cb

    // Cast the read to a byte and check if it's one
	mov r0, 0xff
	and r8, r0

    // If the result was 1 then 
	mov r0, 0x1
	jumpeq r8, r0, LAB_2054

	mov r8, DAT_2c08 ; 0x2c08 // "Wrong"
	mov r9, DAT_2c0f ; 0x2c0f
	call write_stdout // was FUNC_2463

	jump get_flag // was LAB_1e34

LAB_2054:
	mov r8, DAT_2c0f ; 0x2c0f // "Correct!"
	mov r9, 0x2c18
	call write_stdout // was FUNC_2463

LAB_2085:
	ret
```

So from this we can see that it reads and writes between pipes which the child is going to be using to validate and will send back 1 when it is a valid flag.

### Following the child path

We can see up-front that like the parent it closes the other half of the pipe fd's and also closes stdin and stdout

```cpp
child_program:
	mov r8, 0x2004
	call close_ptr

	mov r8, 0x2008
	call close_ptr

	mov r8, 0x0
	call close

	mov r8, 0x1
	call close

	jump child_program_cont // was LAB_375
```

```cpp
child_program_cont:
    // Get the second fd from the second pipe and store it in mem[0x2010]
	mov r0, 0x200c
	mov r0, mem[r0]
	mov r1, 0xffffffff
	and r0, r1
	mov r1, 0x2010
	store mem[r1], r0

    // Get the first fd from the first pipe and store it in mem[0x2018]
	mov r0, 0x2000
	mov r0, mem[r0]
	mov r1, 0xffffffff
	and r0, r1
	mov r1, 0x2018
	store mem[r1], r0

    // Get 'rom' address (0x140e0 is bytecode pointer)
	mov r8, 0x140e0
	add r8, rexe
	call read_ptr

    // Store the address of the 'rom' pointer in mem[0x2020]
	mov r1, 0x2020
	store mem[r1], r8

	call FUNC_247

    ...
```

Before going too deep down this path there is a very important function involved here `FUNC_247` which will change what the printreg instructions end up doing

```cpp
patch_printreg: // was FUNC_247
	mov r8, 0xa // SYS_mprotect
	mov r9, 0x1000
	add r9, rexe    // start = exe+0x1000
	mov r10, 0x2000 // len = 0x2000
	mov r11, 0x7    // prot = PROT_READ | PROT_WRITE | PROT_EXEC
	call syscall ; SYS_mprotect

    // Calculate the absolute address of the DAT_2a23 in memory and store it in r9
	mov r0, 0x2020
	mov r1, mem[r0]
	mov r0, DAT_2a23 ; 0x2a23
	add r1, r0
	mov r9, r1

    // Address to store the data, exe+0x1a00 is just after .text and before .rodata
	mov r8, 0x1a00
	add r8, rexe 

    // Calculate the size of DAT_2a23 and divide it by 8 (>> 3)
	mov r1, str_flag ; 0x2bf6
	mov r0, DAT_2a23 ; 0x2a23
	sub r1, r0
	mov r0, 0x3
	shr r1, r0
	mov r10, r1

    // dst/r8=exe+0x1a00
    // src/r9=absolute address of DAT_2a23
    // size/r10=sizeof(DAT_2a23)/8
	call memcpy_qword // was FUNC_2112 

    // Overwrite the instruction switch jump table entry for printreg(10)
    // with the address of 0x1a00, because this writes a pointer size and
    // the jump table is int it must write two entries so it writes to
    // the entry of 9 and 10 simultanously keeping the value of 9 unchanged
	mov r9, 0xfffff9bcfffff7c8
	mov r8, 0x2068
	add r8, rexe
	call write_ptr

	mov r8, 0xa // SYS_mprotect
	mov r9, 0x1000
	add r9, rexe    // start
	mov r10, 0x2000 // length
	mov r11, 0x5 // proto = PROTO_READ | PROTO_EXEC
	call syscall ; SYS_mprotect

	ret
```

The rabbit hole deepens as you can see, this changes what the `printreg` instruction does to be instead what's hidden in the assembly of `DAT_2a23`.

#### Examining the printreg patching

In order to more easily understand what the code in `DAT_2a23` does let's open `breach.bin` in Ghidra set the language to `x86:LE:default:gcc`, don't let it analyze the code, we know exactly what we want and from where

The important code we want is at 0x2a23 and we want it to be treated as though it's at the address 0x101a00 to more easily relate it to the executable code.

In order to do this in Window -> Memory Map you can click "Move" and provide `0xFEFDD` for the start address which is `0x101a00 - 0x2a23`.

In order to make things a little easier we will also add an uninitialized block that will cover enough space for us to define existing variables and types so I create a new block called `postblock` which starts at `0x101bf5` and has a length of `0x10000`

After this is adjusted now you can go to the address of `0x00101a00` which should match the file `0x2a23` and press D to disassemble, and we can start seeing what it does.

We can see that it starts with
```cpp
00101a00     CALL       FUN_00101a0a
00101a05     JMP        LAB_0010193b
```

If you look at `0x0010193b` in breach you'll see it's the continuation of the loop, so `FUN_00101a0a` is the core of this.

Let's do some initial house keeping and setup some types to match the binary
| address | name | type |
| ------- | ---- | ---- |
| 00104040 | inst_offset | long |
| 001140e0 | bytecode | byte* |
| 00104060 | mem | long[0x2000] (byte[65536] but we bypass that) |
| 00114060 | registers | long[16] |

Now let's look at how the decompilation looks

```cpp
void FUN_00101a0a(void)
{
  byte bVar1;
  ulong in_RCX;
  byte bVar2;
  
  bVar1 = (bytecode + inst_offet)[1];
  bVar2 = bytecode[inst_offet] >> 4;
  if (bVar2 == 0) {
    *(undefined *)((long)mem + mem[1536]) =
         *(undefined *)((long)registers + (in_RCX & 0xffffffffffffff00 | (ulong)(byte)(bVar1 << 3) ))
    ;
    mem[1536] += 1;
  }
  else if (bVar2 == 1) {
    *(byte *)((long)mem + mem[1536]) = bVar1;
    mem[1536] += 1;
  }
  else if (bVar2 == 2) {
    (&DAT_0010405e)[mem[1536]] = (&DAT_0010405f)[mem[1536]] + (&DAT_0010405e)[mem[1536]];
    mem[1536] += -1;
  }
  else if (bVar2 == 3) {
    (&DAT_0010405e)[mem[1536]] = (&DAT_0010405f)[mem[1536]] * (&DAT_0010405e)[mem[1536]];
    mem[1536] += -1;
  }
  else if (bVar2 == 4) {
    (&DAT_0010405e)[mem[1536]] = (&DAT_0010405f)[mem[1536]] ^ (&DAT_0010405e)[mem[1536]];
    mem[1536] += -1;
  }
  else if (bVar2 == 5) {
    (&DAT_0010405f)[mem[1536]] = (&DAT_0010405f)[mem[1536]] == '\0';
  }
  else if (bVar2 == 6) {
    (&DAT_0010405e)[mem[1536]] = (&DAT_0010405f)[mem[1536]] & (&DAT_0010405e)[mem[1536]];
    mem[1536] += -1;
  }
  else if (bVar2 == 7) {
    *(ulong *)((long)registers + (in_RCX & 0xffffffffffffff00 | (ulong)(byte)(bVar1 << 3))) =
         (ulong)(byte)(&DAT_0010405f)[mem[1536]];
    mem[1536] += -1;
  }
  else if (bVar2 == 8) {
    mem[1536] = 0x3008;
  }
  inst_offet = inst_offet + 2;
  return;
}
```

It's a bit of a mess, but gives a reasonable clue what is going on, remember any operations on `mem` you need to multiply by `8` to get the real value as we are using `long` not the original `byte`, it looks like the second nibble of the `printreg` instruction defines these other sub instructions.

There appears to be a stack offset which is stored in `mem[1536]` (0x2000 in real `mem` array) unfortunately the generated code doesn't identify that `DAT_0010405f` is really one below that stack and `DAT_0010405e` is two below the stack

Everything works solely on the stack pushing values then do an operation which pops the values and performs them (a different VM, hidding inside the VM)

| op | instruction |
| -- | ----------- |
| 0 | `ex.push reg` |
| 1 | `ex.push imm` |
| 2 | `ex.add` |
| 3 | `ex.mul` |
| 4 | `ex.xor` |
| 5 | `ex.eqz` |
| 6 | `ex.and` |
| 7 | `ex.pop reg` |
| 8 | `ex.reset` |

Now that we have these we can ditch the `printreg` instruction and add these new instructions.

```py
ExPushReg = namedtuple('ExPushReg', ['addr', 'reg'])
ExPushImm = namedtuple('ExPushImm', ['addr', 'imm'])
ExAdd = namedtuple('ExAdd', ['addr'])
ExMul = namedtuple('ExMul', ['addr'])
ExXor = namedtuple('ExXor', ['addr'])
ExEqz = namedtuple('ExEqz', ['addr'])
ExAnd = namedtuple('ExAnd', ['addr'])
ExPop = namedtuple('ExPop', ['addr', 'reg'])
ExReset = namedtuple('ExReset', ['addr'])
```

Then we adjust the parsing to handle it
```py
def parse(...):
    ...
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
```

Now we just need to print them in the dump
```py
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
```

Well that was a bit of a side-track discovered, a bunch more instructions getting closer to the finish now.

Let's keep walking down the child function

```cpp
child_loop: // was LAB_40b
    /// Read 8 bytes from the pipe into the rom start
	mov r8, 0x0
	mov r0, 0x2018
	mov r9, mem[r0]
	mov r0, 0x2020
	mov r10, mem[r0]
	mov r11, 0x8
	call syscall ; SYS_read

    // Read the pointer/size from the start of the rom
	mov r0, 0x2020
	mov r8, mem[r0]
	call read_ptr

    // Read the flag data into the start of the rom
	mov r11, r8
	mov r8, 0x0
	mov r0, 0x2018
	mov r9, mem[r0]
	mov r0, 0x2020
	mov r10, mem[r0]
	call syscall ; SYS_read

	call check_flag // was FUNC_557

    // Write the result of check_flag (r8) into the start of the rom
	mov r9, r8
	mov r0, 0x2020
	mov r8, mem[r0]
	call write_ptr

    // Write the result back to the parent to read
	mov r8, 0x1
	mov r0, 0x2010
	mov r9, mem[r0]
	mov r0, 0x2020
	mov r10, mem[r0]
	mov r11, 0x1
	call syscall ; SYS_write

	jump child_loop
```

Now the real part where we want to look `check_flag`

```cpp
check_flag:
    // Check if the rom (flag input) starts with 'dice{'
	mov r0, 0x0
	mov r8, rom[r0]
	mov r0, 0xffffffffff
	and r8, r0
	mov r0, 0x7b65636964 // '{ecid'
	jumpeq r8, r0, LAB_589

	jump LAB_1da6

LAB_589:
	ex.reset
    // Load flag offsets
	mov r0, 0x7
	mov r8, rom[r0]
	mov r0, 0x1
	mov r9, rom[r0]
	mov r0, 0x11
	mov r10, rom[r0]
	mov r0, 0xf
	mov r11, rom[r0]

    // Add (can be another op) the first two values
	ex.push r8
	ex.push r9
	ex.add

    // Add (can be another op) the last result to 0x2c
	ex.push 0x2c
	ex.add

    // Add (can be another op) the second two values
	ex.push r10
	ex.push r11
	ex.add

    // Xor (can be another op) the last result and 0xd8
	ex.push 0xd8
	ex.xor

    // Xor the last two groups of operations
	ex.xor

    // Xor the result of the last operation with 0xd8
	ex.push 0x10
	ex.xor

    // Xor the result of that again
	ex.push 0xd6
	ex.xor

    // Check if it's equal to zero (this only happens if it equals 0xd6)
	ex.eqz
... // slightly different ops, constants and offsets in mem provided and repeated multiple times

	ex.and // Combine the result of the final eqz operations
	ex.and
	ex.and
	ex.and
	ex.and
... // repeated and for each block
	ex.pop r8 // Return the result as r8
	jump LAB_1daf

LAB_1da6:
	mov r8, 0x0
LAB_1daf:
	ret
```

## Solving the flag checker

Now we can build another matcher which is able extract all these patterns and then use z3 to be able to solve what matches all these operations.

```py
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
```

This gives us the flag `dice{st4ying_ins1de_vms_1s_0verr4ted}`

## Exploiting the flag input for remote code execution

TODO: Solve this and do a write-up

This is the contaminated pwn challenge which reuses this same binary, I have yet to do this (it's already taken long enough to write this write-up)

In order to exploit contaminated it should be possible to write exploit which will overwrite the buffer which the flag get's written to (the rom) and execute custom VM code from 0x28 until 0x60 overwriting the exit() call doing your own thing (likely need to trigger a second read for a proper payload)