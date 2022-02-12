	mov rsp, 0x10000
	call FUNC_59

	mov r8, 0x3c
	mov r9, 0x0
	call syscall ; SYS_exit

FUNC_59:
	call init

	mov r8, 0x16
	mov r9, rexe
	mov r0, 0x6060
	add r9, r0
	call syscall ; SYS_pipe

	mov r8, 0x16
	mov r9, rexe
	mov r0, 0x6068
	add r9, r0
	call syscall ; SYS_pipe

	mov r8, 0x39
	call syscall ; SYS_fork

	mov r0, 0x0
	jumpeq r8, r0, child_program

	jump parent_program

parent_program:
	mov r8, 0x2000
	call close_ptr

	mov r8, 0x200c
	call close_ptr

	call init_seccomp

	jump parent_program_cont

child_program:
	mov r8, 0x2004
	call close_ptr

	mov r8, 0x2008
	call close_ptr

	mov r8, 0x0
	call close

	mov r8, 0x1
	call close

	jump child_program_cont

patch_printreg:
	mov r8, 0xa
	mov r9, 0x1000
	add r9, rexe
	mov r10, 0x2000
	mov r11, 0x7
	call syscall ; SYS_mprotect

	mov r0, 0x2020
	mov r1, mem[r0]
	mov r0, DAT_2a23 ; 0x2a23
	add r1, r0
	mov r9, r1
	mov r8, 0x1a00
	add r8, rexe
	mov r1, str_flag ; 0x2bf6
	mov r0, DAT_2a23 ; 0x2a23
	sub r1, r0
	mov r0, 0x3
	shr r1, r0
	mov r10, r1
	call memcpy_qword

	mov r9, 0xfffff9bcfffff7c8
	mov r8, 0x2068
	add r8, rexe
	call write_ptr

	mov r8, 0xa
	mov r9, 0x1000
	add r9, rexe
	mov r10, 0x2000
	mov r11, 0x5
	call syscall ; SYS_mprotect

	ret

child_program_cont:
	mov r0, 0x200c
	mov r0, mem[r0]
	mov r1, 0xffffffff
	and r0, r1
	mov r1, 0x2010
	store mem[r1], r0
	mov r0, 0x2000
	mov r0, mem[r0]
	mov r1, 0xffffffff
	and r0, r1
	mov r1, 0x2018
	store mem[r1], r0
	mov r8, 0x140e0
	add r8, rexe
	call read_ptr

	mov r1, 0x2020
	store mem[r1], r8
	call patch_printreg

child_loop:
	mov r8, 0x0
	mov r0, 0x2018
	mov r9, mem[r0]
	mov r0, 0x2020
	mov r10, mem[r0]
	mov r11, 0x8
	call syscall ; SYS_read

	mov r0, 0x2020
	mov r8, mem[r0]
	call read_ptr

	mov r11, r8
	mov r8, 0x0
	mov r0, 0x2018
	mov r9, mem[r0]
	mov r0, 0x2020
	mov r10, mem[r0]
	call syscall ; SYS_read

	call check_flag

	mov r9, r8
	mov r0, 0x2020
	mov r8, mem[r0]
	call write_ptr

	mov r8, 0x1
	mov r0, 0x2010
	mov r9, mem[r0]
	mov r0, 0x2020
	mov r10, mem[r0]
	mov r11, 0x1
	call syscall ; SYS_write

	jump child_loop

check_flag:
	mov r0, 0x0
	mov r8, rom[r0]
	mov r0, 0xffffffffff
	and r8, r0
	mov r0, 0x7b65636964
	jumpeq r8, r0, LAB_589

	jump LAB_1da6

LAB_589:
	ex.reset
	mov r0, 0x7
	mov r8, rom[r0]
	mov r0, 0x1
	mov r9, rom[r0]
	mov r0, 0x11
	mov r10, rom[r0]
	mov r0, 0xf
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0x2c
	ex.add
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0xd8
	ex.xor
	ex.xor
	ex.push 0x10
	ex.xor
	ex.push 0xd6
	ex.xor
	ex.eqz
	mov r0, 0x1
	mov r8, rom[r0]
	mov r0, 0x5
	mov r9, rom[r0]
	mov r0, 0xd
	mov r10, rom[r0]
	mov r0, 0xe
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0xd6
	ex.xor
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0x70
	ex.add
	ex.add
	ex.push 0xe5
	ex.xor
	ex.push 0xa6
	ex.xor
	ex.eqz
	mov r0, 0x11
	mov r8, rom[r0]
	mov r0, 0x0
	mov r9, rom[r0]
	mov r0, 0xa
	mov r10, rom[r0]
	mov r0, 0x1b
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0x2f
	ex.mul
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0xc2
	ex.mul
	ex.add
	ex.push 0x31
	ex.add
	ex.push 0xdd
	ex.xor
	ex.eqz
	mov r0, 0x16
	mov r8, rom[r0]
	mov r0, 0x16
	mov r9, rom[r0]
	mov r0, 0x10
	mov r10, rom[r0]
	mov r0, 0x2
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x96
	ex.mul
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0xb9
	ex.mul
	ex.xor
	ex.push 0x62
	ex.add
	ex.push 0x56
	ex.xor
	ex.eqz
	mov r0, 0x4
	mov r8, rom[r0]
	mov r0, 0x2
	mov r9, rom[r0]
	mov r0, 0xe
	mov r10, rom[r0]
	mov r0, 0x12
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0xba
	ex.add
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0x53
	ex.mul
	ex.add
	ex.push 0xbd
	ex.mul
	ex.push 0x82
	ex.xor
	ex.eqz
	mov r0, 0x16
	mov r8, rom[r0]
	mov r0, 0xd
	mov r9, rom[r0]
	mov r0, 0x11
	mov r10, rom[r0]
	mov r0, 0x4
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x53
	ex.xor
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0xec
	ex.xor
	ex.add
	ex.push 0xc2
	ex.add
	ex.push 0xfe
	ex.xor
	ex.eqz
	mov r0, 0x11
	mov r8, rom[r0]
	mov r0, 0x23
	mov r9, rom[r0]
	mov r0, 0xe
	mov r10, rom[r0]
	mov r0, 0x14
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0x21
	ex.add
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0x6c
	ex.mul
	ex.add
	ex.push 0xa1
	ex.mul
	ex.push 0x79
	ex.xor
	ex.eqz
	mov r0, 0xd
	mov r8, rom[r0]
	mov r0, 0x1f
	mov r9, rom[r0]
	mov r0, 0x19
	mov r10, rom[r0]
	mov r0, 0x1d
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0x86
	ex.mul
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0xdb
	ex.xor
	ex.add
	ex.push 0xcc
	ex.xor
	ex.push 0x69
	ex.xor
	ex.eqz
	mov r0, 0x17
	mov r8, rom[r0]
	mov r0, 0xe
	mov r9, rom[r0]
	mov r0, 0x8
	mov r10, rom[r0]
	mov r0, 0x20
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0x51
	ex.add
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0xd8
	ex.add
	ex.add
	ex.push 0x20
	ex.xor
	ex.push 0x88
	ex.xor
	ex.eqz
	mov r0, 0x18
	mov r8, rom[r0]
	mov r0, 0x18
	mov r9, rom[r0]
	mov r0, 0x1d
	mov r10, rom[r0]
	mov r0, 0x21
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0x88
	ex.xor
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0xae
	ex.xor
	ex.add
	ex.push 0x39
	ex.add
	ex.push 0xe1
	ex.xor
	ex.eqz
	mov r0, 0x12
	mov r8, rom[r0]
	mov r0, 0x1b
	mov r9, rom[r0]
	mov r0, 0xa
	mov r10, rom[r0]
	mov r0, 0x1d
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0x36
	ex.xor
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0x98
	ex.xor
	ex.xor
	ex.push 0x65
	ex.add
	ex.push 0xc2
	ex.xor
	ex.eqz
	mov r0, 0x9
	mov r8, rom[r0]
	mov r0, 0x17
	mov r9, rom[r0]
	mov r0, 0xa
	mov r10, rom[r0]
	mov r0, 0x22
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x39
	ex.add
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0xb9
	ex.mul
	ex.xor
	ex.push 0x9d
	ex.add
	ex.push 0x76
	ex.xor
	ex.eqz
	mov r0, 0xf
	mov r8, rom[r0]
	mov r0, 0x3
	mov r9, rom[r0]
	mov r0, 0xf
	mov r10, rom[r0]
	mov r0, 0x24
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0x40
	ex.add
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0x41
	ex.add
	ex.xor
	ex.push 0xf3
	ex.xor
	ex.push 0x83
	ex.xor
	ex.eqz
	mov r0, 0x23
	mov r8, rom[r0]
	mov r0, 0xa
	mov r9, rom[r0]
	mov r0, 0x10
	mov r10, rom[r0]
	mov r0, 0x21
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x66
	ex.mul
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0x9f
	ex.xor
	ex.add
	ex.push 0xcc
	ex.xor
	ex.push 0x1a
	ex.xor
	ex.eqz
	mov r0, 0x17
	mov r8, rom[r0]
	mov r0, 0x1c
	mov r9, rom[r0]
	mov r0, 0x21
	mov r10, rom[r0]
	mov r0, 0x1c
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0x75
	ex.add
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0x70
	ex.mul
	ex.add
	ex.push 0x3
	ex.add
	ex.push 0xad
	ex.xor
	ex.eqz
	mov r0, 0x4
	mov r8, rom[r0]
	mov r0, 0x3
	mov r9, rom[r0]
	mov r0, 0xe
	mov r10, rom[r0]
	mov r0, 0x4
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0xf8
	ex.mul
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0x6d
	ex.add
	ex.add
	ex.push 0x43
	ex.mul
	ex.push 0x6
	ex.xor
	ex.eqz
	mov r0, 0x24
	mov r8, rom[r0]
	mov r0, 0x24
	mov r9, rom[r0]
	mov r0, 0x1e
	mov r10, rom[r0]
	mov r0, 0xf
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0xdc
	ex.mul
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0xb5
	ex.add
	ex.add
	ex.push 0xd8
	ex.xor
	ex.push 0x8e
	ex.xor
	ex.eqz
	mov r0, 0x1a
	mov r8, rom[r0]
	mov r0, 0x1d
	mov r9, rom[r0]
	mov r0, 0x3
	mov r10, rom[r0]
	mov r0, 0x6
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0x62
	ex.mul
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0x61
	ex.add
	ex.xor
	ex.push 0xe5
	ex.add
	ex.push 0x12
	ex.xor
	ex.eqz
	mov r0, 0x8
	mov r8, rom[r0]
	mov r0, 0x1b
	mov r9, rom[r0]
	mov r0, 0xb
	mov r10, rom[r0]
	mov r0, 0x11
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0x19
	ex.add
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0x7
	ex.xor
	ex.add
	ex.push 0x2f
	ex.add
	ex.push 0x33
	ex.xor
	ex.eqz
	mov r0, 0xf
	mov r8, rom[r0]
	mov r0, 0xa
	mov r9, rom[r0]
	mov r0, 0x1a
	mov r10, rom[r0]
	mov r0, 0x1f
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0x1
	ex.add
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0xc7
	ex.add
	ex.mul
	ex.push 0x87
	ex.mul
	ex.push 0xb8
	ex.xor
	ex.eqz
	mov r0, 0x1d
	mov r8, rom[r0]
	mov r0, 0x12
	mov r9, rom[r0]
	mov r0, 0x1b
	mov r10, rom[r0]
	mov r0, 0x23
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x6f
	ex.xor
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0x1d
	ex.add
	ex.mul
	ex.push 0x1f
	ex.mul
	ex.push 0x21
	ex.xor
	ex.eqz
	mov r0, 0x14
	mov r8, rom[r0]
	mov r0, 0x3
	mov r9, rom[r0]
	mov r0, 0x3
	mov r10, rom[r0]
	mov r0, 0x1e
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x5f
	ex.xor
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0x23
	ex.xor
	ex.add
	ex.push 0x22
	ex.add
	ex.push 0x62
	ex.xor
	ex.eqz
	mov r0, 0xf
	mov r8, rom[r0]
	mov r0, 0x19
	mov r9, rom[r0]
	mov r0, 0x7
	mov r10, rom[r0]
	mov r0, 0x24
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0xd6
	ex.xor
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0xa1
	ex.xor
	ex.xor
	ex.push 0x85
	ex.add
	ex.push 0xa5
	ex.xor
	ex.eqz
	mov r0, 0xd
	mov r8, rom[r0]
	mov r0, 0x14
	mov r9, rom[r0]
	mov r0, 0xf
	mov r10, rom[r0]
	mov r0, 0x10
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0xa1
	ex.add
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0x25
	ex.mul
	ex.xor
	ex.push 0x4
	ex.mul
	ex.push 0x34
	ex.xor
	ex.eqz
	mov r0, 0x1d
	mov r8, rom[r0]
	mov r0, 0x24
	mov r9, rom[r0]
	mov r0, 0x6
	mov r10, rom[r0]
	mov r0, 0x4
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x23
	ex.add
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0x7d
	ex.add
	ex.xor
	ex.push 0xbd
	ex.mul
	ex.push 0x7a
	ex.xor
	ex.eqz
	mov r0, 0x12
	mov r8, rom[r0]
	mov r0, 0xa
	mov r9, rom[r0]
	mov r0, 0x1c
	mov r10, rom[r0]
	mov r0, 0x22
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x99
	ex.mul
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0x35
	ex.xor
	ex.xor
	ex.push 0x44
	ex.add
	ex.push 0xf9
	ex.xor
	ex.eqz
	mov r0, 0x10
	mov r8, rom[r0]
	mov r0, 0x7
	mov r9, rom[r0]
	mov r0, 0x6
	mov r10, rom[r0]
	mov r0, 0x23
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0xaf
	ex.mul
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0x68
	ex.add
	ex.mul
	ex.push 0x87
	ex.xor
	ex.push 0xaf
	ex.xor
	ex.eqz
	mov r0, 0x20
	mov r8, rom[r0]
	mov r0, 0x1f
	mov r9, rom[r0]
	mov r0, 0x10
	mov r10, rom[r0]
	mov r0, 0x3
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0xaa
	ex.xor
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0x42
	ex.add
	ex.mul
	ex.push 0x86
	ex.add
	ex.push 0x9a
	ex.xor
	ex.eqz
	mov r0, 0xa
	mov r8, rom[r0]
	mov r0, 0x1c
	mov r9, rom[r0]
	mov r0, 0x23
	mov r10, rom[r0]
	mov r0, 0x1b
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x12
	ex.add
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0xbd
	ex.xor
	ex.add
	ex.push 0x4b
	ex.add
	ex.push 0x9e
	ex.xor
	ex.eqz
	mov r0, 0x1b
	mov r8, rom[r0]
	mov r0, 0x8
	mov r9, rom[r0]
	mov r0, 0x2
	mov r10, rom[r0]
	mov r0, 0x13
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0x34
	ex.add
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0xb5
	ex.xor
	ex.mul
	ex.push 0xd0
	ex.add
	ex.push 0xcc
	ex.xor
	ex.eqz
	mov r0, 0x9
	mov r8, rom[r0]
	mov r0, 0xf
	mov r9, rom[r0]
	mov r0, 0xa
	mov r10, rom[r0]
	mov r0, 0xb
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0x7f
	ex.add
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0x88
	ex.mul
	ex.add
	ex.push 0x51
	ex.mul
	ex.push 0x12
	ex.xor
	ex.eqz
	mov r0, 0x6
	mov r8, rom[r0]
	mov r0, 0x18
	mov r9, rom[r0]
	mov r0, 0x2
	mov r10, rom[r0]
	mov r0, 0x1e
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0x72
	ex.add
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0xc
	ex.mul
	ex.mul
	ex.push 0x62
	ex.add
	ex.push 0x1a
	ex.xor
	ex.eqz
	mov r0, 0x19
	mov r8, rom[r0]
	mov r0, 0x15
	mov r9, rom[r0]
	mov r0, 0x11
	mov r10, rom[r0]
	mov r0, 0x4
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0xa9
	ex.mul
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0xe
	ex.mul
	ex.xor
	ex.push 0x3b
	ex.xor
	ex.push 0x86
	ex.xor
	ex.eqz
	mov r0, 0x10
	mov r8, rom[r0]
	mov r0, 0xb
	mov r9, rom[r0]
	mov r0, 0x10
	mov r10, rom[r0]
	mov r0, 0x2
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0xdf
	ex.xor
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0x3b
	ex.xor
	ex.mul
	ex.push 0xc5
	ex.mul
	ex.push 0x58
	ex.xor
	ex.eqz
	mov r0, 0x24
	mov r8, rom[r0]
	mov r0, 0xc
	mov r9, rom[r0]
	mov r0, 0x10
	mov r10, rom[r0]
	mov r0, 0x2
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x64
	ex.mul
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0xba
	ex.xor
	ex.add
	ex.push 0xdc
	ex.xor
	ex.push 0xec
	ex.xor
	ex.eqz
	mov r0, 0x4
	mov r8, rom[r0]
	mov r0, 0x15
	mov r9, rom[r0]
	mov r0, 0x14
	mov r10, rom[r0]
	mov r0, 0x7
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0xa7
	ex.mul
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0xce
	ex.xor
	ex.xor
	ex.push 0x97
	ex.mul
	ex.push 0xb4
	ex.xor
	ex.eqz
	mov r0, 0x23
	mov r8, rom[r0]
	mov r0, 0x8
	mov r9, rom[r0]
	mov r0, 0xc
	mov r10, rom[r0]
	mov r0, 0x1a
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x9a
	ex.mul
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0xcf
	ex.add
	ex.xor
	ex.push 0x0
	ex.xor
	ex.push 0xbd
	ex.xor
	ex.eqz
	mov r0, 0x13
	mov r8, rom[r0]
	mov r0, 0x12
	mov r9, rom[r0]
	mov r0, 0xd
	mov r10, rom[r0]
	mov r0, 0x1b
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0xe2
	ex.xor
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0x6d
	ex.mul
	ex.xor
	ex.push 0xf2
	ex.mul
	ex.push 0xd0
	ex.xor
	ex.eqz
	mov r0, 0xa
	mov r8, rom[r0]
	mov r0, 0x5
	mov r9, rom[r0]
	mov r0, 0x12
	mov r10, rom[r0]
	mov r0, 0x20
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x9e
	ex.xor
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0x73
	ex.add
	ex.xor
	ex.push 0x65
	ex.add
	ex.push 0xd9
	ex.xor
	ex.eqz
	mov r0, 0x9
	mov r8, rom[r0]
	mov r0, 0x1
	mov r9, rom[r0]
	mov r0, 0x2
	mov r10, rom[r0]
	mov r0, 0xf
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0x63
	ex.xor
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0xc4
	ex.mul
	ex.add
	ex.push 0xfd
	ex.xor
	ex.push 0xeb
	ex.xor
	ex.eqz
	mov r0, 0x19
	mov r8, rom[r0]
	mov r0, 0xf
	mov r9, rom[r0]
	mov r0, 0x9
	mov r10, rom[r0]
	mov r0, 0x0
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0xed
	ex.mul
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0x19
	ex.xor
	ex.add
	ex.push 0x7f
	ex.xor
	ex.push 0xbd
	ex.xor
	ex.eqz
	mov r0, 0x7
	mov r8, rom[r0]
	mov r0, 0x1d
	mov r9, rom[r0]
	mov r0, 0x8
	mov r10, rom[r0]
	mov r0, 0x1d
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0xda
	ex.xor
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0xe4
	ex.mul
	ex.xor
	ex.push 0x51
	ex.mul
	ex.push 0xeb
	ex.xor
	ex.eqz
	mov r0, 0x1e
	mov r8, rom[r0]
	mov r0, 0x1c
	mov r9, rom[r0]
	mov r0, 0x10
	mov r10, rom[r0]
	mov r0, 0xf
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x8c
	ex.mul
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0xe1
	ex.xor
	ex.xor
	ex.push 0x27
	ex.add
	ex.push 0xf9
	ex.xor
	ex.eqz
	mov r0, 0x12
	mov r8, rom[r0]
	mov r0, 0xf
	mov r9, rom[r0]
	mov r0, 0x11
	mov r10, rom[r0]
	mov r0, 0x15
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0xc4
	ex.xor
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0x4e
	ex.add
	ex.add
	ex.push 0x6d
	ex.add
	ex.push 0x27
	ex.xor
	ex.eqz
	mov r0, 0x4
	mov r8, rom[r0]
	mov r0, 0x1a
	mov r9, rom[r0]
	mov r0, 0x1a
	mov r10, rom[r0]
	mov r0, 0x15
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0xc7
	ex.mul
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0xa
	ex.add
	ex.mul
	ex.push 0xc2
	ex.mul
	ex.push 0x50
	ex.xor
	ex.eqz
	mov r0, 0x1e
	mov r8, rom[r0]
	mov r0, 0x0
	mov r9, rom[r0]
	mov r0, 0x16
	mov r10, rom[r0]
	mov r0, 0x13
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0x70
	ex.mul
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0xf9
	ex.xor
	ex.xor
	ex.push 0x70
	ex.xor
	ex.push 0x25
	ex.xor
	ex.eqz
	mov r0, 0x11
	mov r8, rom[r0]
	mov r0, 0x1b
	mov r9, rom[r0]
	mov r0, 0x1f
	mov r10, rom[r0]
	mov r0, 0x1
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0x54
	ex.mul
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0xef
	ex.mul
	ex.xor
	ex.push 0x41
	ex.xor
	ex.push 0x74
	ex.xor
	ex.eqz
	mov r0, 0x22
	mov r8, rom[r0]
	mov r0, 0x1
	mov r9, rom[r0]
	mov r0, 0x19
	mov r10, rom[r0]
	mov r0, 0x24
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0xec
	ex.add
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0x5d
	ex.mul
	ex.add
	ex.push 0x19
	ex.add
	ex.push 0x27
	ex.xor
	ex.eqz
	mov r0, 0x10
	mov r8, rom[r0]
	mov r0, 0x18
	mov r9, rom[r0]
	mov r0, 0x14
	mov r10, rom[r0]
	mov r0, 0xd
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0x81
	ex.mul
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0x29
	ex.mul
	ex.mul
	ex.push 0xf0
	ex.mul
	ex.push 0xa0
	ex.xor
	ex.eqz
	mov r0, 0x1
	mov r8, rom[r0]
	mov r0, 0x22
	mov r9, rom[r0]
	mov r0, 0x3
	mov r10, rom[r0]
	mov r0, 0x16
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0x7e
	ex.xor
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0x66
	ex.add
	ex.add
	ex.push 0xa
	ex.add
	ex.push 0x36
	ex.xor
	ex.eqz
	mov r0, 0x9
	mov r8, rom[r0]
	mov r0, 0xf
	mov r9, rom[r0]
	mov r0, 0x8
	mov r10, rom[r0]
	mov r0, 0x1e
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x83
	ex.add
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0xbc
	ex.mul
	ex.xor
	ex.push 0x55
	ex.xor
	ex.push 0x5c
	ex.xor
	ex.eqz
	mov r0, 0x7
	mov r8, rom[r0]
	mov r0, 0xa
	mov r9, rom[r0]
	mov r0, 0x13
	mov r10, rom[r0]
	mov r0, 0x6
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0xcb
	ex.add
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0x65
	ex.xor
	ex.mul
	ex.push 0x26
	ex.mul
	ex.push 0x64
	ex.xor
	ex.eqz
	mov r0, 0xf
	mov r8, rom[r0]
	mov r0, 0x6
	mov r9, rom[r0]
	mov r0, 0x13
	mov r10, rom[r0]
	mov r0, 0x7
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0xbd
	ex.add
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0x23
	ex.mul
	ex.mul
	ex.push 0xae
	ex.xor
	ex.push 0xea
	ex.xor
	ex.eqz
	mov r0, 0x0
	mov r8, rom[r0]
	mov r0, 0x1a
	mov r9, rom[r0]
	mov r0, 0x1f
	mov r10, rom[r0]
	mov r0, 0x6
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0xde
	ex.mul
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0x5a
	ex.xor
	ex.xor
	ex.push 0x8a
	ex.add
	ex.push 0x44
	ex.xor
	ex.eqz
	mov r0, 0x22
	mov r8, rom[r0]
	mov r0, 0x1e
	mov r9, rom[r0]
	mov r0, 0x1d
	mov r10, rom[r0]
	mov r0, 0x1b
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x8e
	ex.xor
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0xe6
	ex.add
	ex.mul
	ex.push 0x7c
	ex.add
	ex.push 0x62
	ex.xor
	ex.eqz
	mov r0, 0x1d
	mov r8, rom[r0]
	mov r0, 0x24
	mov r9, rom[r0]
	mov r0, 0x18
	mov r10, rom[r0]
	mov r0, 0x15
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0xb5
	ex.mul
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0x84
	ex.mul
	ex.mul
	ex.push 0xae
	ex.add
	ex.push 0x5e
	ex.xor
	ex.eqz
	mov r0, 0x11
	mov r8, rom[r0]
	mov r0, 0x11
	mov r9, rom[r0]
	mov r0, 0x23
	mov r10, rom[r0]
	mov r0, 0x0
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0xfa
	ex.add
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0x7b
	ex.xor
	ex.add
	ex.push 0xf3
	ex.mul
	ex.push 0x37
	ex.xor
	ex.eqz
	mov r0, 0x1f
	mov r8, rom[r0]
	mov r0, 0x1c
	mov r9, rom[r0]
	mov r0, 0x1
	mov r10, rom[r0]
	mov r0, 0x5
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0xbc
	ex.add
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0xf2
	ex.add
	ex.mul
	ex.push 0xb0
	ex.mul
	ex.push 0x0
	ex.xor
	ex.eqz
	mov r0, 0x1b
	mov r8, rom[r0]
	mov r0, 0x23
	mov r9, rom[r0]
	mov r0, 0x15
	mov r10, rom[r0]
	mov r0, 0x16
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x3d
	ex.mul
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0x62
	ex.mul
	ex.mul
	ex.push 0xa1
	ex.add
	ex.push 0xd9
	ex.xor
	ex.eqz
	mov r0, 0x7
	mov r8, rom[r0]
	mov r0, 0x22
	mov r9, rom[r0]
	mov r0, 0xb
	mov r10, rom[r0]
	mov r0, 0xc
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0x90
	ex.xor
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0x33
	ex.xor
	ex.mul
	ex.push 0x63
	ex.xor
	ex.push 0x39
	ex.xor
	ex.eqz
	mov r0, 0x12
	mov r8, rom[r0]
	mov r0, 0xe
	mov r9, rom[r0]
	mov r0, 0x17
	mov r10, rom[r0]
	mov r0, 0xb
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0x17
	ex.add
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0x1b
	ex.add
	ex.xor
	ex.push 0x95
	ex.mul
	ex.push 0xc6
	ex.xor
	ex.eqz
	mov r0, 0x8
	mov r8, rom[r0]
	mov r0, 0x1f
	mov r9, rom[r0]
	mov r0, 0x6
	mov r10, rom[r0]
	mov r0, 0x0
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x5e
	ex.mul
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0x1a
	ex.mul
	ex.mul
	ex.push 0x81
	ex.mul
	ex.push 0x40
	ex.xor
	ex.eqz
	mov r0, 0x1e
	mov r8, rom[r0]
	mov r0, 0x7
	mov r9, rom[r0]
	mov r0, 0x4
	mov r10, rom[r0]
	mov r0, 0x19
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0x4d
	ex.add
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0x4c
	ex.xor
	ex.xor
	ex.push 0x9b
	ex.add
	ex.push 0xcc
	ex.xor
	ex.eqz
	mov r0, 0x5
	mov r8, rom[r0]
	mov r0, 0xf
	mov r9, rom[r0]
	mov r0, 0x7
	mov r10, rom[r0]
	mov r0, 0x23
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0xc2
	ex.xor
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0xe6
	ex.add
	ex.xor
	ex.push 0xe2
	ex.xor
	ex.push 0xbf
	ex.xor
	ex.eqz
	mov r0, 0x13
	mov r8, rom[r0]
	mov r0, 0x1b
	mov r9, rom[r0]
	mov r0, 0x13
	mov r10, rom[r0]
	mov r0, 0x24
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x6c
	ex.add
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0x87
	ex.add
	ex.xor
	ex.push 0x29
	ex.add
	ex.push 0x9b
	ex.xor
	ex.eqz
	mov r0, 0xa
	mov r8, rom[r0]
	mov r0, 0xf
	mov r9, rom[r0]
	mov r0, 0xb
	mov r10, rom[r0]
	mov r0, 0x23
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0xf0
	ex.add
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0x95
	ex.mul
	ex.add
	ex.push 0x10
	ex.xor
	ex.push 0xad
	ex.xor
	ex.eqz
	mov r0, 0xe
	mov r8, rom[r0]
	mov r0, 0x12
	mov r9, rom[r0]
	mov r0, 0x12
	mov r10, rom[r0]
	mov r0, 0x1d
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0x65
	ex.xor
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0xd9
	ex.xor
	ex.add
	ex.push 0x3a
	ex.xor
	ex.push 0x8c
	ex.xor
	ex.eqz
	mov r0, 0x22
	mov r8, rom[r0]
	mov r0, 0xe
	mov r9, rom[r0]
	mov r0, 0x9
	mov r10, rom[r0]
	mov r0, 0x11
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0x93
	ex.add
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0xe0
	ex.mul
	ex.add
	ex.push 0x3f
	ex.xor
	ex.push 0xf9
	ex.xor
	ex.eqz
	mov r0, 0x1d
	mov r8, rom[r0]
	mov r0, 0x13
	mov r9, rom[r0]
	mov r0, 0x19
	mov r10, rom[r0]
	mov r0, 0x11
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x14
	ex.xor
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0xdd
	ex.add
	ex.mul
	ex.push 0xa5
	ex.xor
	ex.push 0xbb
	ex.xor
	ex.eqz
	mov r0, 0x10
	mov r8, rom[r0]
	mov r0, 0x1
	mov r9, rom[r0]
	mov r0, 0x5
	mov r10, rom[r0]
	mov r0, 0xe
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x14
	ex.xor
	ex.push r10
	ex.push r11
	ex.add
	ex.push 0x59
	ex.xor
	ex.xor
	ex.push 0xf0
	ex.mul
	ex.push 0xc0
	ex.xor
	ex.eqz
	mov r0, 0x21
	mov r8, rom[r0]
	mov r0, 0x1c
	mov r9, rom[r0]
	mov r0, 0x11
	mov r10, rom[r0]
	mov r0, 0xb
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0xb2
	ex.mul
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0xd1
	ex.add
	ex.xor
	ex.push 0xaa
	ex.mul
	ex.push 0xba
	ex.xor
	ex.eqz
	mov r0, 0x14
	mov r8, rom[r0]
	mov r0, 0x6
	mov r9, rom[r0]
	mov r0, 0xa
	mov r10, rom[r0]
	mov r0, 0x15
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0x12
	ex.xor
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0xe8
	ex.xor
	ex.mul
	ex.push 0x2d
	ex.mul
	ex.push 0x3c
	ex.xor
	ex.eqz
	mov r0, 0x14
	mov r8, rom[r0]
	mov r0, 0x10
	mov r9, rom[r0]
	mov r0, 0x14
	mov r10, rom[r0]
	mov r0, 0x7
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0xd3
	ex.xor
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0x1b
	ex.xor
	ex.add
	ex.push 0x60
	ex.mul
	ex.push 0x40
	ex.xor
	ex.eqz
	mov r0, 0x21
	mov r8, rom[r0]
	mov r0, 0x17
	mov r9, rom[r0]
	mov r0, 0x1f
	mov r10, rom[r0]
	mov r0, 0x1c
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0xe0
	ex.add
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0xf8
	ex.add
	ex.mul
	ex.push 0x3e
	ex.mul
	ex.push 0x98
	ex.xor
	ex.eqz
	mov r0, 0x1
	mov r8, rom[r0]
	mov r0, 0xf
	mov r9, rom[r0]
	mov r0, 0xa
	mov r10, rom[r0]
	mov r0, 0x13
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0x3a
	ex.add
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0xec
	ex.add
	ex.xor
	ex.push 0x3c
	ex.add
	ex.push 0x26
	ex.xor
	ex.eqz
	mov r0, 0x9
	mov r8, rom[r0]
	mov r0, 0x1f
	mov r9, rom[r0]
	mov r0, 0x12
	mov r10, rom[r0]
	mov r0, 0x20
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.xor
	ex.push 0xe9
	ex.mul
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0x4a
	ex.mul
	ex.mul
	ex.push 0xc4
	ex.add
	ex.push 0xbc
	ex.xor
	ex.eqz
	mov r0, 0xc
	mov r8, rom[r0]
	mov r0, 0x20
	mov r9, rom[r0]
	mov r0, 0x8
	mov r10, rom[r0]
	mov r0, 0x4
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0x90
	ex.mul
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0x98
	ex.mul
	ex.mul
	ex.push 0xfa
	ex.add
	ex.push 0xfa
	ex.xor
	ex.eqz
	mov r0, 0x9
	mov r8, rom[r0]
	mov r0, 0x1c
	mov r9, rom[r0]
	mov r0, 0x22
	mov r10, rom[r0]
	mov r0, 0x1e
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.mul
	ex.push 0xa4
	ex.mul
	ex.push r10
	ex.push r11
	ex.xor
	ex.push 0x60
	ex.mul
	ex.xor
	ex.push 0x7a
	ex.mul
	ex.push 0x30
	ex.xor
	ex.eqz
	mov r0, 0x24
	mov r8, rom[r0]
	mov r0, 0x18
	mov r9, rom[r0]
	mov r0, 0xe
	mov r10, rom[r0]
	mov r0, 0x1a
	mov r11, rom[r0]
	ex.push r8
	ex.push r9
	ex.add
	ex.push 0xc5
	ex.mul
	ex.push r10
	ex.push r11
	ex.mul
	ex.push 0x4d
	ex.xor
	ex.xor
	ex.push 0xfd
	ex.mul
	ex.push 0x95
	ex.xor
	ex.eqz
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.and
	ex.pop r8
	jump LAB_1daf

LAB_1da6:
	mov r8, 0x0
LAB_1daf:
	ret

parent_program_cont:
	mov r0, 0x2004
	mov r0, mem[r0]
	mov r1, 0xffffffff
	and r0, r1
	mov r1, 0x2010
	store mem[r1], r0
	mov r0, 0x2008
	mov r0, mem[r0]
	mov r1, 0xffffffff
	and r0, r1
	mov r1, 0x2018
	store mem[r1], r0
	mov r8, 0x140e0
	add r8, rexe
	call read_ptr

	mov r1, 0x2020
	store mem[r1], r8
get_flag:
	mov r8, str_flag ; 0x2bf6
	mov r9, str_checking ; 0x2bfc
	call write_stdout

	mov r8, 0x0
	mov r9, 0x0
	mov r0, 0x2020
	mov r10, mem[r0]
	mov r11, 0x60
	call syscall ; SYS_read

	mov r0, 0x1
	jumpeq r8, r0, exit_parent

	mov r1, 0x2028
	store mem[r1], r8
	mov r8, 0x1
	mov r0, 0x2010
	mov r9, mem[r0]
	mov r10, rexe
	mov r0, 0x6088
	add r10, r0
	mov r11, 0x8
	call syscall ; SYS_write

	mov r8, 0x1
	mov r0, 0x2010
	mov r9, mem[r0]
	mov r0, 0x2020
	mov r10, mem[r0]
	mov r1, 0x2028
	mov r11, mem[r1]
	call syscall ; SYS_write

	mov r8, str_checking ; 0x2bfc
	mov r9, str_wrong ; 0x2c08
	call write_stdout

	mov r8, 0x0
	mov r0, 0x2018
	mov r9, mem[r0]
	mov r0, 0x2020
	mov r10, mem[r0]
	mov r11, 0x1
	call syscall ; SYS_read

	mov r0, 0x2020
	mov r8, mem[r0]
	call read_ptr

	mov r0, 0xff
	and r8, r0
	mov r0, 0x1
	jumpeq r8, r0, LAB_2054

	mov r8, str_wrong ; 0x2c08
	mov r9, str_correct ; 0x2c0f
	call write_stdout

	jump get_flag

LAB_2054:
	mov r8, str_correct ; 0x2c0f
	mov r9, 0x2c18
	call write_stdout

exit_parent:
	ret

close_ptr:
	mov r0, r8
	mov r0, mem[r0]
	mov r1, 0xffffffff
	and r0, r1
	mov r8, 0x3
	mov r9, r0
	call syscall ; SYS_close

	ret

close:
	mov r9, r8
	mov r8, 0x3
	call syscall ; SYS_close

	ret

memcpy_qword:
	mov r11, 0x0
LAB_211b:
	push r11
	push r10
	push r8
	push r9
	mov r8, r9
	call read_ptr

	mov r10, r8
	pop r9
	pop r8
	push r8
	push r9
	mov r9, r10
	call write_ptr

	pop r9
	pop r8
	mov r0, 0x8
	add r8, r0
	mov r0, 0x8
	add r9, r0
	pop r10
	pop r11
	mov r0, 0x1
	add r11, r0
	jumpeq r11, r10, LAB_222f

	jump LAB_211b

LAB_222f:
	ret

init_seccomp:
	mov r8, 0x9d
	mov r9, 0x26
	mov r10, 0x1
	mov r11, 0x0
	mov r12, 0x0
	mov r13, 0x0
	call syscall ; SYS_prctl

	mov r0, DAT_seccomp ; 0x29d3
	mov r1, DAT_2a23 ; 0x2a23
	sub r1, r0
	mov r0, 0x3
	shr r1, r0
	mov r0, 0x1000
	store mem[r0], r1
	mov r8, rexe
	mov r0, 0x140e0
	add r8, r0
	call read_ptr

	mov r0, DAT_seccomp ; 0x29d3
	add r8, r0
	mov r0, 0x1008
	store mem[r0], r8
	mov r8, 0x9d
	mov r9, 0x16
	mov r10, 0x2
	mov r11, rexe
	mov r0, 0x5060
	add r11, r0
	call syscall ; SYS_prctl

	ret

syscall:
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
	mov r4, ROP_syscall ; 0x287b
	call execute_rop

	ret

read_ptr:
	mov r0, 0x8008
	store mem[r0], r8
	mov r0, 0x8018
	store mem[r0], r8
	mov r4, ROP_read_ptr ; 0x2953
	call execute_rop

	ret

write_ptr:
	mov r0, 0x8008
	store mem[r0], r9
	mov r0, 0x8020
	store mem[r0], r8
	mov r4, ROP_write_ptr ; 0x299b
	call execute_rop

	ret

write_stdout:
	sub r9, r8
	push r9
	push r8
	mov r8, 0x140e0
	add r8, rexe
	call read_ptr

	pop r10
	add r10, r8
	pop r11
	mov r8, 0x1
	mov r9, 0x1
	call syscall ; SYS_write

	ret

execute_rop:
	mov r5, r4
	mov r4, 0x8000
	call magic_copy

	mov r5, ROP_continue_loop ; 0x27f3
	call magic_copy

	call FUNC_27b3

	halt
	ret

init:
	mov rlibc, 0x30
	mov rexe, 0x0
	sub rexe, rlibc
	mov rlibc, mem[rexe]
	mov r0, 0x1eb980
	sub rlibc, r0
	mov r0, 0x1ef2e0
	mov rexe, rlibc
	add rexe, r0
	mov r0, 0x1150
	mov r1, 0x0
	sub r1, r0
	mov r4, rom[r1]
	mov r0, 0x1100
	add r4, r0
	mov r0, rexe
	sub r0, r4
	mov r5, rom[r0]
	mov r0, 0xe8
	mov r6, r5
	sub r6, r0
	mov r0, r6
	sub r0, r4
	mov r6, rom[r0]
	mov r0, 0x1229
	sub r6, r0
	mov r7, r5
	mov r0, 0x108
	sub r7, r0
	mov rexe, r6
	mov r4, r7
	call init_set_stack

	mov r4, 0x8000
	mov r5, ROP_continue_loop ; 0x27f3
	call magic_copy

	halt
	ret

magic_copy:
	push r6
	push r7
LAB_2681:
	mov r0, rom[r5]
	mov r1, 0x676e614765636944
	xor r0, r1
	mov r1, 0xdeadbeefdeadbeef
	jumpeq r0, r1, LAB_2745

	mov r6, r0
	mov r7, r0
	mov r0, 0xffffffffffffff
	and r6, r0
	mov r0, 0x38
	shr r7, r0
	mov r0, 0x0
	jumpeq r7, r0, LAB_26fd

	mov r0, 0x34
	jumpeq r7, r0, LAB_2708

	mov r0, 0x56
	jumpeq r7, r0, LAB_2717

	jump LAB_2726

LAB_26fd:
	store mem[r4], r6
	jump LAB_2726

LAB_2708:
	mov r0, rlibc
	add r0, r6
	store mem[r4], r0
	jump LAB_2726

LAB_2717:
	mov r0, rexe
	add r0, r6
	store mem[r4], r0
	jump LAB_2726

LAB_2726:
	mov r0, 0x8
	add r5, r0
	mov r0, 0x8
	add r4, r0
	jump LAB_2681

LAB_2745:
	pop r7
	pop r6
	ret

init_set_stack:
	mov r9, r4
	sub r9, rexe
	mov r0, 0x4060
	sub r9, r0
	mov r0, rlibc
	mov r1, 0x32b5a
	add r0, r1
	store mem[r9], r0
	mov r0, 0x8
	add r9, r0
	mov r10, rexe
	mov r0, 0xc060
	add r10, r0
	store mem[r9], r10
	ret

FUNC_27b3:
	mov r10, 0x7fa8
	mov r0, rlibc
	mov r1, 0x32b5a
	add r0, r1
	store mem[r10], r0
	mov r0, 0x8
	add r10, r0
	mov r11, rexe
	mov r0, 0xc060
	add r11, r0
	store mem[r10], r11
	ret


ROP_continue_loop:
	.mlibc 0x4a550 ; pop rax ; ret
	.mexe  0x193b
	.mlibc 0x26b72 ; pop rdi ; ret
	.mexe  0x4048
	.mlibc 0x9f822 ; pop rcx ; ret
	.mraw  0x0
	.mlibc 0xba056 ; mov qword ptr [rdi], rcx ; ret
	.mlibc 0x26b72 ; pop rdi ; ret
	.mexe  0xc060
	.mlibc 0x9f822 ; pop rcx ; ret
	.mlibc 0x270b1 ; call rax
	.mlibc 0xba056 ; mov qword ptr [rdi], rcx ; ret
	.mlibc 0x256c0 ; pop rbp ; ret
	.mexe  0xc000
	.mlibc 0x32b5a ; pop rsp ; ret
	.mexe  0xc060
	.magicend

ROP_syscall:
	.mlibc 0x1056fd ; pop rdx ; pop rcx ; pop rbx ; ret
	.munchanged ; offset 0x8
	.munchanged ; offset 0x10
	.munchanged ; offset 0x18
	.mlibc 0x4a550 ; pop rax ; ret
	.mlibc 0x25679 ; ret
	.mlibc 0x7b0cb ; mov r10, rdx ; jmp rax
	.mlibc 0x11fdaa ; mov r8, rbx ; mov rax, r8 ; pop rbx ; ret
	.munchanged ; offset 0x40
	.mlibc 0x4a550 ; pop rax ; ret
	.munchanged ; offset 0x50
	.mlibc 0x26b72 ; pop rdi ; ret
	.munchanged ; offset 0x60
	.mlibc 0x27529 ; pop rsi ; ret
	.munchanged ; offset 0x70
	.mlibc 0x1056fd ; pop rdx ; pop rcx ; pop rbx ; ret
	.munchanged ; offset 0x80
	.munchanged ; offset 0x88
	.munchanged ; offset 0x90
	.mlibc 0x66229 ; syscall
	.mlibc 0x331ff ; pop rbx ; ret
	.mexe  0x140a0
	.mlibc 0x162d94 ; mov qword ptr [rbx], rax ; pop rax ; pop rdx ; pop rbx ; ret
	.mraw  0x0
	.mraw  0x0
	.mraw  0x0
	.magicend

ROP_read_ptr:
	.mlibc 0x27529 ; pop rsi ; ret
	.munchanged ; offset 0x8
	.mlibc 0x26b72 ; pop rdi ; ret
	.munchanged ; offset 0x18
	.mlibc 0xba040 ; mov rdx, qword ptr [rsi] ; mov qword ptr [rdi], rdx ; ret
	.mlibc 0x26b72 ; pop rdi ; ret
	.mexe  0x140a0
	.mlibc 0x4514d ; mov qword ptr [rdi], rdx ; ret
	.magicend

ROP_write_ptr:
	.mlibc 0x162866 ; pop rdx ; pop rbx ; ret
	.munchanged ; offset 0x8
	.munchanged ; offset 0x10
	.mlibc 0x26b72 ; pop rdi ; ret
	.munchanged ; offset 0x20
	.mlibc 0x4514d ; mov qword ptr [rdi], rdx ; ret
	.magicend

DAT_seccomp:
	.db 0x20
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x4
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x15
	.db 0x0
	.db 0x0
	.db 0x7
	.db 0x3e ; >
	.db 0x0
	.db 0x0
	.db 0xc0
	.db 0x20
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x35 ; 5
	.db 0x0
	.db 0x5
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x40 ; @
	.db 0x15
	.db 0x0
	.db 0x3
	.db 0x0
	.db 0x1
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x15
	.db 0x0
	.db 0x2
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x15
	.db 0x0
	.db 0x1
	.db 0x0
	.db 0x3c ; <
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x6
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x5
	.db 0x0
	.db 0x5
	.db 0x0
	.db 0x6
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0xff
	.db 0x7f
	.db 0x6
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x0

DAT_2a23:
	.db 0xe8
	.db 0x5
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0xe9
	.db 0x31 ; 1
	.db 0xff
	.db 0xff
	.db 0xff
	.db 0x48 ; H
	.db 0x8b
	.db 0x5
	.db 0x2f ; /
	.db 0x26 ; &
	.db 0x0
	.db 0x0
	.db 0x48 ; H
	.db 0x8d
	.db 0x1d
	.db 0xc8
	.db 0x26 ; &
	.db 0x1
	.db 0x0
	.db 0x48 ; H
	.db 0x8b
	.db 0x1b
	.db 0x48 ; H
	.db 0x1
	.db 0xd8
	.db 0x8a
	.db 0x18
	.db 0x48 ; H
	.db 0xf
	.db 0xb6
	.db 0xdb
	.db 0x8a
	.db 0x48 ; H
	.db 0x1
	.db 0x4c ; L
	.db 0x8d
	.db 0x5
	.db 0x32 ; 2
	.db 0x26 ; &
	.db 0x0
	.db 0x0
	.db 0x49 ; I
	.db 0x81
	.db 0xc0
	.db 0x0
	.db 0x30 ; 0
	.db 0x0
	.db 0x0
	.db 0x49 ; I
	.db 0x8b
	.db 0x10
	.db 0xc0
	.db 0xeb
	.db 0x4
	.db 0x80
	.db 0xfb
	.db 0x0
	.db 0x74 ; t
	.db 0x45 ; E
	.db 0x80
	.db 0xfb
	.db 0x1
	.db 0x74 ; t
	.db 0x67 ; g
	.db 0x80
	.db 0xfb
	.db 0x2
	.db 0x74 ; t
	.db 0x7a ; z
	.db 0x80
	.db 0xfb
	.db 0x3
	.db 0xf
	.db 0x84
	.db 0x9d
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x80
	.db 0xfb
	.db 0x4
	.db 0xf
	.db 0x84
	.db 0xc0
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x80
	.db 0xfb
	.db 0x5
	.db 0xf
	.db 0x84
	.db 0xe0
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x80
	.db 0xfb
	.db 0x6
	.db 0xf
	.db 0x84
	.db 0xf2
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x80
	.db 0xfb
	.db 0x7
	.db 0xf
	.db 0x84
	.db 0x12
	.db 0x1
	.db 0x0
	.db 0x0
	.db 0x80
	.db 0xfb
	.db 0x8
	.db 0xf
	.db 0x84
	.db 0x30 ; 0
	.db 0x1
	.db 0x0
	.db 0x0
	.db 0xe9
	.db 0x33 ; 3
	.db 0x1
	.db 0x0
	.db 0x0
	.db 0x48 ; H
	.db 0x8d
	.db 0x5
	.db 0xd4
	.db 0x25 ; %
	.db 0x1
	.db 0x0
	.db 0xc0
	.db 0xe1
	.db 0x3
	.db 0x48 ; H
	.db 0x1
	.db 0xc8
	.db 0x8a
	.db 0x0
	.db 0x48 ; H
	.db 0x8d
	.db 0x1d
	.db 0xc5
	.db 0x25 ; %
	.db 0x0
	.db 0x0
	.db 0x48 ; H
	.db 0x1
	.db 0xd3
	.db 0x88
	.db 0x3
	.db 0x48 ; H
	.db 0x83
	.db 0xc2
	.db 0x1
	.db 0x49 ; I
	.db 0x89
	.db 0x10
	.db 0xe9
	.db 0xc
	.db 0x1
	.db 0x0
	.db 0x0
	.db 0x48 ; H
	.db 0x8d
	.db 0x1d
	.db 0xad
	.db 0x25 ; %
	.db 0x0
	.db 0x0
	.db 0x48 ; H
	.db 0x1
	.db 0xd3
	.db 0x88
	.db 0xb
	.db 0x48 ; H
	.db 0x83
	.db 0xc2
	.db 0x1
	.db 0x49 ; I
	.db 0x89
	.db 0x10
	.db 0xe9
	.db 0xf4
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x48 ; H
	.db 0x8d
	.db 0x5
	.db 0x94
	.db 0x25 ; %
	.db 0x0
	.db 0x0
	.db 0x48 ; H
	.db 0x8d
	.db 0x1d
	.db 0x8c
	.db 0x25 ; %
	.db 0x0
	.db 0x0
	.db 0x8a
	.db 0x4
	.db 0x10
	.db 0x8a
	.db 0x1c
	.db 0x13
	.db 0x0
	.db 0xd8
	.db 0x48 ; H
	.db 0x8d
	.db 0x1d
	.db 0x7d ; }
	.db 0x25 ; %
	.db 0x0
	.db 0x0
	.db 0x88
	.db 0x4
	.db 0x13
	.db 0x48 ; H
	.db 0x83
	.db 0xea
	.db 0x1
	.db 0x49 ; I
	.db 0x89
	.db 0x10
	.db 0xe9
	.db 0xc8
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x48 ; H
	.db 0x8d
	.db 0x5
	.db 0x68 ; h
	.db 0x25 ; %
	.db 0x0
	.db 0x0
	.db 0x48 ; H
	.db 0x8d
	.db 0x1d
	.db 0x60 ; `
	.db 0x25 ; %
	.db 0x0
	.db 0x0
	.db 0x8a
	.db 0x4
	.db 0x10
	.db 0x8a
	.db 0x1c
	.db 0x13
	.db 0xf6
	.db 0xe3
	.db 0x48 ; H
	.db 0x8d
	.db 0x1d
	.db 0x51 ; Q
	.db 0x25 ; %
	.db 0x0
	.db 0x0
	.db 0x88
	.db 0x4
	.db 0x13
	.db 0x48 ; H
	.db 0x83
	.db 0xea
	.db 0x1
	.db 0x49 ; I
	.db 0x89
	.db 0x10
	.db 0xe9
	.db 0x9c
	.db 0x0
	.db 0x0
	.db 0x0
	.db 0x48 ; H
	.db 0x8d
	.db 0x5
	.db 0x3c ; <
	.db 0x25 ; %
	.db 0x0
	.db 0x0
	.db 0x48 ; H
	.db 0x8d
	.db 0x1d
	.db 0x34 ; 4
	.db 0x25 ; %
	.db 0x0
	.db 0x0
	.db 0x8a
	.db 0x4
	.db 0x10
	.db 0x8a
	.db 0x1c
	.db 0x13
	.db 0x30 ; 0
	.db 0xd8
	.db 0x48 ; H
	.db 0x8d
	.db 0x1d
	.db 0x25 ; %
	.db 0x25 ; %
	.db 0x0
	.db 0x0
	.db 0x88
	.db 0x4
	.db 0x13
	.db 0x48 ; H
	.db 0x83
	.db 0xea
	.db 0x1
	.db 0x49 ; I
	.db 0x89
	.db 0x10
	.db 0xeb
	.db 0x73 ; s
	.db 0x48 ; H
	.db 0x8d
	.db 0x5
	.db 0x13
	.db 0x25 ; %
	.db 0x0
	.db 0x0
	.db 0x8a
	.db 0x4
	.db 0x10
	.db 0x84
	.db 0xc0
	.db 0xf
	.db 0x94
	.db 0xc0
	.db 0x48 ; H
	.db 0x8d
	.db 0x1d
	.db 0x4
	.db 0x25 ; %
	.db 0x0
	.db 0x0
	.db 0x88
	.db 0x4
	.db 0x13
	.db 0xeb
	.db 0x58 ; X
	.db 0x48 ; H
	.db 0x8d
	.db 0x5
	.db 0xf8
	.db 0x24 ; $
	.db 0x0
	.db 0x0
	.db 0x48 ; H
	.db 0x8d
	.db 0x1d
	.db 0xf0
	.db 0x24 ; $
	.db 0x0
	.db 0x0
	.db 0x8a
	.db 0x4
	.db 0x10
	.db 0x8a
	.db 0x1c
	.db 0x13
	.db 0x20
	.db 0xd8
	.db 0x48 ; H
	.db 0x8d
	.db 0x1d
	.db 0xe1
	.db 0x24 ; $
	.db 0x0
	.db 0x0
	.db 0x88
	.db 0x4
	.db 0x13
	.db 0x48 ; H
	.db 0x83
	.db 0xea
	.db 0x1
	.db 0x49 ; I
	.db 0x89
	.db 0x10
	.db 0xeb
	.db 0x2f ; /
	.db 0x48 ; H
	.db 0x8d
	.db 0x5
	.db 0xcf
	.db 0x24 ; $
	.db 0x0
	.db 0x0
	.db 0x8a
	.db 0x4
	.db 0x10
	.db 0x48 ; H
	.db 0xf
	.db 0xb6
	.db 0xc0
	.db 0x48 ; H
	.db 0x8d
	.db 0x1d
	.db 0xc2
	.db 0x24 ; $
	.db 0x1
	.db 0x0
	.db 0xc0
	.db 0xe1
	.db 0x3
	.db 0x48 ; H
	.db 0x1
	.db 0xcb
	.db 0x48 ; H
	.db 0x89
	.db 0x3
	.db 0x48 ; H
	.db 0x83
	.db 0xea
	.db 0x1
	.db 0x49 ; I
	.db 0x89
	.db 0x10
	.db 0xeb
	.db 0x8
	.db 0xb8
	.db 0x8
	.db 0x30 ; 0
	.db 0x0
	.db 0x0
	.db 0x49 ; I
	.db 0x89
	.db 0x0
	.db 0x48 ; H
	.db 0x8b
	.db 0x5
	.db 0x81
	.db 0x24 ; $
	.db 0x0
	.db 0x0
	.db 0x48 ; H
	.db 0x83
	.db 0xc0
	.db 0x2
	.db 0x48 ; H
	.db 0x89
	.db 0x5
	.db 0x76 ; v
	.db 0x24 ; $
	.db 0x0
	.db 0x0
	.db 0xc3
	.db 0x90
	.db 0x90
	.db 0x90
	.db 0x90
	.db 0x90
	.db 0x90
	.db 0x90
	.db 0x90

str_flag:
	.db 0x46 ; F
	.db 0x6c ; l
	.db 0x61 ; a
	.db 0x67 ; g
	.db 0x3a ; :
	.db 0x20

str_checking:
	.db 0x43 ; C
	.db 0x68 ; h
	.db 0x65 ; e
	.db 0x63 ; c
	.db 0x6b ; k
	.db 0x69 ; i
	.db 0x6e ; n
	.db 0x67 ; g
	.db 0x2e ; .
	.db 0x2e ; .
	.db 0x2e ; .
	.db 0xa

str_wrong:
	.db 0x57 ; W
	.db 0x72 ; r
	.db 0x6f ; o
	.db 0x6e ; n
	.db 0x67 ; g
	.db 0x21 ; !
	.db 0xa

str_correct:
	.db 0x43 ; C
	.db 0x6f ; o
	.db 0x72 ; r
	.db 0x72 ; r
	.db 0x65 ; e
	.db 0x63 ; c
	.db 0x74 ; t
	.db 0x21 ; !
	.db 0xa
