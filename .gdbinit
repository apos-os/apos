#set architecture i386:x86-64:intel
file kernel.bin
target remote localhost:1234

break die
break die_phys
break int_handler

set disassemble-next-line on
# try this: layout asm
