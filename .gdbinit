#set architecture i386:x86-64:intel
file kernel.bin
target remote localhost:1234

break die
break die_phys

# For some reason GDB insists on stopping at all page faults.  This will silently continue when that happens.
break int14
commands
silent
continue
end

set disassemble-next-line on
# try this: layout asm
