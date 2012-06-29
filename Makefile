# Copyright 2014 Andrew Oates.  All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

AS	= i586-elf-as
ASFLAGS = --gen-debug
CC	= i586-elf-gcc
CFLAGS	= -Wall -Wextra -nostdlib -ffreestanding -nostartfiles -nodefaultlibs -std=c99 -g -I.
LD	= i586-elf-ld

BOOTLOADER	= grub
 
OBJFILES = load/multiboot.o load/loader.o load/gdt.o load/gdt_flush.o load/mem_init.o load/kernel_init.o load/idt.o \
	   common/kstring.o common/kassert.o common/klog.o common/kprintf.o common/io.o \
	   memory.o page_alloc.o kernel.o kmalloc.o interrupts.o isr.o ps2.o irq.o timer.o \
	   test/ktest.o test/ktest_test.o test/kstring_test.o test/kprintf_test.o test/interrupt_test.o

HDRFILES = $(wildcard *.h) $(wildcard load/*.h) $(wildcard test/*.h)
 
all: kernel.img
 
%.o : %.s
	$(AS) $(ASFLAGS) -o $@ $<

%.o : %.c $(HDRFILES)
	$(CC) $(CFLAGS) -o $@ -c $<
 
kernel.bin: $(OBJFILES) linker.ld
	$(LD) -T linker.ld -o $@ $^

kernel.img: kernel.bin grub/menu.lst kernel.img.base
	cp kernel.img.base $@
	mcopy -i $@ grub/menu.lst ::/boot/grub/menu.lst 
	mcopy -i $@ kernel.bin ::/
 
clean:
	$(RM) $(OBJFILES) kernel.bin kernel.img pad.tmp

run: kernel.img
	./bochs/bochs -q

runx: kernel.img
	./bochs/bochs -q -f bochsrc.txt.x11

gdb: kernel.bin kernel.img
	./bochs/bochs_gdb -q -f bochsrc.txt.gdb
