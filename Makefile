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
CFLAGS	= -Wall -Wextra -Werror -nostdlib -ffreestanding -nostartfiles -nodefaultlibs -std=c99 -g -I.
LD	= i586-elf-ld

BOOTLOADER	= grub
 
OBJFILES = load/multiboot.o load/loader.o load/gdt.o load/gdt_flush.o load/mem_init.o load/kernel_init.o load/idt.o \
	   common/kstring.o common/kassert.o common/klog.o common/kprintf.o common/io.o \
	   dev/interrupts.o dev/ps2.o dev/irq.o dev/timer.o dev/isr.o \
	   dev/keyboard/ps2_keyboard.o dev/keyboard/ps2_scancodes.o dev/keyboard/keyboard.o \
	   dev/video/vga.o dev/video/vterm.o \
	   memory.o page_alloc.o kernel.o kmalloc.o \
	   test/ktest.o test/ktest_test.o test/kstring_test.o test/kprintf_test.o test/interrupt_test.o test/kmalloc_test.o

HDRFILES = $(wildcard *.h) $(wildcard load/*.h) $(wildcard test/*.h)

BUILD = build
 
all: kernel.img
 
%.o : %.s
	$(AS) $(ASFLAGS) -o $@ $<

%.o : %.c $(HDRFILES)
	$(CC) $(CFLAGS) -o $@ -c $<
 
kernel.bin: $(OBJFILES) $(BUILD)/linker.ld
	$(LD) -T $(BUILD)/linker.ld -o $@ $^

kernel.img: kernel.bin grub/menu.lst $(BUILD)/kernel.img.base
	cp $(BUILD)/kernel.img.base $@
	mcopy -i $@ grub/menu.lst ::/boot/grub/menu.lst 
	mcopy -i $@ kernel.bin ::/
 
clean:
	$(RM) $(OBJFILES) kernel.bin kernel.img tags

run: kernel.img
	./bochs/bochs -q -f $(BUILD)/bochsrc.txt

runx: kernel.img
	./bochs/bochs -q -f $(BUILD)/bochsrc.txt.x11

gdb: kernel.bin kernel.img
	./bochs/bochs_gdb -q -f $(BUILD)/bochsrc.txt.gdb
