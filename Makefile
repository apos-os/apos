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
CFLAGS	= -Wall -Wextra -Werror -nostdlib -ffreestanding -nostartfiles -nodefaultlibs -std=gnu99 -g -I. \
	  -Wno-unused-parameter -Wno-error=unused-function \
	  -DENABLE_KERNEL_SAFETY_NETS=1
LD	= i586-elf-ld

BOOTLOADER	= grub
 
OBJFILES = load/multiboot.o load/loader.o load/gdt.o load/gdt_flush.o load/mem_init.o load/kernel_init.o load/idt.o \
	   common/kstring.o common/kassert.o common/klog.o common/kprintf.o common/io.o \
	   common/errno.o common/hashtable.o common/builtins.o \
	   dev/interrupts.o dev/ps2.o dev/irq.o dev/timer.o dev/isr.o dev/rtc.o \
	   dev/keyboard/ps2_keyboard.o dev/keyboard/ps2_scancodes.o dev/keyboard/keyboard.o \
	   dev/video/vga.o dev/video/vterm.o dev/ld.o dev/pci/pci.o dev/pci/piix.o \
	   dev/ata/ata.o dev/ata/dma.o \
	   dev/ramdisk/ramdisk.o \
	   proc/kthread.o proc/kthread_asm.o proc/scheduler.o proc/process.o \
	   proc/sleep.o proc/kthread_pool.o \
	   memory.o page_alloc.o kernel.o kmalloc.o page_fault.o slab_alloc.o \
	   test/ktest.o test/ktest_test.o test/kstring_test.o test/kprintf_test.o test/interrupt_test.o \
	   test/kmalloc_test.o test/kthread_test.o test/page_alloc_map_test.o test/page_alloc_test.o \
	   test/ld_test.o test/hashtable_test.o test/ramdisk_test.o \
	   test/block_dev_test.o test/ata_test.o test/slab_alloc_test.o \
	   test/kthread_pool_test.o test/flag_printf_test.o \
	   util/flag_printf.o \
	   kshell.o

FIND_FLAGS = '(' -name '*.c' -or -name '*.h' ')' -and -not -path './bochs/*'
ALLFILES = $(shell find $(FIND_FLAGS))
HDRFILES = $(filter %.h, $(ALLFILES))

BUILD_DIR = build
 
HD_IMAGES = hd1.img hd2.img hd3.img hd4.img

all: kernel.img $(HD_IMAGES) tags
 
%.o : %.s
	$(AS) $(ASFLAGS) -o $@ $<

%.o : %.c $(HDRFILES)
	$(CC) $(CFLAGS) -o $@ -c $<
 
kernel.bin: $(OBJFILES) $(BUILD_DIR)/linker.ld
	$(LD) -T $(BUILD_DIR)/linker.ld -o $@ $(filter-out %.ld, $^)

kernel.img: kernel.bin grub/menu.lst $(BUILD_DIR)/kernel.img.base
	cp $(BUILD_DIR)/kernel.img.base $@
	mcopy -i $@ grub/menu.lst ::/boot/grub/menu.lst 
	mcopy -i $@ kernel.bin ::/

$(HD_IMAGES):
	@echo 'generating hard drive image...'
	@./bochs/bximage -hd -mode=flat -size=10 -q hd1.img
	cp hd1.img hd2.img
	cp hd1.img hd3.img
	cp hd1.img hd4.img

clean:
	$(RM) $(OBJFILES) kernel.bin kernel.img $(HD_IMAGES) tags

run: all
	./bochs/bochs -q -f $(BUILD_DIR)/bochsrc.txt

runx: all
	./bochs/bochs -q -f $(BUILD_DIR)/bochsrc.txt.x11

gdb: kernel.bin all
	./bochs/bochs_gdb -q -f $(BUILD_DIR)/bochsrc.txt.gdb

tags: $(ALLFILES)
	@echo 'generating tags...'
	@find $(FIND_FLAGS) | ctags -L - --languages=all
	@echo 'generated' `wc -l tags | cut -d ' ' -f 1` 'tags'
