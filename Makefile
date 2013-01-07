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
ASFLAGS	= --gen-debug
CC	= i586-elf-gcc
CFLAGS	= -Wall -Wextra -Werror -nostdlib -ffreestanding -std=gnu99 -g -I. \
	  -Wno-unused-parameter -Wno-error=unused-function \
	  -DENABLE_KERNEL_SAFETY_NETS=1
LD	= i586-elf-ld

BOOTLOADER	= grub
 
SOURCES = load/multiboot.s load/loader.s load/gdt.c load/gdt_flush.s load/mem_init.c load/kernel_init.c load/idt.c \
	  common/kstring.c common/kassert.c common/klog.c common/kprintf.c common/io.c \
	  common/errno.c common/hashtable.c common/builtins.c \
	  dev/interrupts.c dev/ps2.c dev/irq.c dev/timer.c dev/isr.s dev/rtc.c \
	  dev/keyboard/ps2_keyboard.c dev/keyboard/ps2_scancodes.c dev/keyboard/keyboard.c \
	  dev/video/vga.c dev/video/vterm.c dev/ld.c dev/pci/pci.c dev/pci/piix.c \
	  dev/ata/ata.c dev/ata/dma.c \
	  dev/ramdisk/ramdisk.c \
	  proc/kthread.c proc/kthread_asm.s proc/scheduler.c proc/process.c \
	  proc/sleep.c proc/kthread_pool.c \
	  memory.c page_alloc.c kernel.c kmalloc.c page_fault.c slab_alloc.c \
	  test/ktest.c test/ktest_test.c test/kstring_test.c test/kprintf_test.c test/interrupt_test.c \
	  test/kmalloc_test.c test/kthread_test.c test/page_alloc_map_test.c test/page_alloc_test.c \
	  test/ld_test.c test/hashtable_test.c test/ramdisk_test.c \
	  test/block_dev_test.c test/ata_test.c test/slab_alloc_test.c \
	  test/kthread_pool_test.c test/flag_printf_test.c \
	  util/flag_printf.c \
	  kshell.c
C_SOURCES = $(filter %.c,$(SOURCES))
ASM_SOURCES = $(filter %.s,$(SOURCES))
OBJFILES = $(C_SOURCES:.c=.o) $(ASM_SOURCES:.s=.o)

FIND_FLAGS = '(' -name '*.c' -or -name '*.h' ')' -and -not -path './bochs/*'
ALLFILES = $(shell find $(FIND_FLAGS))
HDRFILES = $(filter %.h, $(ALLFILES))

BUILD_DIR = build
 
HD_IMAGES = hd1.img hd2.img hd3.img hd4.img

# Clang- and GCC-specific flags.
ifeq ($(CC),clang)
  CFLAGS += -march=i586
else
  CFLAGS += -nostartfiles -nodefaultlibs
endif

# Various tests use self assignment as a no-op to appease the compiler.
test/%.o: CFLAGS += -Wno-self-assign

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
