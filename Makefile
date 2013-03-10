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
BUILD_OUT 	= build-out

BOOTLOADER	= grub
 
SOURCES = load/multiboot.s load/loader.s load/gdt.c load/gdt_flush.s load/mem_init.c load/kernel_init.c load/idt.c \
	  common/kstring.c common/kassert.c common/klog.c common/kprintf.c common/io.c \
	  common/errno.c common/hashtable.c common/builtins.c \
	  dev/interrupts.c dev/ps2.c dev/irq.c dev/timer.c dev/isr.s dev/rtc.c \
	  dev/keyboard/ps2_keyboard.c dev/keyboard/ps2_scancodes.c dev/keyboard/keyboard.c \
	  dev/video/vga.c dev/video/vterm.c dev/ld.c dev/pci/pci.c dev/pci/piix.c \
	  dev/pci/usb_uhci.c \
	  dev/ata/ata.c dev/ata/dma.c \
	  dev/ramdisk/ramdisk.c \
	  dev/usb/uhci/uhci.c dev/usb/uhci/uhci_cmd.c dev/usb/uhci/uhci_hub.c \
	  dev/usb/bus.c dev/usb/usb.c dev/usb/usb_driver.c dev/usb/request.c \
	  dev/usb/descriptor.c \
	  dev/usb/drivers/drivers.c \
	  dev/dev.c \
	  proc/kthread.c proc/kthread_asm.s proc/scheduler.c proc/process.c \
	  proc/sleep.c proc/kthread_pool.c \
	  memory/memory.c memory/page_alloc.c memory/kmalloc.c \
	  memory/page_fault.c memory/slab_alloc.c memory/block_cache.c \
	  memory/memobj_block_dev.c \
	  kernel.c \
	  vfs/vfs.c vfs/ramfs.c vfs/file.c vfs/util.c \
	  vfs/ext2/ext2.c vfs/ext2/ext2-internal.c vfs/ext2/ext2_ops.c \
	  vfs/ext2/ext2fs.c \
	  test/ktest.c test/ktest_test.c test/kstring_test.c test/kprintf_test.c test/interrupt_test.c \
	  test/kmalloc_test.c test/kthread_test.c test/page_alloc_map_test.c test/page_alloc_test.c \
	  test/ld_test.c test/hashtable_test.c test/ramdisk_test.c \
	  test/block_dev_test.c test/ata_test.c test/slab_alloc_test.c \
	  test/kthread_pool_test.c test/flag_printf_test.c \
	  test/ramfs_test.c test/vfs_test.c \
	  test/hash_test.c \
	  test/block_cache_test.c \
	  util/flag_printf.c \
	  kshell.c
C_SOURCES = $(filter %.c,$(SOURCES))
ASM_SOURCES = $(filter %.s,$(SOURCES))
OBJFILES = $(patsubst %,$(BUILD_OUT)/%,$(C_SOURCES:.c=.o) $(ASM_SOURCES:.s=.o))

# Object files that are placed manually in the linker script.
MANUALLY_LINKED_OBJS = $(patsubst %,$(BUILD_OUT)/%, \
		       load/multiboot.o load/loader.o load/mem_init.o \
		       load/gdt.o load/gdt_flush.o load/idt.o)

FIND_FLAGS = '(' -name '*.c' -or -name '*.h' ')' -and -not -path './bochs/*'
ALLFILES = $(shell find $(FIND_FLAGS))

BUILD_DIR = build
 
HD_IMAGES = hd1.img hd2.img hd3.img hd4.img

# Clang- and GCC-specific flags.
ifeq ($(CC),clang)
  CFLAGS += -march=i586

  # Various tests use self assignment as a no-op to appease the compiler.
  $(BUILD_OUT)/test/%.o: CFLAGS += -Wno-self-assign
else
  CFLAGS += -nostartfiles -nodefaultlibs
endif

all: kernel.img $(HD_IMAGES) tags

mk-build-dir = @mkdir -p $(dir $@)
 
$(BUILD_OUT)/%.o : %.s
	$(mk-build-dir)
	$(AS) $(ASFLAGS) -o $@ $<

$(BUILD_OUT)/%.o : %.c
	$(mk-build-dir)
	$(CC) $(CFLAGS) -o $@ -c $<
 
kernel.bin: $(OBJFILES) $(BUILD_DIR)/linker.ld
	$(LD) -T $(BUILD_DIR)/linker.ld -L $(BUILD_OUT) -o $@ \
	  $(filter-out %.ld $(MANUALLY_LINKED_OBJS), $^)

kernel.img: kernel.bin grub/menu.lst $(BUILD_DIR)/kernel.img.base
	cp $(BUILD_DIR)/kernel.img.base $@
	mcopy -i $@ grub/menu.lst ::/boot/grub/menu.lst 
	mcopy -i $@ kernel.bin ::/

hd1.img :
	@echo 'generating hard drive image...'
	@./bochs/bximage -hd -mode=flat -size=10 -q hd1.img

%.img : hd1.img
	cp $< $@

# Automatic dependency calculation.
$(BUILD_OUT)/%.d : %.c
	@echo Generating dependency list for $<
	$(mk-build-dir)
	@$(CC) $(CFLAGS) -MM $< | \
	  sed 's,^\($(notdir $*)\)\.o:,$(dir $@)\1.o $@ :,' \
	  > $@
DEPSFILES = $(patsubst %.c,$(BUILD_OUT)/%.d,$(C_SOURCES))
-include $(DEPSFILES)

clean:
	$(RM) $(OBJFILES) $(DEPSFILES) kernel.bin kernel.img $(HD_IMAGES) tags

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
