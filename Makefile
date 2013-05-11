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
CFLAGS	= -Wall -Wextra -Werror -nostdlib -ffreestanding -std=gnu11 -g -I. \
	  -Wno-unused-parameter -Wno-error=unused-function \
	  -DENABLE_KERNEL_SAFETY_NETS=1
LD	= i586-elf-ld
M4      = m4
M4FLAGS =
M4_DEPS = util/m4_deps.sh
BUILD_OUT 	= build-out

BOOTLOADER	= grub

HD_IMAGES = hd1.img hd2.img hd3.img hd4.img

all: kernel.img $(HD_IMAGES)

# Macros for Sources.mk.
define SOURCES_SUBDIR
  DIR := /$(1)
  include $(SRC_PATH)$$(DIR)/Sources.mk
endef

define BEGIN_SOURCES
  SP := $(SP).x
  SRC_PATH_IN_$$(SP) := $(SRC_PATH)
  LOCAL_SOURCES_IN_$$(SP) := $(LOCAL_SOURCES)
  SRC_PATH := $(SRC_PATH)$(DIR)
  LOCAL_SOURCES :=
endef

define END_SOURCES
  SOURCES += $(patsubst %,$(SRC_PATH)/%,$(LOCAL_SOURCES))
  SRC_PATH := $(SRC_PATH_IN_$(SP))
  LOCAL_SOURCES := $(LOCAL_SOURCES_IN_$(SP))
  SP := $(basename $(SP))
endef

# Build master $(SOURCES) list.
LOCAL_SOURCES :=
SOURCES :=
SP :=
include Sources.mk

C_SOURCES = $(filter %.c,$(SOURCES))
ASM_SOURCES = $(filter %.s,$(SOURCES))
OBJFILES = $(patsubst %,$(BUILD_OUT)/%,$(C_SOURCES:.c=.o) $(ASM_SOURCES:.s=.o))

# Object files that are placed manually in the linker script.
MANUALLY_LINKED_OBJS = $(patsubst %,$(BUILD_OUT)/%, \
		       load/multiboot.o load/loader.o load/mem_init.o \
		       load/gdt.o load/idt.o \
		       memory/gdt.PHYS.o \
		       main/user_main.o \
		       user/fs.o user/syscall.o user/test.o)

FIND_FLAGS = '(' -name '*.c' -or -name '*.h' ')' -and -not -path './bochs/*'
ALLFILES = $(shell find $(FIND_FLAGS))

BUILD_DIR = build

# Clang- and GCC-specific flags.
ifeq ($(CC),clang)
  CFLAGS += -march=i586 -DSUPPORTS_GENERIC_MACROS

  # Various tests use self assignment as a no-op to appease the compiler.
  $(BUILD_OUT)/test/%.o: CFLAGS += -Wno-self-assign
else
  CFLAGS += -nostartfiles -nodefaultlibs
endif

$(MANUALLY_LINKED_OBJS): CFLAGS += -D_MULTILINK_SUFFIX=_PHYS

mk-build-dir = @mkdir -p $(dir $@)

# Preserve the output of generated source files.
.PRECIOUS : $(BUILD_OUT)/%.m4.c $(BUILD_OUT)/%.tpl.c

$(BUILD_OUT)/%.m4.c : %.m4
	$(mk-build-dir)
	$(M4) $(M4FLAGS) $< > $@

$(BUILD_OUT)/%.tpl.c : %.tpl
	$(mk-build-dir)
	util/tpl_gen.py $< > $@

$(BUILD_OUT)/%.o : %.s
	$(mk-build-dir)
	$(AS) $(ASFLAGS) -o $@ $<

$(BUILD_OUT)/%.o : %.c
	$(mk-build-dir)
	$(CC) $(CFLAGS) -o $@ -c $<

# Autogenerated source files.
$(BUILD_OUT)/%.o : $(BUILD_OUT)/%.c
	$(mk-build-dir)
	$(CC) $(CFLAGS) -o $@ -c $<

$(BUILD_OUT)/%.PHYS.o : %.c
	$(mk-build-dir)
	$(CC) $(CFLAGS) -D_MULTILINK_SUFFIX=_PHYS -o $@ -c $<
 
kernel.bin: $(OBJFILES) $(MANUALLY_LINKED_OBJS) $(BUILD_DIR)/linker.ld
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
$(BUILD_OUT)/%.m4.d : %.m4
	@echo Generating dependency list for $<
	$(mk-build-dir)
	@$(M4_DEPS) $< | \
	  sed 's,^\($<\):,$(dir $@)$(notdir $<).c $@ :,' \
	  > $@
$(BUILD_OUT)/%.tpl.d : %.tpl
	@echo Generating dependency list for $<
	$(mk-build-dir)
	@util/tpl_deps.sh $< | \
	  sed 's,^\($<\):,$(dir $@)$(notdir $<).c $@ :,' \
	  > $@
DEPSFILES = $(patsubst %.c,$(BUILD_OUT)/%.d,$(C_SOURCES))
-include $(DEPSFILES)

clean:
	$(RM) $(OBJFILES) $(DEPSFILES) kernel.bin kernel.img $(HD_IMAGES)

run: all
	./bochs/bochs -q -f $(BUILD_DIR)/bochsrc.txt

runx: all
	./bochs/bochs -q -f $(BUILD_DIR)/bochsrc.txt.x11

gdb: kernel.bin all
	./bochs/bochs_gdb -q -f $(BUILD_DIR)/bochsrc.txt.gdb
