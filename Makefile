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

ARCH	= i586
TARGET_PREFIX 	= i586-pc-apos
AR	= $(TARGET_PREFIX)-ar
AS	= $(TARGET_PREFIX)-as
ASFLAGS	= --gen-debug
CC	= $(TARGET_PREFIX)-gcc
CFLAGS	= -Wall -Wextra -Werror -nostdlib -ffreestanding -std=gnu11 -g3 -I. \
	  -Wno-unused-parameter -Wno-error=unused-function -Wstrict-prototypes \
	  -DENABLE_KERNEL_SAFETY_NETS=1 \
	  -I archs/$(ARCH) -I archs/common
LD	= $(TARGET_PREFIX)-ld
M4      = m4
M4FLAGS =
M4_DEPS = util/m4_deps.sh
BUILD_OUT 	= build-out

BOOTLOADER	= grub

HD_IMAGES = hd1.img hd2.img hd3.img hd4.img

all: $(BUILD_OUT)/kernel.bin.stripped $(HD_IMAGES)

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

# Defines a tpl-generated file.
# Usage: ADD_TPL(tpl_path,out_path)
define ADD_TPL
GENERATED += $(2)
$(2) : $(1)
	$(mk-build-dir)
	util/tpl_gen.py $(1) > $(2)
$(BUILD_OUT)/$(2).d : $(1) util/tpl_deps.sh
	@echo Generating dependency list for $2
	$(mk-build-dir)
	@util/tpl_deps.sh $1 | \
	  sed 's,^\($1\):,$(BUILD_OUT)/$(2).d $2 : $1,' \
	  > $(BUILD_OUT)/$(2).d
endef

# Build master $(SOURCES) list.
LOCAL_SOURCES :=
SOURCES :=
SP :=
GENERATED :=
include Sources.mk

C_SOURCES = $(filter %.c,$(SOURCES))
ASM_SOURCES = $(filter %.s,$(SOURCES))
TPL_SOURCES = $(filter %.tpl.c,$(SOURCES))
OBJFILES = $(patsubst %,$(BUILD_OUT)/%,$(C_SOURCES:.c=.o) $(ASM_SOURCES:.s=.o))

# Object files that are placed manually in the linker script.
MANUALLY_LINKED_OBJS = $(patsubst %,$(BUILD_OUT)/%, \
		       archs/i586/internal/load/loader.o \
		       archs/i586/internal/load/mem_init.o \
		       archs/i586/internal/load/gdt.o \
		       archs/i586/internal/load/idt.o \
		       archs/i586/internal/memory/gdt.PHYS.o)

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

$(BUILD_OUT)/libkernel_phys.a: $(MANUALLY_LINKED_OBJS)
	$(AR) rcs $@ $^
 
$(BUILD_OUT)/kernel.bin: $(OBJFILES) $(BUILD_OUT)/libkernel_phys.a archs/$(ARCH)/build/linker.ld
	$(LD)  -T archs/$(ARCH)/build/linker.ld -L $(BUILD_OUT) -o $@ $(OBJFILES)

$(BUILD_OUT)/kernel.bin.stripped: $(BUILD_OUT)/kernel.bin
	strip -s $< -o $@

$(BUILD_OUT)/kernel.img: $(BUILD_OUT)/kernel.bin.stripped grub/menu.lst $(BUILD_DIR)/kernel.img.base
	cp $(BUILD_DIR)/kernel.img.base $@
	mcopy -i $@ grub/menu.lst ::/boot/grub/menu.lst 
	mcopy -i $@ $(BUILD_OUT)/kernel.bin.stripped ::/kernel.bin

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
$(BUILD_OUT)/%.d : $(BUILD_OUT)/%.c
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
$(BUILD_OUT)/%.d : %.tpl util/tpl_deps.sh
	@echo Generating dependency list for $<
	$(mk-build-dir)
	@util/tpl_deps.sh $< | \
	  sed 's,^\($<\):,$(dir $@)$(notdir $<).c $@ : $<,' \
	  > $@
DEPSFILES = $(patsubst %.c,$(BUILD_OUT)/%.d,$(C_SOURCES)) $(patsubst %.tpl.c,$(BUILD_OUT)/%.d,$(TPL_SOURCES)) $(patsubst %,$(BUILD_OUT)/%.d,$(GENERATED))
-include $(DEPSFILES)

clean:
	$(RM) $(OBJFILES) $(DEPSFILES) $(BUILD_OUT)/kernel.bin $(BUILD_OUT)/kernel.img $(HD_IMAGES)
	$(RM) $(OBJFILES) $(DEPSFILES) $(BUILD_OUT)/kernel.bin $(BUILD_OUT)/kernel.bin.stripped $(BUILD_OUT)/kernel.img $(HD_IMAGES)

run: all
	./bochs/bochs -q -f $(BUILD_DIR)/bochsrc.txt

runx: all
	./bochs/bochs -q -f $(BUILD_DIR)/bochsrc.txt.x11

gdb: $(BUILD_OUT)/kernel.bin all
	./bochs/bochs_gdb -q -f $(BUILD_DIR)/bochsrc.txt.gdb
