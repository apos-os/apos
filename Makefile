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
CC	= i586-elf-gcc
CFLAGS	= -Wall -Wextra -nostdlib -fno-builtin -nostartfiles -nodefaultlibs
LD	= i586-elf-ld

BOOTLOADER	= grub
 
OBJFILES = loader.o kernel.o
 
all: kernel.img
 
%.o : %.s
	$(AS) -o $@ $<

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<
 
kernel.bin: $(OBJFILES)
	$(LD) -T linker.ld -o $@ $^

kernel.img: kernel.bin
	dd if=/dev/zero of=pad.tmp bs=1 count=750
	cat $(BOOTLOADER)/stage1 $(BOOTLOADER)/stage2 pad.tmp $< > $@
 
clean:
	$(RM) $(OBJFILES) kernel.bin kernel.img pad.tmp

run: kernel.img
	./bochs/bochs
