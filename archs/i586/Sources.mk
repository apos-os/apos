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

$(eval $(BEGIN_SOURCES))

LOCAL_SOURCES := \
  arch/common/die.c \
  arch/common/io.c \
  arch/dev/interrupts.c \
  arch/dev/irq.c \
  arch/dev/isr.s \
  arch/memory/page_alloc.c \
  arch/memory/page_fault.c \
  arch/proc/kthread.c \
  arch/proc/kthread_asm.s \
  arch/proc/stack_trace.c \
  arch/proc/user_context.c \
  arch/proc/user_mode.c \
  arch/syscall/context.c \
  arch/syscall/init.c \
  internal/dev/faults.c \
  internal/memory/gdt.c \
  internal/proc/tss.c \

LOCAL_SUBDIRS := internal/load

$(foreach subdir,$(LOCAL_SUBDIRS),$(eval $(call SOURCES_SUBDIR,$(subdir))))

$(eval $(END_SOURCES))
