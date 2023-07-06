# Copyright 2023 Andrew Oates.  All Rights Reserved.
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

.set SSTATUS_SIE, 0x2

# void enable_interrupts(void)
.global enable_interrupts
enable_interrupts:
  csrsi sstatus, SSTATUS_SIE
  ret

# void disable_interrupts(void)
.global disable_interrupts
disable_interrupts:
  csrci sstatus, SSTATUS_SIE
  ret

# interrupt_state_t get_interrupts_state(void)
.global get_interrupts_state
get_interrupts_state:
  csrr a0, sstatus
  andi a0, a0, SSTATUS_SIE
  ret

# interrupt_state_t save_and_disable_interrupts(void)
.global save_and_disable_interrupts
save_and_disable_interrupts:
  # Read sstatus and clear SIE
  csrrci a0, sstatus, SSTATUS_SIE
  andi a0, a0, SSTATUS_SIE
  ret

# void restore_interrupts(interrupt_state_t saved)
.global restore_interrupts
restore_interrupts:
  beqz a0, .done
  csrsi sstatus, SSTATUS_SIE
.done:
  ret

# TODO(riscv): define these properly
.global _int_handlers_start
.global _int_handlers_end
_int_handlers_start:
_int_handlers_end:
