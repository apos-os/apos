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

.global basic_thread_test_tramp_fn
.global basic_thread_test_fn
.global thread_test_create_tramp

basic_thread_test_tramp_fn:
  .option push
  .option norelax
1:auipc gp, %pcrel_hi(__global_pointer$)
  addi  gp, gp, %pcrel_lo(1b)
  .option pop

  mv a0, sp
  call basic_thread_test_fn
  # Shouldn't get here.
  ret

thread_test_create_tramp:
  .option push
  .option norelax
1:auipc gp, %pcrel_hi(__global_pointer$)
  addi  gp, gp, %pcrel_lo(1b)
  .option pop

  # Thread function arg and address were pushed.
  ld t0, 0(sp)
  ld a0, 8(sp)
  jalr t0
  call apos_thread_exit
