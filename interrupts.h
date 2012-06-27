// Copyright 2014 Andrew Oates.  All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code for registering and handling interrupts.
#ifndef APOO_INTERRUPTS_H
#define APOO_INTERRUPTS_H

void interrupts_init();

// Structs for the IDT and its entries.
typedef struct {
   uint16_t offset_low;
   uint16_t selector;
   uint8_t zero;
   uint8_t type_attr;
   uint16_t offset_high;
} __attribute__((packed)) idt_entry_t;

typedef struct {
   uint16_t limit;
   uint32_t base;
} __attribute__((packed)) idt_ptr_t;

#endif
