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

// Code for handling page fault exceptions.
#ifndef APOO_PAGE_FAULT
#define APOO_PAGE_FAULT

#include <stdint.h>
#include "memory/memory.h"

// Initialize the page fault handler and register it with the interrupts module.
void paging_init(memory_info_t* meminfo);

// Interrupt handler for page faults.  Reads the address that caused the fault
// from register CR2, and takes the error code given by the interrupt.
void page_fault_handler(uint32_t interrupt, uint32_t error);

#endif
