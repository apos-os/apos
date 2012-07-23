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

// Code for initializing and using the PS/2 controller and devices.
#ifndef APOO_PS2_H
#define APOO_PS2_H

// Constants for communicating with the ps2 driver.
#define PS2_PORT1 1
#define PS2_PORT2 2

// Device types.
#define PS2_DEVICE_DISABLED 0    // The port is disabled.
#define PS2_DEVICE_UNKNOWN 1     // We don't know what the device is
#define PS2_DEVICE_KEYBOARD 2

// Initialize the PS2 subsystem.  Returns 0 if there was a failure.
int ps2_init();

// Returns the device type of the device attached to the given port.
int ps2_get_device_type(int port);

// Enables interrupts for the given port.
void ps2_enable_interrupts(int port);

// Blocks until a byte of data is available on the given port, then returns it.
uint8_t ps2_read_byte(int port);

// Async version of the above.  Loops up to timeout times waiting for data, then
// puts it in data_out and returns 1.  If no data is available after the number
// of checks is done, then 0 is returned.
int ps2_read_byte_async(int port, uint8_t* data_out, int timeout);

// Writes a byte to the given port.  Blocks until the write is complete.
void ps2_write_byte(int port, uint8_t data);

#endif
