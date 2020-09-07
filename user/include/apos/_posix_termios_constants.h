// Copyright 2020 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_USER_INCLUDE_APOS__POSIX_TERMIOS_CONSTANTS_H
#define APOO_USER_INCLUDE_APOS__POSIX_TERMIOS_CONSTANTS_H

// Control characters.
#define VEOF 0
#define VEOL 1
#define VERASE 2
#define VINTR 3
#define VKILL 4
#define VMIN 5
#define VQUIT 6
#define VSTART 7
#define VSTOP 8
#define VSUSP 9
#define VTIME 10
#define NCCS 11

#define _POSIX_VDISABLE 0xff

// Input mode flags (for c_iflag).
#define BRKINT (1 << 1)  // Signal interrupt on break.
#define ICRNL  (1 << 2)  // Map CR to NL on input.
#define IGNBRK (1 << 3)  // Ignore break condition.
#define IGNCR  (1 << 4)  // Ignore CR.
#define IGNPAR (1 << 5)  // Ignore characters with parity errors.
#define INLCR  (1 << 6)  // Map NL to CR on input.
#define INPCK  (1 << 7)  // Enable input parity check.
#define ISTRIP (1 << 8)  // Strip character.
#define IXANY  (1 << 9)  // Enable any character to restart output.
#define IXOFF  (1 << 10)  // Enable start/stop input control.
#define IXON   (1 << 11)  // Enable start/stop output control.
#define PARMRK (1 << 12)  // Mark parity errors.


// Output mode flags (for c_oflag).
#define OPOST  (1 << 1)  // Post-process output.
#define ONLCR  (1 << 2)  // Map NL to CR-NL on output.
#define OCRNL  (1 << 3)  // Map CR to NL on output.
#define ONOCR  (1 << 4)  // No CR output at column 0.
#define ONLRET (1 << 5)  // NL performs CR function.
#define OFDEL  (1 << 6)  // Fill is DEL.
#define OFILL  (1 << 7)  // Use fill characters for delay.

#define NLDLY  (1 << 8)  // Select newline delays:
#define NL0          0   //   Newline type 0.
#define NL1    (1 << 8)  //   Newline type 1.

#define CRDLY (3 << 9)   // Select carriage-return delays:
#define CR0         0    //   Carriage-return delay type 0.
#define CR1   (1 << 9)   //   Carriage-return delay type 1.
#define CR2   (1 << 10)  //   Carriage-return delay type 2.
#define CR3   (3 << 9)   //   Carriage-return delay type 3.

#define TABDLY (3 << 11)  // Select horizontal-tab delays:
#define TAB0          0   //   Horizontal-tab delay type 0.
#define TAB1   (1 << 11)  //   Horizontal-tab delay type 1.
#define TAB2   (1 << 12)  //   Horizontal-tab delay type 2.
#define TAB3   (3 << 11)  //   Expand tabs to spaces.

#define BSDLY (1 << 13)  // Select backspace delays:
#define BS0          0   //   Backspace-delay type 0.
#define BS1   (1 << 13)  //   Backspace-delay type 1.

#define VTDLY (1 << 14)  // Select vertical-tab delays:
#define VT0          0   //   Vertical-tab delay type 0.
#define VT1   (1 << 14)  //   Vertical-tab delay type 1.

#define FFDLY (1 << 15)  // Select form-feed delays:
#define FF0          0   //   Form-feed delay type 0.
#define FF1   (1 << 15)  //   Form-feed delay type 1.


// Baud rate constants.
#define B0 0  // Hang up
#define B50 1
#define B75 2
#define B110 3
#define B134 4  // 134.5 baud
#define B150 5
#define B200 6
#define B300 7
#define B600 8
#define B1200 9
#define B1800 10
#define B2400 11
#define B4800 12
#define B9600 13
#define B19200 14
#define B38400 15


// Control mode flags (for c_cflag).
#define CSIZE 3  // Character size:
#define CS5   0  //   5 bits
#define CS6   1  //   6 bits
#define CS7   2  //   7 bits
#define CS8   3  //   8 bits

#define CSTOPB (1 << 2)  // Send two stop bits, else one.
#define CREAD  (1 << 3)  // Enable receiver.
#define PARENB (1 << 4)  // Parity enable.
#define PARODD (1 << 5)  // Odd parity, else even.
#define HUPCL  (1 << 6)  // Hang up on last close.
#define CLOCAL (1 << 7)  // Ignore modem status lines.


// Local mode flags (for c_lflag).
#define ECHO   (1 << 1)  // Enable echo.
#define ECHOE  (1 << 2)  // Echo erase character as error-correcting backspace.
#define ECHOK  (1 << 3)  // Echo KILL.
#define ECHONL (1 << 4)  // Echo NL.
#define ICANON (1 << 5)  // Canonical input (erase and kill processing).
#define IEXTEN (1 << 6)  // Enable extended input character processing.
#define ISIG   (1 << 7)  // Enable signals.
#define NOFLSH (1 << 8)  // Disable flush after interrupt or quit.
#define TOSTOP (1 << 9)  // Send SIGTTOU for background output.


// Attribute selection.
#define TCSANOW 1    // Change attributes immediately.
#define TCSADRAIN 2  // Change attributes when output has drained.
#define TCSAFLUSH 3  // Change attributes when output has drained; also flush pending input.


// Line control.
#define TCIFLUSH 1   // Flush pending input.
#define TCIOFLUSH 2  // Flush both pending input and untransmitted output.
#define TCOFLUSH 3   // Flush untransmitted output.

#define TCIOFF 1  // Transmit a STOP character, intended to suspend input data.
#define TCION 2   // Transmit a START character, intended to restart input data.
#define TCOOFF 3  // Suspend output.
#define TCOON 4   // Restart output.

#endif
