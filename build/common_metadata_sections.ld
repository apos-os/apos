/*
 * Copyright 2024 Andrew Oates.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Common sections for all linker scripts; should be INCLUDE'd in SECTIONS. */
.comment        : AT(ADDR(.comment))        { *(.comment) }
.debug_line     : AT(ADDR(.debug_line))     { *(.debug_line) }
.debug_info     : AT(ADDR(.debug_info))     { *(.debug_info) }
.debug_abbrev   : AT(ADDR(.debug_abbrev))   { *(.debug_abbrev) }
.debug_aranges  : AT(ADDR(.debug_aranges))  { *(.debug_aranges) }
.debug_str      : AT(ADDR(.debug_str))      { *(.debug_str) }
.debug_macinfo  : AT(ADDR(.debug_macinfo))  { *(.debug_macinfo) }
.debug_macro    : AT(ADDR(.debug_macro))    { *(.debug_macro) }
.debug_frame    : AT(ADDR(.debug_frame))    { *(.debug_frame) }
.debug_loc      : AT(ADDR(.debug_loc))      { *(.debug_loc) }
.debug_ranges   : AT(ADDR(.debug_ranges))   { *(.debug_ranges) }
.note.GNU-stack : AT(ADDR(.note.GNU-stack)) { *(.note.GNU-stack) }
.rel.text       : AT(ADDR(.rel.text))       { *(.rel.text) }
.rela.text      : AT(ADDR(.rela.text))      { *(.rela.text) }

/* Discard sections created automatically by TSAN. */
/DISCARD/ :
{
    *(.init_array.0)
    *(.text.tsan.module_ctor)
}
