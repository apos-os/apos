// Copyright 2026 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_OS_CORE_LOADER_TESTDATA_LIBS_HEADER_H
#define APOO_OS_CORE_LOADER_TESTDATA_LIBS_HEADER_H

typedef struct {
  int lib1_funcA;
  int lib2_funcB;
  int lib2b_funcB2;
  int lib2_funcC;
  int lib3_funcD;
  int lib4_funcE;
  int lib4_funcA;
  int lib4_funcB;
  int bin_funcX;
  int lib4_funcX;
} testlib_calls_t;

// A series of functions defined in different shared libraries that create a
// complex DAG of dependencies.
// lib_bin -> lib1
//   lib1 -> lib2
//   lib1 -> lib2b
//   lib2 -> lib2b
//   lib1 -> lib3
//     lib3 -> lib2
//     lib3 -> lib4
//  lib4: provides duplicate symbols to lib1 and lib2.
void funcA(testlib_calls_t* c);  // lib1 and lib4
void funcB(testlib_calls_t* c);  // lib2 and lib4
void funcB2(testlib_calls_t* c);  // lib2b
void funcC(testlib_calls_t* c);  // lib2
void funcD(testlib_calls_t* c);  // lib3
void funcE(testlib_calls_t* c);  // lib4
void funcX(testlib_calls_t* c);  // bin and lib4

#define IMPL_FUNC(_lib, _func, _body) \
  void _func(testlib_calls_t* c) {    \
    (c->_lib##_func)++;               \
    _body                             \
  }

#endif
