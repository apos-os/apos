// Copyright 2023 Andrew Oates.  All Rights Reserved.
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

// A utility to inject hooks into code under test, for dire circumstances when
// there is absolutely no other way to test functionality.
#ifndef APOO_TEST_TEST_POINT_H
#define APOO_TEST_TEST_POINT_H

// A test point hook function.
typedef void (*test_point_cb_t)(const char* name, void* arg);

// Register a test point with the given name.  When triggered, the hook will be
// called with the argument.
void test_point_add(const char* name, test_point_cb_t cb, void* arg);

// Removes the named test hook.  If the hook is currently running, blocks until
// the last running instance completes.  Returns the number of times it was
// triggered (so the test can verify it was properly injected).
int test_point_remove(const char* name);

// Triggers a test hook.  If a hook is registered with the given name, executes
// it synchronously.
void test_point_run(const char* name);

// Returns the total number of test points (useful for verifying all have been
// removed at the end of a test run).
int test_point_count(void);

#endif
