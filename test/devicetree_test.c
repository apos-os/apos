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

#include "common/endian.h"
#include "common/errno.h"
#include "common/kstring.h"
#include "dev/devicetree/devicetree.h"
#include "dev/devicetree/dtb.h"
#include "dev/devicetree/interrupts.h"
#include "memory/kmalloc.h"
#include "test/ktest.h"

// A sample golden DTB slimmed down from a QEMU-generated riscv virt sample.
static unsigned char kGoldenDtb[] __attribute__((aligned(4))) = {
#include "test/dtb_testdata/large_golden.dts.h"
};

static unsigned char kSmallGoldenDtb[] __attribute__((aligned(4))) = {
#include "test/dtb_testdata/small_golden.dts.h"
};

static const char kGoldenDtbPrinted[] =
    "FDT header:\n"
    " magic: 0xd00dfeed\n"
    " totalsize: 0x6ad\n"
    " off_dt_struct: 0x38\n"
    " off_dt_strings: 0x5b4\n"
    " off_mem_rsvmap: 0x28\n"
    " version: 0x11\n"
    " last_comp_version: 0x10\n"
    " boot_cpuid_phys: 0x0\n"
    " size_dt_strings: 0xf9\n"
    " size_dt_struct: 0x57c\n"
    "\n"
    "Memory reservation blocks:\n"
    "\n"
    "FDT struct:\n"
    "{\n"
    "  #address-cells = 2 (0x2) [u32]\n"
    "  #size-cells = 2 (0x2) [u32]\n"
    "  compatible = 'riscv-virtio' [string]\n"
    "  model = 'riscv-virtio,qemu' [string]\n"
    "\n"
    "  reserved-memory {\n"
    "    #address-cells = 2 (0x2) [u32]\n"
    "    #size-cells = 2 (0x2) [u32]\n"
    "    ranges = <0 bytes>\n"
    "\n"
    "    mmode_resv1@80000000 {\n"
    "      reg = <0x80000000 - 0x80040000> \n"
    "      no-map = <0 bytes>\n"
    "    }\n"
    "\n"
    "    mmode_resv0@80040000 {\n"
    "      reg = <0x80040000 - 0x80050000> \n"
    "      no-map = <0 bytes>\n"
    "    }\n"
    "  }\n"
    "\n"
    "  fw-cfg@10100000 {\n"
    "    dma-coherent = <0 bytes>\n"
    "    reg = <0x10100000 - 0x10100018> \n"
    "    compatible = 'qemu,fw-cfg-mmio' [string]\n"
    "  }\n"
    "\n"
    "  platform-bus@4000000 {\n"
    "    interrupt-parent = 3 (0x3) [u32]\n"
    "    ranges = <16 bytes>\n"
    "    #address-cells = 1 (0x1) [u32]\n"
    "    #size-cells = 1 (0x1) [u32]\n"
    "    compatible = <25 bytes>\n"
    "  }\n"
    "\n"
    "  memory@80000000 {\n"
    "    device_type = 'memory' [string]\n"
    "    reg = <0x80000000 - 0x88000000> \n"
    "  }\n"
    "\n"
    "  cpus {\n"
    "    #address-cells = 1 (0x1) [u32]\n"
    "    #size-cells = 0 (0x0) [u32]\n"
    "    timebase-frequency = 10000000 (0x989680) [u32]\n"
    "\n"
    "    cpu@0 {\n"
    "      phandle = 1 (0x1) [u32]\n"
    "      reg = 0 (0x0) [u32]\n"
    "      compatible = 'riscv' [string]\n"
    "      riscv,cbom-block-size = 64 (0x40) [u32]\n"
    "\n"
    "      interrupt-controller {\n"
    "        #interrupt-cells = 1 (0x1) [u32]\n"
    "        interrupt-controller = <0 bytes>\n"
    "        compatible = 'riscv,cpu-intc' [string]\n"
    "        phandle = 2 (0x2) [u32]\n"
    "      }\n"
    "    }\n"
    "  }\n"
    "\n"
    "  soc {\n"
    "    #address-cells = 2 (0x2) [u32]\n"
    "    #size-cells = 2 (0x2) [u32]\n"
    "    compatible = 'simple-bus' [string]\n"
    "    ranges = <0 bytes>\n"
    "\n"
    "    serial@10000000 {\n"
    "      interrupts = 10 (0xa) [u32]\n"
    "      interrupt-parent = 3 (0x3) [u32]\n"
    "      clock-frequency = 3686400 (0x384000) [u32]\n"
    "      reg = <0x10000000 - 0x10000100> \n"
    "      compatible = 'ns16550a' [string]\n"
    "    }\n"
    "\n"
    "    test@100000 {\n"
    "      phandle = 4 (0x4) [u32]\n"
    "      reg = <0x100000 - 0x101000> \n"
    "      compatible = <33 bytes>\n"
    "    }\n"
    "\n"
    "    plic@c000000 {\n"
    "      phandle = 3 (0x3) [u32]\n"
    "      riscv,ndev = 95 (0x5f) [u32]\n"
    "      reg = <0xc000000 - 0xc600000> \n"
    "      interrupts-extended = <16 bytes>\n"
    "      interrupt-controller = <0 bytes>\n"
    "      compatible = <30 bytes>\n"
    "      #address-cells = 0 (0x0) [u32]\n"
    "      #interrupt-cells = 1 (0x1) [u32]\n"
    "    }\n"
    "  }\n"
    "}\n";

static const char kSmallGoldenDtbPrinted[] =
    "{\n"
    "  #address-cells = 2 (0x2) [u32]\n"
    "  #size-cells = 2 (0x2) [u32]\n"
    "  compatible = 'riscv-virtio' [string]\n"
    "  model = 'riscv-virtio,qemu' [string]\n"
    "\n"
    "  reserved-memory {\n"
    "    #address-cells = 2 (0x2) [u32]\n"
    "    #size-cells = 2 (0x2) [u32]\n"
    "    ranges = <0 bytes>\n"
    "  }\n"
    "\n"
    "  platform-bus@4000000 {\n"
    "    interrupt-parent = 3 (0x3) [u32]\n"
    "    ranges = <16 bytes>\n"
    "    #address-cells = 1 (0x1) [u32]\n"
    "    #size-cells = 1 (0x1) [u32]\n"
    "    compatible = <25 bytes>\n"
    "  }\n"
    "\n"
    "  cpus {\n"
    "    #address-cells = 1 (0x1) [u32]\n"
    "    #size-cells = 0 (0x0) [u32]\n"
    "    timebase-frequency = 10000000 (0x989680) [u32]\n"
    "\n"
    "    cpu@0 {\n"
    "      phandle = 1 (0x1) [u32]\n"
    "      reg = 0 (0x0) [u32]\n"
    "      compatible = 'riscv' [string]\n"
    "      riscv,cbom-block-size = 64 (0x40) [u32]\n"
    "\n"
    "      interrupt-controller {\n"
    "        #interrupt-cells = 1 (0x1) [u32]\n"
    "        interrupt-controller = <0 bytes>\n"
    "        compatible = 'riscv,cpu-intc' [string]\n"
    "        phandle = 2 (0x2) [u32]\n"
    "      }\n"
    "    }\n"
    "  }\n"
    "}\n";

static const char kIntTestDtb[] __attribute__((aligned(4))) = {
#include "test/dtb_testdata/interrupt_test.dts.h"
};

const size_t kPrintBufLen = 10000;
static void printer(void* arg, const char* s) {
  kstrlcat(arg, s, kPrintBufLen);
}

static void dtb_print_golden_test(void) {
  KTEST_BEGIN("dtfdt_print(): golden test");

  char* pbuf = (char*)kmalloc(kPrintBufLen);
  kmemset(pbuf, 0, kPrintBufLen);
  KEXPECT_EQ(DTFDT_OK, dtfdt_print(kGoldenDtb, true, printer, pbuf));
  if (ARCH_IS_64_BIT) {
    // On 32-bit archs some numbers are printed differently.
    KEXPECT_MULTILINE_STREQ(kGoldenDtbPrinted, pbuf);
  }

  // Smaller golden that prints the same on all architectures.
  kmemset(pbuf, 0, kPrintBufLen);
  KEXPECT_EQ(DTFDT_OK, dtfdt_print(kSmallGoldenDtb, false, printer, pbuf));
  KEXPECT_MULTILINE_STREQ(kSmallGoldenDtbPrinted, pbuf);

  kfree(pbuf);
}

static void dtree_basic_test(void) {
  KTEST_BEGIN("dt_create(): basic test");

  const size_t kBufLen = 10000;
  void* buf = kmalloc(kBufLen);
  dt_tree_t* tree = NULL;
  KEXPECT_EQ(DTFDT_OK, dt_create(kGoldenDtb, &tree, buf, kBufLen));

  KEXPECT_EQ((const void*)buf, tree->buffer);
  KEXPECT_STREQ("", tree->root->name);
  KEXPECT_STREQ("#address-cells", tree->root->properties->name);
  KEXPECT_EQ(0x2, btoh32(*(const uint32_t*)(tree->root->properties->val)));
  KEXPECT_STREQ("#size-cells", tree->root->properties->next->name);
  KEXPECT_EQ(0x2, btoh32(*(const uint32_t*)(tree->root->properties->next->val)));

  KEXPECT_EQ(NULL, tree->root->parent);
  KEXPECT_EQ(tree->root, dt_lookup(tree, "/"));
  const dt_node_t* mem = tree->root->children->next->next->next;
  KEXPECT_EQ(mem, dt_lookup(tree, "/memory@80000000"));
  KEXPECT_STREQ("device_type",
                (const char*)dt_get_prop(mem, "device_type")->name);
  KEXPECT_STREQ("memory", (const char*)dt_get_prop(mem, "device_type")->val);
  KEXPECT_EQ(tree->root, mem->parent);

  KEXPECT_EQ(NULL, dt_lookup(tree, "/abc"));
  KEXPECT_EQ(NULL, dt_lookup(tree, ""));

  KEXPECT_EQ(NULL, dt_get_prop(mem, "noprop"));
  KEXPECT_STREQ("device_type",
                dt_get_nprop(tree, "/memory@80000000", "device_type")->name);
  KEXPECT_EQ(NULL, dt_get_nprop(tree, "/memory2@80000000", "device_type"));
  KEXPECT_EQ(NULL, dt_get_nprop(tree, "/memory@80000000", "device_type2"));

  KTEST_BEGIN("dt_create(): phandle lookups");
  KEXPECT_EQ(NULL, dt_lookup_phandle(tree, 0));
  KEXPECT_EQ(NULL, dt_lookup_phandle(tree, 10));
  KEXPECT_STREQ("cpu@0", dt_lookup_phandle(tree, 1)->name);
  KEXPECT_STREQ("interrupt-controller", dt_lookup_phandle(tree, 2)->name);
  KEXPECT_STREQ("test@100000", dt_lookup_phandle(tree, 4)->name);

  const dt_node_t* serial = dt_lookup(tree, "/soc/serial@10000000");
  KEXPECT_EQ(dt_lookup(tree, "/soc"), serial->parent);
  KEXPECT_EQ(dt_lookup(tree, "/soc/plic@c000000"),
             dt_lookup_prop_phandle(tree, serial, "interrupt-parent"));
  KEXPECT_EQ(NULL, dt_lookup_prop_phandle(tree, serial, "interrupt-parent2"));
  KEXPECT_EQ(NULL, dt_lookup_prop_phandle(tree, serial, "compatible"));

  KTEST_BEGIN("dt_create(): buffer too small");
  KEXPECT_EQ(DTFDT_OUT_OF_MEMORY, dt_create(kGoldenDtb, &tree, buf, 100));


  KTEST_BEGIN("dt_print_path(): basic test");
  const size_t kNameBufLen = 100;
  char namebuf[kNameBufLen];
  const char* path = "/cpus/cpu@0/interrupt-controller";
  const dt_node_t* node = dt_lookup(tree, path);
  KEXPECT_NE(NULL, node);
  KEXPECT_EQ(32, kstrlen(path));
  KEXPECT_EQ(32, dt_print_path(node, namebuf, kNameBufLen));
  KEXPECT_STREQ(path, namebuf);

  kmemset(namebuf, 'X', kNameBufLen);
  KEXPECT_EQ(1, dt_print_path(tree->root, namebuf, kNameBufLen));
  KEXPECT_STREQ("/", namebuf);

  KTEST_BEGIN("dt_print_path(): buffer too short");
  kmemset(namebuf, 'X', kNameBufLen);
  // For each of these, it should return at least the given bufsize, signalling
  // truncation (exact return value is unspecified).
  KEXPECT_LT(2, dt_print_path(node, namebuf, 2));
  KEXPECT_STREQ("/", namebuf);
  kmemset(namebuf, 'X', kNameBufLen);
  KEXPECT_LT(11, dt_print_path(node, namebuf, 11));
  KEXPECT_STREQ("/cpus/cpu@", namebuf);
  KEXPECT_LT(6, dt_print_path(node, namebuf, 6));
  KEXPECT_STREQ("/cpus", namebuf);
  KEXPECT_LT(7, dt_print_path(node, namebuf, 7));
  KEXPECT_STREQ("/cpus/", namebuf);

  kfree(buf);
}

static void name_test(void) {
  dt_node_t node;
  node.name = "abc";
  KEXPECT_STREQ("", dt_get_unit(&node));
  node.name = "abc@";
  KEXPECT_STREQ("", dt_get_unit(&node));
  node.name = "abc@1234";
  KEXPECT_STREQ("1234", dt_get_unit(&node));
  node.name = "abc@c123a";
  KEXPECT_STREQ("c123a", dt_get_unit(&node));
}

static void intr_test1(const dt_tree_t* tree) {
  KTEST_BEGIN("dtint_extract(): basic test");
  const dt_node_t* intc_node = dt_lookup(tree, "/soc/int-controller1");
  KEXPECT_NE(NULL, intc_node);

  const dt_node_t* node = dt_lookup(tree, "/int-generator1");
  KEXPECT_NE(NULL, node);

  const size_t kMaxInts = 10;
  dt_interrupt_t int_buf[kMaxInts];
  kmemset(int_buf, 0xab, sizeof(int_buf));
  KEXPECT_EQ(2, dtint_extract(tree, node, int_buf, kMaxInts));

  KEXPECT_EQ(1, int_buf[0].cells);
  KEXPECT_EQ(4, int_buf[0]._int[0]);
  KEXPECT_EQ(0, int_buf[0]._int[1]);  // Should be zeroed.
  KEXPECT_EQ(intc_node, int_buf[0].int_parent);
  KEXPECT_EQ(1, int_buf[1].cells);
  KEXPECT_EQ(7, int_buf[1]._int[0]);
  KEXPECT_EQ(0, int_buf[1]._int[1]);
  KEXPECT_EQ(intc_node, int_buf[1].int_parent);

  // Basic flat extraction.
  KEXPECT_EQ(4, dtint_flatten(&int_buf[0]));
  KEXPECT_EQ(7, dtint_flatten(&int_buf[1]));


  KTEST_BEGIN("dtint_extract(): implicit interrupt parent");
  kmemset(int_buf, 0xab, sizeof(int_buf));
  node = dt_lookup(tree, "/int-two-cells/gen-ok");
  KEXPECT_NE(NULL, node);
  KEXPECT_EQ(2, dtint_extract(tree, node, int_buf, kMaxInts));
  KEXPECT_EQ(2, int_buf[0].cells);
  KEXPECT_EQ(5, int_buf[0]._int[0]);
  KEXPECT_EQ(6, int_buf[0]._int[1]);
  KEXPECT_EQ(0, int_buf[0]._int[2]);
  KEXPECT_EQ(dt_lookup(tree, "/int-two-cells"), int_buf[0].int_parent);
  KEXPECT_EQ(2, int_buf[1].cells);
  KEXPECT_EQ(7, int_buf[1]._int[0]);
  KEXPECT_EQ(8, int_buf[1]._int[1]);
  KEXPECT_EQ(0, int_buf[1]._int[2]);
  KEXPECT_EQ(dt_lookup(tree, "/int-two-cells"), int_buf[1].int_parent);


  KTEST_BEGIN("dtint_extract(): too many interrupts");
  KEXPECT_EQ(-ENOMEM, dtint_extract(tree, node, int_buf, 1));


  KTEST_BEGIN("dtint_extract(): too many interrupt cells");
  node = dt_lookup(tree, "/int-too-many-cells/gen");
  KEXPECT_NE(NULL, node);
  KEXPECT_EQ(-EINVAL, dtint_extract(tree, node, int_buf, kMaxInts));


  KTEST_BEGIN("dtint_extract(): invalid (zero) #interrupt-cells");
  node = dt_lookup(tree, "/int-zero-cells/gen");
  KEXPECT_NE(NULL, node);
  KEXPECT_EQ(-EINVAL, dtint_extract(tree, node, int_buf, kMaxInts));


  KTEST_BEGIN("dtint_extract(): invalid (too small) #interrupt-cells");
  node = dt_lookup(tree, "/int-too-short-cells/gen");
  KEXPECT_NE(NULL, node);
  KEXPECT_EQ(-EINVAL, dtint_extract(tree, node, int_buf, kMaxInts));


  KTEST_BEGIN("dtint_extract(): invalid (too big) #interrupt-cells");
  node = dt_lookup(tree, "/int-too-long-cells/gen");
  KEXPECT_NE(NULL, node);
  KEXPECT_EQ(-EINVAL, dtint_extract(tree, node, int_buf, kMaxInts));


  KTEST_BEGIN("dtint_extract(): not even multiple of #interrupt-cells");
  node = dt_lookup(tree, "/int-two-cells/gen1");
  KEXPECT_NE(NULL, node);
  KEXPECT_EQ(-EINVAL, dtint_extract(tree, node, int_buf, kMaxInts));
  node = dt_lookup(tree, "/int-two-cells/gen2");
  KEXPECT_NE(NULL, node);
  KEXPECT_EQ(-EINVAL, dtint_extract(tree, node, int_buf, kMaxInts));


  KTEST_BEGIN("dtint_extract(): missing #interrupt-cells");
  node = dt_lookup(tree, "/int-no-cells/gen");
  KEXPECT_NE(NULL, node);
  KEXPECT_EQ(-EINVAL, dtint_extract(tree, node, int_buf, kMaxInts));


  KTEST_BEGIN("dtint_extract(): no interrupt parent (root)");
  node = dt_lookup(tree, "/");
  KEXPECT_NE(NULL, node);
  KEXPECT_EQ(-EINVAL, dtint_extract(tree, node, int_buf, kMaxInts));


  KTEST_BEGIN("dtint_extract(): no interrupts specified");
  node = dt_lookup(tree, "/int-two-cells/gen-no-ints");
  KEXPECT_NE(NULL, node);
  KEXPECT_EQ(-EINVAL, dtint_extract(tree, node, int_buf, kMaxInts));


  // TODO(aoates): other basic tests:
  //  - interrupts-extended
  //  - multiple parents with different #interrupt-cells
  //  - interrupts-extended and interrupts both set
  // TODO(aoates): test with an interrupt nexus and interrupt-map (and mask).
}

static void intr_test2(const dt_tree_t* tree) {
  KTEST_BEGIN("dtint_map(): basic test");
  const dt_node_t* intc_node = dt_lookup(tree, "/soc/int-controller1");
  KEXPECT_NE(NULL, intc_node);

  const dt_node_t* node = dt_lookup(tree, "/int-generator1");
  KEXPECT_NE(NULL, node);

  const size_t kMaxInts = 10;
  dt_interrupt_t int_buf[kMaxInts];
  kmemset(int_buf, 0xab, sizeof(int_buf));
  KEXPECT_EQ(2, dtint_extract(tree, node, int_buf, kMaxInts));

  dt_interrupt_t mapped;
  kmemset(&mapped, 0xab, sizeof(mapped));
  KEXPECT_EQ(0, dtint_map(tree, node, &int_buf[0], intc_node, &mapped));
  KEXPECT_EQ(intc_node, mapped.int_parent);
  KEXPECT_EQ(1, mapped.cells);
  KEXPECT_EQ(4, mapped._int[0]);


  KTEST_BEGIN("dtint_map(): no path to root");
  kmemset(&mapped, 0xab, sizeof(mapped));
  KEXPECT_EQ(
      -EINVAL,
      dtint_map(tree, node, &int_buf[0],
                dt_lookup(tree, "/cpus/cpu@0/interrupt-controller"), &mapped));
}

static void intr_test3(const dt_tree_t* tree) {
  KTEST_BEGIN("dtint_map(): basic interrupt-map test");
  const dt_node_t* intc1_node =
      dt_lookup(tree, "/cpus/cpu@0/interrupt-controller");
  KEXPECT_NE(NULL, intc1_node);
  const dt_node_t* intc2_node = dt_lookup(tree, "/soc/int-controller1");
  KEXPECT_NE(NULL, intc2_node);

  const dt_node_t* node = dt_lookup(tree, "/int-map/gen1@100000002");
  KEXPECT_NE(NULL, node);

  const size_t kMaxInts = 10;
  dt_interrupt_t int_buf[kMaxInts];
  kmemset(int_buf, 0xab, sizeof(int_buf));
  KEXPECT_EQ(3, dtint_extract(tree, node, int_buf, kMaxInts));

  dt_interrupt_t mapped;
  kmemset(&mapped, 0xab, sizeof(mapped));
  KEXPECT_EQ(0, dtint_map(tree, node, &int_buf[0], intc1_node, &mapped));
  KEXPECT_EQ(intc1_node, mapped.int_parent);
  KEXPECT_EQ(1, mapped.cells);
  KEXPECT_EQ(0x95, mapped._int[0]);

  KEXPECT_EQ(-ENOENT, dtint_map(tree, node, &int_buf[1], intc1_node, &mapped));
  KEXPECT_EQ(-ENOENT, dtint_map(tree, node, &int_buf[1], intc2_node, &mapped));

  kmemset(&mapped, 0xab, sizeof(mapped));
  KEXPECT_EQ(0, dtint_map(tree, node, &int_buf[2], intc2_node, &mapped));
  KEXPECT_EQ(intc2_node, mapped.int_parent);
  KEXPECT_EQ(1, mapped.cells);
  KEXPECT_EQ(0xab, mapped._int[0]);


  KTEST_BEGIN("dtint_map(): child unit mask applied test");
  node = dt_lookup(tree, "/int-map/gen2@1100000002");
  KEXPECT_NE(NULL, node);

  kmemset(int_buf, 0xab, sizeof(int_buf));
  KEXPECT_EQ(3, dtint_extract(tree, node, int_buf, kMaxInts));

  kmemset(&mapped, 0xab, sizeof(mapped));
  KEXPECT_EQ(0, dtint_map(tree, node, &int_buf[0], intc1_node, &mapped));
  KEXPECT_EQ(intc1_node, mapped.int_parent);
  KEXPECT_EQ(1, mapped.cells);
  KEXPECT_EQ(0x95, mapped._int[0]);


  KTEST_BEGIN("dtint_map(): child unit mask applied test #2");
  node = dt_lookup(tree, "/int-map/gen3@1110000002");
  KEXPECT_NE(NULL, node);

  kmemset(int_buf, 0xab, sizeof(int_buf));
  KEXPECT_EQ(3, dtint_extract(tree, node, int_buf, kMaxInts));

  KEXPECT_EQ(-ENOENT, dtint_map(tree, node, &int_buf[0], intc1_node, &mapped));
  KEXPECT_EQ(-ENOENT, dtint_map(tree, node, &int_buf[1], intc1_node, &mapped));
  KEXPECT_EQ(-ENOENT, dtint_map(tree, node, &int_buf[2], intc1_node, &mapped));
  KEXPECT_EQ(-ENOENT, dtint_map(tree, node, &int_buf[0], intc2_node, &mapped));
  KEXPECT_EQ(-ENOENT, dtint_map(tree, node, &int_buf[1], intc2_node, &mapped));
  KEXPECT_EQ(-ENOENT, dtint_map(tree, node, &int_buf[2], intc2_node, &mapped));
}

static void intr_test4(const dt_tree_t* tree) {
  KTEST_BEGIN("dtint_map(): interrupt-map multi-nexus cascade test");
  const dt_node_t* intc1_node = dt_lookup(tree, "/int-map-multi/maps/intc");
  KEXPECT_NE(NULL, intc1_node);

  const dt_node_t* node = dt_lookup(tree, "/int-map-multi/gen1@100000002");
  KEXPECT_NE(NULL, node);

  const size_t kMaxInts = 10;
  dt_interrupt_t int_buf[kMaxInts];
  kmemset(int_buf, 0xab, sizeof(int_buf));
  KEXPECT_EQ(1, dtint_extract(tree, node, int_buf, kMaxInts));
  KEXPECT_EQ(1, int_buf[0].cells);
  KEXPECT_EQ(4, int_buf[0]._int[0]);
  KEXPECT_EQ(dt_lookup(tree, "/int-map-multi/maps/map1"),
             int_buf[0].int_parent);

  dt_interrupt_t mapped;
  kmemset(&mapped, 0xab, sizeof(mapped));
  KEXPECT_EQ(0, dtint_map(tree, node, &int_buf[0], intc1_node, &mapped));
  KEXPECT_EQ(intc1_node, mapped.int_parent);
  KEXPECT_EQ(2, mapped.cells);
  KEXPECT_EQ(0x78, mapped._int[0]);
  KEXPECT_EQ(0x9a, mapped._int[1]);


  KTEST_BEGIN("dtint_map(): interrupt src node missing reg property");
  node = dt_lookup(tree, "/int-map-errors/gen1-noreg1@100000002");
  KEXPECT_NE(NULL, node);
  KEXPECT_EQ(1, dtint_extract(tree, node, int_buf, kMaxInts));

  KEXPECT_EQ(-EINVAL, dtint_map(tree, node, &int_buf[0], intc1_node, &mapped));

  node = dt_lookup(tree, "/int-map-errors/gen1-noreg2");
  KEXPECT_NE(NULL, node);
  KEXPECT_EQ(1, dtint_extract(tree, node, int_buf, kMaxInts));

  KEXPECT_EQ(-EINVAL, dtint_map(tree, node, &int_buf[0], intc1_node, &mapped));

  KTEST_BEGIN("dtint_map(): interrupt src node invalid (short) reg property");
  node = dt_lookup(tree, "/int-map-errors/gen1-bad-reg-short@100000002");
  KEXPECT_NE(NULL, node);
  KEXPECT_EQ(1, dtint_extract(tree, node, int_buf, kMaxInts));

  KEXPECT_EQ(-EINVAL, dtint_map(tree, node, &int_buf[0], intc1_node, &mapped));

  node = dt_lookup(tree, "/int-map-errors/gen1-bad-reg-short2@100000002");
  KEXPECT_NE(NULL, node);
  KEXPECT_EQ(1, dtint_extract(tree, node, int_buf, kMaxInts));

  KEXPECT_EQ(-EINVAL, dtint_map(tree, node, &int_buf[0], intc1_node, &mapped));

  KTEST_BEGIN("dtint_map(): interrupt src node invalid (long) reg property");
  node = dt_lookup(tree, "/int-map-errors/gen1-bad-reg-long@100000002");
  KEXPECT_NE(NULL, node);
  KEXPECT_EQ(1, dtint_extract(tree, node, int_buf, kMaxInts));

  KEXPECT_EQ(-EINVAL, dtint_map(tree, node, &int_buf[0], intc1_node, &mapped));

  KTEST_BEGIN("dtint_map(): interrupt src node empty reg property");
  node = dt_lookup(tree, "/int-map-errors/gen1-bad-reg-zero@100000002");
  KEXPECT_NE(NULL, node);
  KEXPECT_EQ(1, dtint_extract(tree, node, int_buf, kMaxInts));

  KEXPECT_EQ(-EINVAL, dtint_map(tree, node, &int_buf[0], intc1_node, &mapped));


  KTEST_BEGIN("dtint_extract(): #interrupt-cells is zero");
  node = dt_lookup(tree, "/int-map-errors/gen-zero-intcells@100000002");
  KEXPECT_NE(NULL, node);
  KEXPECT_EQ(-EINVAL, dtint_extract(tree, node, int_buf, kMaxInts));

  node = dt_lookup(tree, "/int-map-errors/gen-zero-intcells2@100000002");
  KEXPECT_NE(NULL, node);
  KEXPECT_EQ(-EINVAL, dtint_extract(tree, node, int_buf, kMaxInts));


  KTEST_BEGIN("dtint_map(): #interrupt-cells is zero");
  node = dt_lookup(tree, "/int-map-errors/gen-zero-intcells-mid@1");
  KEXPECT_NE(NULL, node);

  kmemset(int_buf, 0xab, sizeof(int_buf));
  KEXPECT_EQ(1, dtint_extract(tree, node, int_buf, kMaxInts));
  kmemset(&mapped, 0xab, sizeof(mapped));
  KEXPECT_EQ(-EINVAL, dtint_map(tree, node, &int_buf[0], intc1_node, &mapped));

  node = dt_lookup(tree, "/int-map-errors/gen-big-intcells-mid@2");
  KEXPECT_NE(NULL, node);

  kmemset(int_buf, 0xab, sizeof(int_buf));
  KEXPECT_EQ(1, dtint_extract(tree, node, int_buf, kMaxInts));
  kmemset(&mapped, 0xab, sizeof(mapped));
  KEXPECT_EQ(-EINVAL, dtint_map(tree, node, &int_buf[0], intc1_node, &mapped));


  KTEST_BEGIN("dtint_map(): #interrupt-cells is missing");
  node = dt_lookup(tree, "/int-map-errors/gen-no-intcells@5");
  KEXPECT_NE(NULL, node);

  kmemset(int_buf, 0xab, sizeof(int_buf));
  KEXPECT_EQ(1, dtint_extract(tree, node, int_buf, kMaxInts));
  kmemset(&mapped, 0xab, sizeof(mapped));
  KEXPECT_EQ(-EINVAL, dtint_map(tree, node, &int_buf[0], intc1_node, &mapped));


  KTEST_BEGIN("dtint_map(): map to node without interrupt-map");
  node = dt_lookup(tree, "/int-map-errors/gen-no-intmap@3");
  KEXPECT_NE(NULL, node);

  kmemset(int_buf, 0xab, sizeof(int_buf));
  KEXPECT_EQ(1, dtint_extract(tree, node, int_buf, kMaxInts));
  kmemset(&mapped, 0xab, sizeof(mapped));
  KEXPECT_EQ(-EINVAL, dtint_map(tree, node, &int_buf[0], intc1_node, &mapped));


  KTEST_BEGIN("dtint_map(): map to node without interrupt-map-mask");
  node = dt_lookup(tree, "/int-map-errors/gen-no-intmask@4");
  KEXPECT_NE(NULL, node);

  kmemset(int_buf, 0xab, sizeof(int_buf));
  KEXPECT_EQ(1, dtint_extract(tree, node, int_buf, kMaxInts));
  kmemset(&mapped, 0xab, sizeof(mapped));
  KEXPECT_EQ(-EINVAL, dtint_map(tree, node, &int_buf[0], intc1_node, &mapped));


  // TODO(aoates): advanced scenarios to test (when nexuses are implemented):
  //  - chain that hits a bad interrupt controller in the middle
  //  - chain that hits a phandle that can't be looked up in the middle
  //  - map with pointers to multiple different parents
}

static void intr_test(void) {
  KTEST_BEGIN("dtint_*(): test setup");
  const size_t kBufLen = 20000;
  void* buf = kmalloc(kBufLen);
  dt_tree_t* tree = NULL;
  KEXPECT_EQ(DTFDT_OK, dt_create(kIntTestDtb, &tree, buf, kBufLen));

  intr_test1(tree);
  intr_test2(tree);
  intr_test3(tree);
  intr_test4(tree);

  kfree(buf);
}

void devicetree_test(int x) {
  KTEST_SUITE_BEGIN("devicetree");
  dtb_print_golden_test();
  dtree_basic_test();
  name_test();
  intr_test();
}
