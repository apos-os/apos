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
#include "common/kstring.h"
#include "dev/devicetree/devicetree.h"
#include "dev/devicetree/dtb.h"
#include "memory/kmalloc.h"
#include "test/ktest.h"

// A sample golden DTB slimmed down from a QEMU-generated riscv virt sample.
static unsigned char kGoldenDtb[] __attribute__((aligned(4))) = {
#include "test/dtb_testdata/large_golden.dts.h"
};

unsigned char kSmallGoldenDtb[] __attribute__((aligned(4))) = {
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

void devicetree_test(int x) {
  KTEST_SUITE_BEGIN("devicetree");
  dtb_print_golden_test();
  dtree_basic_test();
  name_test();
}
