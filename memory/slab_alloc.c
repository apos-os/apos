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

#include "common/kassert.h"
#include "common/kstring.h"
#include "memory/kmalloc.h"
#include "memory/page_alloc.h"
#include "memory/slab_alloc.h"

struct slab_alloc {
  int obj_size;  // The object size.
  int max_pages;  // Maximum number of pages to allocate.

  // Up to max_pages pages used for this allocator.  The last portion of
  // each page is a byte-aligned bitmap large enough for a bit for each object
  // in the page.  The rest of the page, starting at offset 0, is enough objects
  // to fit before the bitmap.
  void** pages;

  // Free count for each page.
  int* free_count;
};

#define NUM_OBJECTS(size) (8 * PAGE_SIZE / (8 * (size) + 1))

// Given a page and the number of objects, return the start of the page's
// bitmap.
static inline uint8_t* get_bitmap(int num, void* page) {
  // TODO(aoates): This could be so much more efficient.  And I'm sure it will
  // be a hot spot.
  int bitmap_len;
  if (num % 8 == 0) {
    bitmap_len = num / 8;
  } else {
    bitmap_len = num / 8 + 1;
  }
  return (uint8_t*)page + (PAGE_SIZE - bitmap_len);
}

// Allocate and initialize a new page for the given allocator.
static void* alloc_slab_page(slab_alloc_t* s) {
  uint32_t page_phys = page_frame_alloc();
  uint8_t* page = (uint8_t*)phys2virt(page_phys);

  // Initialize the bitmap.
  const int num = NUM_OBJECTS(s->obj_size);
  uint8_t* bitmap = get_bitmap(num, page);
  kmemset(bitmap, 0xFF, num / 8);  // All free.
  if (num % 8 != 0) {
    switch (num % 8) {
      case 1: bitmap[num / 8] = 0x01; break;
      case 2: bitmap[num / 8] = 0x03; break;
      case 3: bitmap[num / 8] = 0x07; break;
      case 4: bitmap[num / 8] = 0x0F; break;
      case 5: bitmap[num / 8] = 0x1F; break;
      case 6: bitmap[num / 8] = 0x3F; break;
      case 7: bitmap[num / 8] = 0x7F; break;
    }
  }
  return (void*)page;
}

slab_alloc_t* slab_alloc_create(int obj_size, int max_pages) {
  slab_alloc_t* s = (slab_alloc_t*)kmalloc(sizeof(slab_alloc_t));
  s->obj_size = obj_size;
  s->max_pages = max_pages;
  s->pages = (void**)kmalloc(sizeof(void*) * max_pages);
  s->free_count = (int*)kmalloc(sizeof(int) * max_pages);
  int num_objects = NUM_OBJECTS(obj_size);
  for (int i = 0; i < max_pages; ++i) {
    s->pages[i] = 0x0;
    s->free_count[i] = num_objects;
  }

  // Go ahead and allocate the first page.
  s->pages[0] = alloc_slab_page(s);

  return s;
}

void slab_alloc_destroy(slab_alloc_t* s) {
  for (int i = 0; i < s->max_pages; ++i) {
    if (s->pages[i] != 0x0) {
      page_frame_free(virt2phys((uint32_t)s->pages[i]));
      s->pages[i] = 0x0;
    }
  }
  kfree(s->pages);
  kfree(s->free_count);
  s->pages = 0x0;
  s->free_count = 0x0;
  kfree(s);
}

void* slab_alloc(slab_alloc_t* s) {
  // Find a free page.
  int i;
  for (i = 0; i < s->max_pages; ++i) {
    if (s->pages[i] != 0x0 && s->free_count[i] > 0) {
      break;
    }
  }

  const int num_objects = NUM_OBJECTS(s->obj_size);

  // If no free pages, create a new one.
  if (i >= s->max_pages) {
    for (i = 0; i < s->max_pages; ++i) {
      if (s->pages[i] == 0x0) {
        break;
      }
    }

    // Allocator is full :(
    if (i >= s->max_pages) {
      return 0x0;
    }

    s->pages[i] = alloc_slab_page(s);
    s->free_count[i] = num_objects;
  }

  KASSERT(i >= 0 && i < s->max_pages);
  KASSERT(s->free_count[i] > 0);

  // Find a free object in that page.
  uint8_t* bitmap = get_bitmap(num_objects, s->pages[i]);
  int bitmap_idx = 0;
  while (bitmap[bitmap_idx] == 0x00) bitmap_idx++;
  KASSERT((uint32_t)bitmap + bitmap_idx < (uint32_t)s->pages[i] + PAGE_SIZE);

  // Get a free page from that 8-block.
  int obj_idx = bitmap_idx * 8;
  KASSERT(bitmap[bitmap_idx] != 0);
  if (bitmap[bitmap_idx] &      0b11110000) {
    if (bitmap[bitmap_idx] &    0b11000000) {
      if (bitmap[bitmap_idx] &  0b10000000) {
        bitmap[bitmap_idx] &=  ~0b10000000;
        obj_idx += 7;
      } else {
        bitmap[bitmap_idx] &=  ~0b01000000;
        obj_idx += 6;
      }
    } else {
      if (bitmap[bitmap_idx] &  0b00100000) {
        bitmap[bitmap_idx] &=  ~0b00100000;
        obj_idx += 5;
      } else {
        bitmap[bitmap_idx] &=  ~0b00010000;
        obj_idx += 4;
      }
    }
  } else {
    if (bitmap[bitmap_idx] &    0b00001100) {
      if (bitmap[bitmap_idx] &  0b00001000) {
        bitmap[bitmap_idx] &=  ~0b00001000;
        obj_idx += 3;
      } else {
        bitmap[bitmap_idx] &=  ~0b00000100;
        obj_idx += 2;
      }
    } else {
      if (bitmap[bitmap_idx] &  0b00000010) {
        bitmap[bitmap_idx] &=  ~0b00000010;
        obj_idx += 1;
      } else {
        bitmap[bitmap_idx] &=  ~0b00000001;
      }
    }
  }

  s->free_count[i]--;
  KASSERT_DBG(s->free_count[i] >= 0);

  return (void*)(s->pages[i] + obj_idx * s->obj_size);
}

void slab_free(slab_alloc_t* s, void* x) {
  // Find the page the thing is in.
  KASSERT(((uint32_t)x % PAGE_SIZE) % s->obj_size == 0);

  int i;
  for (i = 0; i < s->max_pages; ++i) {
    if (s->pages[i] != 0x0 && x >= s->pages[i] && x < s->pages[i] + PAGE_SIZE) {
      break;
    }
  }
  KASSERT(i < s->max_pages);

  const int obj_idx = ((uint32_t)x % 4096) / s->obj_size;
  const int num_objects = NUM_OBJECTS(s->obj_size);
  KASSERT(obj_idx < num_objects);

  // TODO(aoates): pull these bitmap functions into a common area.
  uint8_t* bitmap = get_bitmap(num_objects, s->pages[i]);
  bitmap += obj_idx / 8;
  switch (obj_idx % 8) {
    case 0: *bitmap |= 0b00000001; break;
    case 1: *bitmap |= 0b00000010; break;
    case 2: *bitmap |= 0b00000100; break;
    case 3: *bitmap |= 0b00001000; break;
    case 4: *bitmap |= 0b00010000; break;
    case 5: *bitmap |= 0b00100000; break;
    case 6: *bitmap |= 0b01000000; break;
    case 7: *bitmap |= 0b10000000; break;
  }
  s->free_count[i]++;
  KASSERT_DBG(s->free_count[i] <= num_objects);
}
