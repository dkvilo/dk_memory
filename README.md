# DK_MEMORY

single-file public domain (or MIT licensed) custom memory management libraries for C/C++

| Library          | LoC | Description                                                 |
| ---------------- | --- | ----------------------------------------------------------- |
| dk_alloc.h       | 811 | General-purpose memory allocator                            |
| dk_memory_pool.h | 645 | Fixed-size memory pool                                      |
| dk_ring_buffer.h | 743 | FIFO-style data handling                                    |
| dk_temp_alloc.h  | 380 | Linear allocator with scoped markers (no overflow handling) |

# Sample

```c

#define DK_ALLOCATOR_IMPLEMENTATION
#include "dk_alloc.h"

#define DK_MEMORY_POOL_IMPLEMENTATION
#include "dk_memory_pool.h"

#define DK_TEMP_ALLOCATOR_IMPLEMENTATION
#include "dk_temp_alloc.h"

typedef float vec3[3];

int main() {

  //
  // General purpose
  //
  DK_Allocator *allocator = DK_AllocatorCreate();

  void* a = DK_Allocate(allocator, 64, 0);
  void* b = DK_Allocate(allocator, 1024, 0);
  void* c = DK_Allocate(allocator, 1024 << 1, 0);

  int vertexCount = 1024;
  vec3* positions = (vec3*)DK_Allocate(allocator, sizeof(vec3) * vertexCount, 0);
  positions[0] = 1.0f;
  DK_Deallocate(allocator, positions);

  positions = DK_Reallocate(allocator, positions, new_size);

  //
  // Memory Pool
  //
  DK_MemoryPool *pool = DK_MemoryPoolCreate(sizeof(char), 1024);
  int* handles[32] = {0};
  for (size_t i = 0; i < 52; i++)
  {
    handles[i] = DK_MemoryPoolAlloc(pool);
  }

  //
  // Temporary allocator
  //
  DK_TempAllocator frame = DK_TempCreate(0); // this will fallback to DK_TEMP_DEFAULT_SIZE (16MB) by default

  char* str = (char*)DK_TempAlloc(frame, 64);
  strcpy(str, "This is a string allocated in the temporary storage.\0");
  printf("String: %s\n", str);

  float* vector = (float*)DK_TempAllocAligned(frame, 4 * sizeof(float), 16);
  vector[0] = 1.0f;
  vector[1] = 2.0f;
  vector[2] = 3.0f;
  vector[3] = 4.0f;

  //
  // scope example with marker
  //
  DK_TEMP_SCOPE_BEGIN(frame);
  size_t  size        = 1024 * sizeof(float);
  size_t  alignment   = 16;
  float   *matrices   = (float*)DK_TempAllocAligned(frame, size, alignment);
  DK_TEMP_SCOPE_END(frame);

  return 0;
}
```
