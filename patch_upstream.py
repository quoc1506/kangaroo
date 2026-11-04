#!/usr/bin/env python3
"""Patch JeanLucPons/Kangaroo for:
1. Portable ARM64 (Linux aarch64 & macOS Apple Silicon) support in SECPK1/Int.h:
   Eliminates invalid '=d'/'=a' asm constraints & x86-only builtins via GCC/Clang 128-bit arithmetic.
2. Multi-GPU safe batched kangaroo respawning (per-instance VRAM buffers, eliminates global static collisions).
3. Asynchronous decoupling (Launch() separates kernel finish & result retrieval from callKernel()).
4. Elimination of OS sleep jitter via persistent cudaEvent_t and hybrid polling.
"""
import os
import re
import sys

def patch_secpk1_int():
    target = "SECPK1/Int.h"
    if not os.path.exists(target):
        return

    with open(target, "r") as f:
        content = f.read()

    if "Portable ARM64" in content:
        print("[*] SECPK1/Int.h already patched for ARM64")
        return

    old_block = '''#ifndef WIN64

// Missing intrinsics
static uint64_t inline _umul128(uint64_t a, uint64_t b, uint64_t *h) {
  uint64_t rhi;
  uint64_t rlo;
  __asm__( "mulq  %[b];" :"=d"(rhi),"=a"(rlo) :"1"(a),[b]"rm"(b));
  *h = rhi;
  return rlo;
}

static int64_t inline _mul128(int64_t a, int64_t b, int64_t *h) {
  uint64_t rhi;
  uint64_t rlo;
  __asm__( "imulq  %[b];" :"=d"(rhi),"=a"(rlo) :"1"(a),[b]"rm"(b));
  *h = rhi;
  return rlo;  
}

static uint64_t inline _udiv128(uint64_t hi, uint64_t lo, uint64_t d,uint64_t *r) {
  uint64_t q;
  uint64_t _r;
  __asm__( "divq  %[d];" :"=d"(_r),"=a"(q) :"d"(hi),"a"(lo),[d]"rm"(d));
  *r = _r;
  return q;  
}

static uint64_t inline __rdtsc() {
  uint32_t h;
  uint32_t l;
  __asm__( "rdtsc;" :"=d"(h),"=a"(l));
  return (uint64_t)h << 32 | (uint64_t)l;
}

#define __shiftright128(a,b,n) ((a)>>(n))|((b)<<(64-(n)))
#define __shiftleft128(a,b,n) ((b)<<(n))|((a)>>(64-(n)))
#define _subborrow_u64(a,b,c,d) __builtin_ia32_sbb_u64(a,b,c,(long long unsigned int*)d);
#define _addcarry_u64(a,b,c,d) __builtin_ia32_addcarryx_u64(a,b,c,(long long unsigned int*)d);
#define _byteswap_uint64 __builtin_bswap64
#define LZC(x) __builtin_clzll(x)
#define TZC(x) __builtin_ctzll(x)

#else'''

    new_block = '''#ifndef WIN64

// Missing intrinsics - Portable ARM64 (aarch64 / Apple Silicon) & x86_64 implementation
#if defined(__x86_64__) || defined(_M_X64)
static uint64_t inline _umul128(uint64_t a, uint64_t b, uint64_t *h) {
  uint64_t rhi;
  uint64_t rlo;
  __asm__( "mulq  %[b];" :"=d"(rhi),"=a"(rlo) :"1"(a),[b]"rm"(b));
  *h = rhi;
  return rlo;
}

static int64_t inline _mul128(int64_t a, int64_t b, int64_t *h) {
  uint64_t rhi;
  uint64_t rlo;
  __asm__( "imulq  %[b];" :"=d"(rhi),"=a"(rlo) :"1"(a),[b]"rm"(b));
  *h = rhi;
  return rlo;  
}

static uint64_t inline _udiv128(uint64_t hi, uint64_t lo, uint64_t d,uint64_t *r) {
  uint64_t q;
  uint64_t _r;
  __asm__( "divq  %[d];" :"=d"(_r),"=a"(q) :"d"(hi),"a"(lo),[d]"rm"(d));
  *r = _r;
  return q;  
}

static uint64_t inline __rdtsc() {
  uint32_t h;
  uint32_t l;
  __asm__( "rdtsc;" :"=d"(h),"=a"(l));
  return (uint64_t)h << 32 | (uint64_t)l;
}

#define _subborrow_u64(a,b,c,d) __builtin_ia32_sbb_u64(a,b,c,(long long unsigned int*)d)
#define _addcarry_u64(a,b,c,d) __builtin_ia32_addcarryx_u64(a,b,c,(long long unsigned int*)d)

#else
// Standard GCC/Clang 128-bit arithmetic & ARM virtual counter for ARM64/Apple Silicon
static inline uint64_t _umul128(uint64_t a, uint64_t b, uint64_t *h) {
  unsigned __int128 res = (unsigned __int128)a * (unsigned __int128)b;
  *h = (uint64_t)(res >> 64);
  return (uint64_t)res;
}

static inline int64_t _mul128(int64_t a, int64_t b, int64_t *h) {
  __int128 res = (__int128)a * (__int128)b;
  *h = (int64_t)(res >> 64);
  return (int64_t)res;
}

static inline uint64_t _udiv128(uint64_t hi, uint64_t lo, uint64_t d, uint64_t *r) {
  unsigned __int128 dividend = ((unsigned __int128)hi << 64) | lo;
  uint64_t q = (uint64_t)(dividend / d);
  *r = (uint64_t)(dividend % d);
  return q;
}

static inline uint64_t __rdtsc() {
#if defined(__aarch64__) || defined(__arm64__)
  uint64_t val;
  __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(val));
  return val;
#else
  return 0ULL;
#endif
}

static inline unsigned char _addcarry_u64(unsigned char c_in, uint64_t a, uint64_t b, void *out) {
  unsigned __int128 sum = (unsigned __int128)a + (unsigned __int128)b + (unsigned __int128)c_in;
  *(uint64_t *)out = (uint64_t)sum;
  return (unsigned char)(sum >> 64);
}

static inline unsigned char _subborrow_u64(unsigned char b_in, uint64_t a, uint64_t b, void *out) {
  unsigned __int128 diff = (unsigned __int128)a - (unsigned __int128)b - (unsigned __int128)(b_in ? 1 : 0);
  *(uint64_t *)out = (uint64_t)diff;
  return (unsigned char)((diff >> 64) ? 1 : 0);
}
#endif

#define __shiftright128(a,b,n) ((a)>>(n))|((b)<<(64-(n)))
#define __shiftleft128(a,b,n) ((b)<<(n))|((a)>>(64-(n)))
#define _byteswap_uint64 __builtin_bswap64
#define LZC(x) __builtin_clzll(x)
#define TZC(x) __builtin_ctzll(x)

#else'''

    if old_block in content:
        content = content.replace(old_block, new_block)
        with open(target, "w") as f:
            f.write(content)
        print("[+] Patched SECPK1/Int.h for ARM64/Apple Silicon compatibility")
    else:
        pat = re.compile(r'#ifndef WIN64.*?#define TZC\(x\) __builtin_ctzll\(x\)\s*#else', re.DOTALL)
        if pat.search(content):
            content = pat.sub(new_block, content, count=1)
            with open(target, "w") as f:
                f.write(content)
            print("[+] Patched SECPK1/Int.h via regex pattern")
        else:
            print("[-] Warning: Could not locate assembly block in SECPK1/Int.h")

def patch_gpu_engine():
    # 1. Patch GPU/GPUEngine.h
    if not os.path.exists("GPU/GPUEngine.h"):
        return
    with open("GPU/GPUEngine.h", "r") as f:
        h = f.read()

    decl = '''typedef struct {
  uint64_t kIdx;
  Int px;
  Int py;
  Int d;
} KangarooRespawnItem;

typedef struct {
  uint64_t kIdx;
  uint64_t px[4];
  uint64_t py[4];
  uint64_t d[2];
} KangarooGpuItem;
'''
    if "KangarooRespawnItem" not in h:
        h = h.replace("typedef struct {", decl + "\ntypedef struct {", 1)
        h = h.replace(
            "void SetKangaroo(uint64_t kIdx,Int *px,Int *py,Int *d);",
            "void SetKangaroo(uint64_t kIdx,Int *px,Int *py,Int *d);\n  void SetKangaroosBatch(const KangarooRespawnItem *items, size_t count);"
        )
        h = h.replace(
            "  bool initialised;",
            "  bool initialised;\n  KangarooGpuItem *d_respawn_buffer;\n  KangarooGpuItem *h_gpu_items;\n  size_t d_respawn_capacity;\n  cudaEvent_t evt_sync;"
        )
        with open("GPU/GPUEngine.h", "w") as f:
            f.write(h)
        print("[+] Patched GPU/GPUEngine.h (Multi-GPU instance buffers & declarations)")

    # 2. Patch GPU/GPUEngine.cu
    if not os.path.exists("GPU/GPUEngine.cu"):
        return
    with open("GPU/GPUEngine.cu", "r") as f:
        cu = f.read()

    if "d_respawn_buffer = NULL;" not in cu:
        cu = cu.replace(
            "  initialised = false;",
            "  initialised = false;\n  d_respawn_buffer = NULL;\n  h_gpu_items = NULL;\n  d_respawn_capacity = 0;\n  evt_sync = NULL;\n  cudaEventCreateWithFlags(&evt_sync, cudaEventDisableTiming);"
        )

    if "if(d_respawn_buffer) cudaFree(d_respawn_buffer);" not in cu:
        cu = cu.replace(
            "  if(jumpPinned) cudaFreeHost(jumpPinned);",
            "  if(jumpPinned) cudaFreeHost(jumpPinned);\n  if(evt_sync) cudaEventDestroy(evt_sync);\n  if(d_respawn_buffer) cudaFree(d_respawn_buffer);\n  if(h_gpu_items) cudaFreeHost(h_gpu_items);"
        )

    old_launch_pattern = '''    // Use cudaMemcpyAsync to avoid default spin wait of cudaMemcpy wich takes 100% CPU
    cudaEvent_t evt;
    cudaEventCreate(&evt);
    cudaMemcpyAsync(outputItemPinned,outputItem,4,cudaMemcpyDeviceToHost,0);
    cudaEventRecord(evt,0);
    while(cudaEventQuery(evt) == cudaErrorNotReady) {
      // Sleep 1 ms to free the CPU
      Timer::SleepMillis(1);
    }
    cudaEventDestroy(evt);'''

    new_launch_wait = '''    // Hybrid spin-yield polling using persistent cudaEvent_t (eliminates 1 to 4 ms sleep bubbles)
    cudaMemcpyAsync(outputItemPinned,outputItem,4,cudaMemcpyDeviceToHost,0);
    cudaEventRecord(evt_sync,0);
    for(int spin = 0; spin < 2000; ++spin) {
      if(cudaEventQuery(evt_sync) == cudaSuccess) break;
      #if defined(__x86_64__) || defined(_M_X64)
      __builtin_ia32_pause();
      #endif
    }
    while(cudaEventQuery(evt_sync) == cudaErrorNotReady) {
      sched_yield();
    }'''

    if old_launch_pattern in cu:
        cu = cu.replace(old_launch_pattern, new_launch_wait)
        print("[+] Patched GPUEngine::Launch wait loop with persistent event & hybrid polling")

    old_launch_tail = '\n  return callKernel();\n\n}'
    new_launch_tail = '\n  return true;\n\n}'
    if old_launch_tail in cu:
        cu = cu.replace(old_launch_tail, new_launch_tail)
        print("[+] Decoupled callKernel() from GPUEngine::Launch() (solves P0 async desync)")

    batch_func = '''__global__ void _SetKangaroosBatchKernel(const KangarooGpuItem *items, size_t count, uint64_t *inputKangaroo, int nbThreadPerGroup, int gSize, int strideSize, int blockSize) {
    size_t i = (size_t)blockIdx.x * (size_t)blockDim.x + (size_t)threadIdx.x;
    if (i >= count) return;
    KangarooGpuItem item = items[i];
    uint64_t kIdx = item.kIdx;
    uint64_t t = kIdx % nbThreadPerGroup;
    uint64_t g = (kIdx / nbThreadPerGroup) % GPU_GRP_SIZE;
    uint64_t b = kIdx / (nbThreadPerGroup * GPU_GRP_SIZE);
    uint64_t baseOffset = b * blockSize + g * strideSize + t;

    inputKangaroo[baseOffset + 0 * nbThreadPerGroup] = item.px[0];
    inputKangaroo[baseOffset + 1 * nbThreadPerGroup] = item.px[1];
    inputKangaroo[baseOffset + 2 * nbThreadPerGroup] = item.px[2];
    inputKangaroo[baseOffset + 3 * nbThreadPerGroup] = item.px[3];

    inputKangaroo[baseOffset + 4 * nbThreadPerGroup] = item.py[0];
    inputKangaroo[baseOffset + 5 * nbThreadPerGroup] = item.py[1];
    inputKangaroo[baseOffset + 6 * nbThreadPerGroup] = item.py[2];
    inputKangaroo[baseOffset + 7 * nbThreadPerGroup] = item.py[3];

    inputKangaroo[baseOffset + 8 * nbThreadPerGroup] = item.d[0];
    inputKangaroo[baseOffset + 9 * nbThreadPerGroup] = item.d[1];
#ifdef USE_SYMMETRY
    inputKangaroo[baseOffset + 10 * nbThreadPerGroup] = (uint64_t)NB_JUMP;
#endif
}

void GPUEngine::SetKangaroosBatch(const KangarooRespawnItem *items, size_t count) {
    if (count == 0 || items == nullptr) return;
    if (count > this->d_respawn_capacity) {
        if (this->d_respawn_buffer) {
            cudaFree(this->d_respawn_buffer);
            this->d_respawn_buffer = nullptr;
        }
        if (this->h_gpu_items) {
            cudaFreeHost(this->h_gpu_items);
            this->h_gpu_items = nullptr;
        }
        this->d_respawn_capacity = 0;
        size_t new_cap = (count < 65536) ? 65536 : count * 2;
        if (cudaMalloc(&this->d_respawn_buffer, new_cap * sizeof(KangarooGpuItem)) == cudaSuccess) {
            if (cudaHostAlloc((void**)&this->h_gpu_items, new_cap * sizeof(KangarooGpuItem), cudaHostAllocDefault) == cudaSuccess) {
                this->d_respawn_capacity = new_cap;
            } else {
                cudaFree(this->d_respawn_buffer);
                this->d_respawn_buffer = nullptr;
            }
        }
    }
    if (this->d_respawn_buffer == nullptr || this->h_gpu_items == nullptr) {
        for (size_t i = 0; i < count; ++i) {
            SetKangaroo(items[i].kIdx, (Int*)&items[i].px, (Int*)&items[i].py, (Int*)&items[i].d);
        }
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        this->h_gpu_items[i].kIdx = items[i].kIdx;
        this->h_gpu_items[i].px[0] = items[i].px.bits64[0];
        this->h_gpu_items[i].px[1] = items[i].px.bits64[1];
        this->h_gpu_items[i].px[2] = items[i].px.bits64[2];
        this->h_gpu_items[i].px[3] = items[i].px.bits64[3];
        this->h_gpu_items[i].py[0] = items[i].py.bits64[0];
        this->h_gpu_items[i].py[1] = items[i].py.bits64[1];
        this->h_gpu_items[i].py[2] = items[i].py.bits64[2];
        this->h_gpu_items[i].py[3] = items[i].py.bits64[3];
        Int dOff = items[i].d;
        if (items[i].kIdx % 2 == WILD) dOff.ModAddK1order(&wildOffset);
        this->h_gpu_items[i].d[0] = dOff.bits64[0];
        this->h_gpu_items[i].d[1] = dOff.bits64[1];
    }
    cudaMemcpy(this->d_respawn_buffer, this->h_gpu_items, count * sizeof(KangarooGpuItem), cudaMemcpyHostToDevice);
    int gSize = KSIZE * GPU_GRP_SIZE;
    int strideSize = nbThreadPerGroup * KSIZE;
    int blockSize = nbThreadPerGroup * gSize;
    int threads = 256;
    int blocks = (int)((count + threads - 1) / threads);
    _SetKangaroosBatchKernel<<<blocks, threads>>>(this->d_respawn_buffer, count, inputKangaroo, nbThreadPerGroup, gSize, strideSize, blockSize);
}
'''
    if "SetKangaroosBatch" not in cu:
        cu += "\n" + batch_func + "\n"

    with open("GPU/GPUEngine.cu", "w") as f:
        f.write(cu)
    print("[+] Patched GPU/GPUEngine.cu (Multi-GPU instance buffers & scatter kernel)")

if __name__ == "__main__":
    patch_secpk1_int()
    patch_gpu_engine()
