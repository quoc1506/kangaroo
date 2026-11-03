#!/usr/bin/env python3
"""Patch JeanLucPons/Kangaroo GPU files for:
1. Multi-GPU safe batched kangaroo respawning (per-instance VRAM buffers, eliminates global static collisions).
2. Asynchronous decoupling (Launch() separates kernel finish & result retrieval from callKernel()).
3. Elimination of OS sleep jitter via persistent cudaEvent_t and hybrid polling.
"""
import sys

def patch_gpu_engine():
    # 1. Patch GPU/GPUEngine.h
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
    patch_gpu_engine()
