#!/usr/bin/env python3
"""
Patch JeanLucPons/Kangaroo GPU files to support batch kangaroo respawning.
Eliminates PCIe stall caused by thousands of synchronous 8-byte cudaMemcpy calls.
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
        with open("GPU/GPUEngine.h", "w") as f:
            f.write(h)
        print("[+] Patched GPU/GPUEngine.h")

    # 2. Patch GPU/GPUEngine.cu
    with open("GPU/GPUEngine.cu", "r") as f:
        cu = f.read()

    batch_func = '''static KangarooGpuItem *g_h_gpu_items = nullptr;
static KangarooGpuItem *g_d_respawn_buffer = nullptr;
static size_t g_d_respawn_capacity = 0;

__global__ void _SetKangaroosBatchKernel(const KangarooGpuItem *items, size_t count, uint64_t *inputKangaroo, int nbThreadPerGroup, int gSize, int strideSize, int blockSize) {
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
    if (count > g_d_respawn_capacity) {
        if (g_d_respawn_buffer) {
            cudaFree(g_d_respawn_buffer);
            g_d_respawn_buffer = nullptr;
        }
        if (g_h_gpu_items) {
            free(g_h_gpu_items);
            g_h_gpu_items = nullptr;
        }
        g_d_respawn_capacity = 0;

        size_t new_cap = (count < 65536) ? 65536 : count * 2;
        if (cudaMalloc(&g_d_respawn_buffer, new_cap * sizeof(KangarooGpuItem)) == cudaSuccess) {
            g_h_gpu_items = (KangarooGpuItem*)malloc(new_cap * sizeof(KangarooGpuItem));
            if (g_h_gpu_items) {
                g_d_respawn_capacity = new_cap;
            } else {
                cudaFree(g_d_respawn_buffer);
                g_d_respawn_buffer = nullptr;
            }
        }
    }

    if (g_d_respawn_buffer == nullptr || g_h_gpu_items == nullptr) {
        for (size_t i = 0; i < count; ++i) {
            SetKangaroo(items[i].kIdx, (Int*)&items[i].px, (Int*)&items[i].py, (Int*)&items[i].d);
        }
        return;
    }

    for (size_t i = 0; i < count; ++i) {
        g_h_gpu_items[i].kIdx = items[i].kIdx;
        g_h_gpu_items[i].px[0] = items[i].px.bits64[0];
        g_h_gpu_items[i].px[1] = items[i].px.bits64[1];
        g_h_gpu_items[i].px[2] = items[i].px.bits64[2];
        g_h_gpu_items[i].px[3] = items[i].px.bits64[3];
        g_h_gpu_items[i].py[0] = items[i].py.bits64[0];
        g_h_gpu_items[i].py[1] = items[i].py.bits64[1];
        g_h_gpu_items[i].py[2] = items[i].py.bits64[2];
        g_h_gpu_items[i].py[3] = items[i].py.bits64[3];
        Int dOff = items[i].d;
        if (items[i].kIdx % 2 == WILD) dOff.ModAddK1order(&wildOffset);
        g_h_gpu_items[i].d[0] = dOff.bits64[0];
        g_h_gpu_items[i].d[1] = dOff.bits64[1];
    }

    cudaMemcpy(g_d_respawn_buffer, g_h_gpu_items, count * sizeof(KangarooGpuItem), cudaMemcpyHostToDevice);
    int gSize = KSIZE * GPU_GRP_SIZE;
    int strideSize = nbThreadPerGroup * KSIZE;
    int blockSize = nbThreadPerGroup * gSize;
    int threads = 256;
    int blocks = (int)((count + threads - 1) / threads);
    _SetKangaroosBatchKernel<<<blocks, threads>>>(g_d_respawn_buffer, count, inputKangaroo, nbThreadPerGroup, gSize, strideSize, blockSize);
}
'''

    if "SetKangaroosBatch" not in cu:
        cu += "\n" + batch_func + "\n"
        with open("GPU/GPUEngine.cu", "w") as f:
            f.write(cu)
        print("[+] Patched GPU/GPUEngine.cu")

if __name__ == "__main__":
    patch_gpu_engine()
