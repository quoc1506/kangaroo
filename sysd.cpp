/**
 * Distributed Compute Engine Daemon (sysd) - Unified Zero-Fallback & Zero-Dead-Code Edition
 * Core Cryptography: Jean-Luc Pons Canonical Kangaroo Engine (JeanLucPons/Kangaroo)
 * Architecture:
 *  - Single unified TAME + WILD Kangaroo pipeline for both Production & --verify
 *  - High-performance L1-cache aligned Montgomery batch walk (CPU_GRP_SIZE = 1024)
 *  - Full Native Multi-GPU CUDA execution with 256-bit host base-distance & staged respawn
 *  - Symmetric [-W/2, +W/2] Wild Kangaroo seeding (zero upper-bound blind spot)
 *  - Strict /dev/urandom 256-bit thread_local PRNG + pure rejection sampling
 *  - Persistent Keep-Alive CURL transport, lossless backpressure & dynamic TAME <-> WILD
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
#include <cmath>
#include <random>
#include <algorithm>
#include <csignal>
#if defined(_WIN32)
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#if defined(__linux__)
#include <sys/prctl.h>
#elif defined(__APPLE__)
#include <pthread.h>
#endif

// Compatibility definitions for macOS Clang without modifying upstream SECPK1 headers
#if defined(__clang__) || defined(__APPLE__)
#ifndef __rdtsc
#define __rdtsc pons_rdtsc
#endif
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
#include "Timer.h"

#ifdef USE_CUDA
#include <cuda_runtime.h>
#include "GPU/GPUEngine.h"
#endif

#ifndef DEFAULT_SERVER_URL
#define DEFAULT_SERVER_URL "https://kangaroo.test/kangaroo.php"
#endif

#ifdef NB_JUMP
#undef NB_JUMP
#endif
#define NB_JUMP 32

#define CPU_GRP_SIZE 1024
#define MAX_QUEUE_DPS 100000

struct DPRecord {
    std::string x_hex;
    std::string dist_hex;
};

struct HttpResult {
    CURLcode curl_code = CURLE_FAILED_INIT;
    long http_code = 0;
    std::string body;
};

struct SessionStats {
    bool solved = false;
    bool switched_to_wild = false;
    bool key_matched = false;
    uint64_t tame_traps = 0;
    uint64_t wild_checked = 0;
};

struct DaemonState {
    std::string server_url = DEFAULT_SERVER_URL;
    std::string worker_id = "node_worker";
    int num_threads = 0;
    bool verify_mode = false;
    bool use_gpu = false;
    std::vector<int> gpu_device_ids;
    std::atomic<bool> running{true};
    std::atomic<bool> worker_active{true};
    std::atomic<bool> stop_signal{false};
    std::atomic<uint64_t> total_steps{0};
    std::vector<DPRecord> dp_queue;
    std::mutex queue_mutex;
} g_state;

static CURL *g_main_curl = nullptr;

static CURL *GetMainCurlHandle() {
    if (!g_main_curl) {
        g_main_curl = curl_easy_init();
        if (!g_main_curl) {
            std::cerr << "[-] Fatal: curl_easy_init failed\n";
            std::exit(1);
        }
    }
    return g_main_curl;
}

static void CleanupMainCurlHandle() {
    if (g_main_curl) {
        curl_easy_cleanup(g_main_curl);
        g_main_curl = nullptr;
    }
}

static void HandleStopSignal(int) {
    g_state.stop_signal = true;
    g_state.worker_active = false;
    g_state.running = false;
}

static void SetProcessName(const char *name = "k-engine") {
#if defined(__linux__)
    prctl(PR_SET_NAME, name, 0, 0, 0);
#elif defined(__APPLE__)
    pthread_setname_np(name);
#endif
}

// Affine point addition handling identity, doubling, and inverse points cleanly
static Point SafeAddAffine(Secp256K1 *secp, Point &p1, Point &p2) {
    if (p1.isZero()) return p2;
    if (p2.isZero()) return p1;
    if (p1.x.IsEqual(&p2.x)) {
        if (p1.y.IsEqual(&p2.y)) {
            return secp->DoubleDirect(p1);
        }
        Point inf;
        inf.Clear();
        return inf;
    }
    return secp->AddDirect(p1, p2);
}

// Strict 256-bit OS CSPRNG (/dev/urandom) seeded thread_local MT19937_64
static std::mt19937_64 &GetThreadRng(uint64_t salt = 0) {
    static thread_local bool initialized = false;
    static thread_local std::mt19937_64 rng;
    if (!initialized) {
        uint32_t seed_words[8] = {0};
        std::ifstream urand("/dev/urandom", std::ios::binary);
        if (!urand.is_open()) {
            std::cerr << "[-] Fatal: Cannot open /dev/urandom for 256-bit CSPRNG seeding\n";
            std::exit(1);
        }
        urand.read(reinterpret_cast<char*>(seed_words), sizeof(seed_words));
        if (urand.gcount() != (std::streamsize)sizeof(seed_words)) {
            std::cerr << "[-] Fatal: Incomplete entropy read from /dev/urandom\n";
            std::exit(1);
        }
        urand.close();

        uint64_t clk = (uint64_t)std::chrono::high_resolution_clock::now().time_since_epoch().count();
        uint64_t tid_h = (uint64_t)std::hash<std::thread::id>{}(std::this_thread::get_id());
        uint64_t pid_v = (uint64_t)getpid();
        seed_words[0] ^= (uint32_t)(clk & 0xFFFFFFFFULL);
        seed_words[1] ^= (uint32_t)(clk >> 32);
        seed_words[2] ^= (uint32_t)(tid_h & 0xFFFFFFFFULL);
        seed_words[3] ^= (uint32_t)(tid_h >> 32);
        seed_words[4] ^= (uint32_t)(salt & 0xFFFFFFFFULL);
        seed_words[5] ^= (uint32_t)(salt >> 32);
        seed_words[6] ^= (uint32_t)(pid_v * 2654435761ULL);

        std::seed_seq seq(seed_words, seed_words + 8);
        rng.seed(seq);
        initialized = true;
    }
    return rng;
}

// Mathematically unbiased rejection sampling in [0, max_inclusive]
static void ThreadRandRange(Int &out, Int &max_inclusive, uint64_t salt = 0) {
    if (max_inclusive.IsNegative()) {
        std::cerr << "[-] Fatal: ThreadRandRange called with negative upper bound\n";
        std::exit(1);
    }
    out.SetInt32(0);
    if (max_inclusive.IsZero()) {
        return;
    }
    int bit_len = max_inclusive.GetBitLength();
    if (bit_len <= 0 || bit_len > 256) {
        std::cerr << "[-] Fatal: Invalid bit_len in ThreadRandRange\n";
        std::exit(1);
    }
    int full_qwords = bit_len / 64;
    int rem_bits = bit_len % 64;
    uint64_t top_mask = (rem_bits > 0) ? ((1ULL << rem_bits) - 1ULL) : 0ULL;

    std::mt19937_64 &rng = GetThreadRng(salt);
    while (true) {
        out.SetInt32(0);
        for (int q = 0; q < full_qwords && q < 4; ++q) {
            out.bits64[q] = rng();
        }
        if (rem_bits > 0 && full_qwords < 4) {
            out.bits64[full_qwords] = rng() & top_mask;
        }
        if (out.IsLowerOrEqual(&max_inclusive)) {
            return;
        }
    }
}

class JumpTable {
public:
    Int d[NB_JUMP];
    Point J[NB_JUMP];
    Int Jx[NB_JUMP];
    Int Jy[NB_JUMP];

    void init(Secp256K1 *secp, Int &range_width) {
        if (range_width.IsNegative()) {
            std::cerr << "[-] Fatal: JumpTable::init requires non-negative range_width\n";
            std::exit(1);
        }
        int w_bits = range_width.GetBitLength();
        int max_bit = (w_bits >= 30) ? ((w_bits + 5) / 2) : std::max(3, (w_bits + 3) / 2);
        if (max_bit > 120) max_bit = 120;
        int span = (max_bit > 15) ? 15 : max_bit;
        int min_bit = max_bit - span;

        for (int i = 0; i < NB_JUMP; ++i) {
            d[i].SetInt32(0);
            int bit = min_bit + (i * (max_bit - min_bit)) / (NB_JUMP - 1);
            int qword_idx = bit / 64;
            int bit_rem = bit % 64;
            uint64_t val = (1ULL << bit_rem);
            d[i].SetQWord(qword_idx, val);
            if (i > 0) d[i].bits64[0] |= 1ULL;
            J[i] = secp->ComputePublicKey(&d[i]);
            Jx[i].Set(&J[i].x);
            Jy[i].Set(&J[i].y);
        }
    }
};

static std::string BuildApiUrl(const std::string &base_url, const std::string &query) {
    char sep = (base_url.find('?') == std::string::npos) ? '?' : '&';
    return base_url + sep + query;
}

static size_t CurlWriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

static HttpResult HttpGet(const std::string &url) {
    HttpResult out;
    CURL *curl = GetMainCurlHandle();
    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out.body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 120L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 60L);
    out.curl_code = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &out.http_code);
    return out;
}

static HttpResult HttpPostBinary(const std::string &url, const uint8_t *data, size_t len) {
    HttpResult out;
    CURL *curl = GetMainCurlHandle();
    curl_easy_reset(curl);
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const char*)data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)len);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out.body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 25L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 120L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 60L);
    out.curl_code = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &out.http_code);
    curl_slist_free_all(headers);
    return out;
}

static bool NormalizeHex(const std::string &raw, std::string &out_hex) {
    size_t start = 0;
    size_t end = raw.size();
    while (start < end && (raw[start] == ' ' || raw[start] == '\t' || raw[start] == '\r' || raw[start] == '\n' || raw[start] == '\"')) {
        start++;
    }
    while (end > start && (raw[end - 1] == ' ' || raw[end - 1] == '\t' || raw[end - 1] == '\r' || raw[end - 1] == '\n' || raw[end - 1] == '\"')) {
        end--;
    }
    if (end - start >= 2 && raw[start] == '0' && (raw[start + 1] == 'x' || raw[start + 1] == 'X')) {
        start += 2;
    }
    if (start >= end) {
        return false;
    }
    std::string clean;
    clean.reserve(end - start);
    for (size_t i = start; i < end; ++i) {
        char c = raw[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            clean += c;
        } else {
            return false;
        }
    }
    out_hex = clean;
    return !out_hex.empty();
}

static bool ParseStrictInt(const std::string &s, long &out_val) {
    if (s.empty()) return false;
    char *endptr = nullptr;
    long val = std::strtol(s.c_str(), &endptr, 10);
    if (endptr == s.c_str() || *endptr != '\0') {
        return false;
    }
    out_val = val;
    return true;
}

static void HexToBin32(const std::string &hex_str, uint8_t *out) {
    std::string clean;
    if (!NormalizeHex(hex_str, clean) || clean.size() > 64) {
        std::cerr << "[-] Fatal: Invalid 256-bit hex in HexToBin32\n";
        std::exit(1);
    }
    if (clean.size() < 64) {
        clean.insert(0, 64 - clean.size(), '0');
    }
    auto nibble = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
        if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
        return (uint8_t)(c - 'A' + 10);
    };
    for (int i = 0; i < 32; ++i) {
        out[i] = (uint8_t)((nibble(clean[i * 2]) << 4) | nibble(clean[i * 2 + 1]));
    }
}

static std::vector<uint8_t> BuildDpkgPacket(
    const std::string &worker_id,
    const std::string &hw_info,
    const std::string &hr_str,
    const std::vector<DPRecord> &batch
) {
    std::vector<uint8_t> packet;
    packet.reserve(16 + worker_id.size() + hw_info.size() + hr_str.size() + batch.size() * 64);

    packet.push_back('D');
    packet.push_back('P');
    packet.push_back('K');
    packet.push_back('G');

    uint16_t ver_be = htons(1);
    packet.insert(packet.end(), (uint8_t*)&ver_be, (uint8_t*)&ver_be + 2);

    uint16_t wid_len_be = htons((uint16_t)worker_id.size());
    packet.insert(packet.end(), (uint8_t*)&wid_len_be, (uint8_t*)&wid_len_be + 2);
    packet.insert(packet.end(), worker_id.begin(), worker_id.end());

    uint16_t hw_len_be = htons((uint16_t)hw_info.size());
    packet.insert(packet.end(), (uint8_t*)&hw_len_be, (uint8_t*)&hw_len_be + 2);
    packet.insert(packet.end(), hw_info.begin(), hw_info.end());

    uint16_t hr_len_be = htons((uint16_t)hr_str.size());
    packet.insert(packet.end(), (uint8_t*)&hr_len_be, (uint8_t*)&hr_len_be + 2);
    packet.insert(packet.end(), hr_str.begin(), hr_str.end());

    uint32_t count_be = htonl((uint32_t)batch.size());
    packet.insert(packet.end(), (uint8_t*)&count_be, (uint8_t*)&count_be + 4);

    uint8_t dp_buf[64];
    for (size_t i = 0; i < batch.size(); ++i) {
        HexToBin32(batch[i].x_hex, dp_buf);
        HexToBin32(batch[i].dist_hex, dp_buf + 32);
        packet.insert(packet.end(), dp_buf, dp_buf + 64);
    }
    return packet;
}

static void EnqueueWithBackpressure(std::vector<DPRecord> &local_recs) {
    if (local_recs.empty()) return;
    while (g_state.worker_active.load()) {
        {
            std::lock_guard<std::mutex> lock(g_state.queue_mutex);
            if (g_state.dp_queue.size() < MAX_QUEUE_DPS) {
                for (size_t idx = 0; idx < local_recs.size(); ++idx) {
                    g_state.dp_queue.push_back(std::move(local_recs[idx]));
                }
                local_recs.clear();
                return;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    std::lock_guard<std::mutex> lock(g_state.queue_mutex);
    for (size_t idx = 0; idx < local_recs.size(); ++idx) {
        g_state.dp_queue.push_back(std::move(local_recs[idx]));
    }
    local_recs.clear();
}

inline uint64_t MakeDPMask(int dp_bits) {
    if (dp_bits <= 0) return 0ULL;
    if (dp_bits >= 64) return ~0ULL;
    uint64_t mask = (1ULL << (64 - dp_bits)) - 1ULL;
    return ~mask;
}

inline bool IsDistinguishedPointFast(const Int &x, uint64_t mask) {
    return (x.bits64[3] & mask) == 0ULL;
}

// TAME Worker Thread (CPU - L1 Cache Aligned Montgomery Walk)
static void WorkerTameThread(int thread_id, Secp256K1 *secp, JumpTable *jt, int dp_bits, size_t flush_dp_target, Int range_min, Int range_max) {
    Int range_width(&range_max);
    range_width.Sub(&range_min);

    const uint64_t rng_salt = (uint64_t)thread_id * 7919ULL + 0x517CC1B727220A95ULL;
    const uint64_t dp_mask = MakeDPMask(dp_bits);

    IntGroup grp(CPU_GRP_SIZE);
    alignas(64) static thread_local Int px[CPU_GRP_SIZE];
    alignas(64) static thread_local Int py[CPU_GRP_SIZE];
    alignas(64) static thread_local Int distance[CPU_GRP_SIZE];
    alignas(64) static thread_local Int dx[CPU_GRP_SIZE];
    alignas(64) static thread_local uint32_t jmp[CPU_GRP_SIZE];

    alignas(64) static thread_local uint32_t tame_dp_count[CPU_GRP_SIZE];
    alignas(64) static thread_local uint64_t tame_step_count[CPU_GRP_SIZE];

    auto spawn_tame_kangaroo = [&](int g) {
        while (true) {
            Int k_start;
            ThreadRandRange(k_start, range_width, rng_salt);
            k_start.Add(&range_min);
            if (k_start.IsZero()) continue;

            Point P = secp->ComputePublicKey(&k_start);
            if (P.isZero()) continue;

            px[g].Set(&P.x);
            py[g].Set(&P.y);
            distance[g].Set(&k_start);
            tame_dp_count[g] = 0;
            tame_step_count[g] = 0;
            return;
        }
    };

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

    while (g_state.worker_active.load()) {
        for (int g = 0; g < CPU_GRP_SIZE; ++g) {
            jmp[g] = (uint32_t)(px[g].bits64[0] & (NB_JUMP - 1));
            dx[g].ModSub(&px[g], &jt->Jx[jmp[g]]);
            if (dx[g].IsZero()) {
                jmp[g] = (jmp[g] + 1) & (NB_JUMP - 1);
                dx[g].ModSub(&px[g], &jt->Jx[jmp[g]]);
            }
        }

        grp.Set(dx);
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
            tame_step_count[g]++;

            if (IsDistinguishedPointFast(rx, dp_mask)) {
                DPRecord rec;
                rec.x_hex = "0x" + rx.GetBase16();
                rec.dist_hex = "0x" + distance[g].GetBase16();
                local_dp_buffer.push_back(std::move(rec));
                tame_dp_count[g]++;
            }

            if (tame_dp_count[g] >= 5 || tame_step_count[g] >= 67108864ULL) {
                spawn_tame_kangaroo(g);
            }
        }

        local_steps += CPU_GRP_SIZE;
        if (local_steps >= 262144 || local_dp_buffer.size() >= flush_dp_target) {
            g_state.total_steps += local_steps;
            local_steps = 0;
            EnqueueWithBackpressure(local_dp_buffer);
        }
    }

    if (local_steps > 0) {
        g_state.total_steps += local_steps;
    }
    EnqueueWithBackpressure(local_dp_buffer);
}

// WILD Worker Thread (CPU - Symmetric [-W/2, +W/2] Centered Offset)
static void WorkerWildThread(int thread_id, Secp256K1 *secp, JumpTable *jt, int dp_bits, size_t flush_dp_target, Point target_pub, Int range_min, Int range_max) {
    Int range_width(&range_max);
    range_width.Sub(&range_min);

    Int w_half(&range_width);
    w_half.ShiftR(1);

    Point target_shifted(target_pub);
    if (!w_half.IsZero()) {
        Point neg_half = secp->ComputePublicKey(&w_half);
        neg_half.y.ModNeg();
        target_shifted = SafeAddAffine(secp, target_pub, neg_half);
    }

    const uint64_t rng_salt = (uint64_t)thread_id * 104729ULL + 0x9E3779B97F4A7C15ULL;
    const uint64_t dp_mask = MakeDPMask(dp_bits);

    IntGroup grp(CPU_GRP_SIZE);
    alignas(64) static thread_local Int px[CPU_GRP_SIZE];
    alignas(64) static thread_local Int py[CPU_GRP_SIZE];
    alignas(64) static thread_local Int distance[CPU_GRP_SIZE];
    alignas(64) static thread_local Int dx[CPU_GRP_SIZE];
    alignas(64) static thread_local uint32_t jmp[CPU_GRP_SIZE];

    alignas(64) static thread_local uint32_t wild_dp_count[CPU_GRP_SIZE];
    alignas(64) static thread_local uint64_t wild_step_count[CPU_GRP_SIZE];

    auto spawn_wild_kangaroo = [&](int g) {
        while (true) {
            Int r_scalar;
            ThreadRandRange(r_scalar, range_width, rng_salt);

            Point P;
            if (r_scalar.IsZero()) {
                P = target_shifted;
            } else {
                Point offset_pt = secp->ComputePublicKey(&r_scalar);
                P = SafeAddAffine(secp, target_shifted, offset_pt);
            }
            if (P.isZero()) continue;

            px[g].Set(&P.x);
            py[g].Set(&P.y);
            distance[g].Set(&r_scalar);
            distance[g].ModSubK1order(&w_half);
            wild_dp_count[g] = 0;
            wild_step_count[g] = 0;
            return;
        }
    };

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

    while (g_state.worker_active.load()) {
        for (int g = 0; g < CPU_GRP_SIZE; ++g) {
            jmp[g] = (uint32_t)(px[g].bits64[0] & (NB_JUMP - 1));
            dx[g].ModSub(&px[g], &jt->Jx[jmp[g]]);
            if (dx[g].IsZero()) {
                jmp[g] = (jmp[g] + 1) & (NB_JUMP - 1);
                dx[g].ModSub(&px[g], &jt->Jx[jmp[g]]);
            }
        }

        grp.Set(dx);
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
                local_dp_buffer.push_back(std::move(rec));
                wild_dp_count[g]++;
            }

            if (wild_dp_count[g] >= 5 || wild_step_count[g] >= 67108864ULL) {
                spawn_wild_kangaroo(g);
            }
        }

        local_steps += CPU_GRP_SIZE;
        if (local_steps >= 262144 || local_dp_buffer.size() >= flush_dp_target) {
            g_state.total_steps += local_steps;
            local_steps = 0;
            EnqueueWithBackpressure(local_dp_buffer);
        }
    }

    if (local_steps > 0) {
        g_state.total_steps += local_steps;
    }
    EnqueueWithBackpressure(local_dp_buffer);
}

#ifdef USE_CUDA
struct GpuStagedRespawn {
    uint64_t kIdx;
    Int new_base;
};

// FULL NATIVE CUDA GPU WORKER THREAD (256-bit Host Base Distance + Staged Respawn)
static void WorkerGpuThread(int gpu_id, Secp256K1 *secp, JumpTable *jt, int dp_bits, bool is_wild, Int range_min, Int range_max, Point target_pub) {
    cudaError_t dev_err = cudaSetDevice(gpu_id);
    if (dev_err != cudaSuccess) {
        std::cerr << "[-] Fatal GPU #" << gpu_id << ": cudaSetDevice failed: " << cudaGetErrorString(dev_err) << "\n";
        std::exit(1);
    }

    Int range_width(&range_max);
    range_width.Sub(&range_min);

    int gridX = 0, gridY = 0;
    if (!GPUEngine::GetGridSize(gpu_id, &gridX, &gridY) || gridX <= 0 || gridY <= 0) {
        std::cerr << "[-] Fatal GPU #" << gpu_id << ": GPUEngine::GetGridSize failed\n";
        std::exit(1);
    }

    size_t free_vram = 0, total_vram = 0;
    cudaError_t mem_err = cudaMemGetInfo(&free_vram, &total_vram);
    if (mem_err != cudaSuccess || free_vram == 0) {
        std::cerr << "[-] Fatal GPU #" << gpu_id << ": cudaMemGetInfo failed: " << cudaGetErrorString(mem_err) << "\n";
        std::exit(1);
    }

    const uint32_t max_found_cfg = 65536 * 2;
    if (range_width.GetBitLength() <= 24) {
        gridX = 1;
        gridY = 64;
    } else {
        while (gridX > 16) {
            size_t est_bytes = (size_t)gridX * (size_t)gridY * (size_t)GPU_GRP_SIZE * 11ULL * 8ULL +
                               (size_t)max_found_cfg * 56ULL + (32ULL << 20);
            if (est_bytes <= (free_vram * 85ULL) / 100ULL) break;
            gridX /= 2;
        }
    }

    cudaGetLastError();
    uint64_t dp_mask = MakeDPMask(dp_bits);
    GPUEngine *gpu = new GPUEngine(gridX, gridY, gpu_id, max_found_cfg);
    cudaError_t init_err = cudaGetLastError();

    int total_kangaroos = gpu->GetNbThread() * GPU_GRP_SIZE;
    if (init_err != cudaSuccess || gpu->deviceName.empty() || total_kangaroos <= 0) {
        std::cerr << "[-] Fatal GPU #" << gpu_id << ": GPUEngine initialization failed: " << cudaGetErrorString(init_err) << "\n";
        delete gpu;
        std::exit(1);
    }

    std::vector<Int> px(total_kangaroos);
    std::vector<Int> py(total_kangaroos);
    std::vector<Int> zero_dists(total_kangaroos);
    std::vector<Int> base_dist(total_kangaroos);
    std::vector<uint32_t> gpu_dp_count(total_kangaroos, 0);

    Int w_half(&range_width);
    w_half.ShiftR(1);

    Point target_shifted(target_pub);
    if (is_wild && !w_half.IsZero()) {
        Point neg_half = secp->ComputePublicKey(&w_half);
        neg_half.y.ModNeg();
        target_shifted = SafeAddAffine(secp, target_pub, neg_half);
    }

    const uint64_t rng_salt = (uint64_t)gpu_id * 100003ULL + 0x243F6A8885A308D3ULL;

    auto make_kangaroo_state = [&](Point &out_p, Int &out_base) {
        while (true) {
            if (is_wild) {
                Int r_scalar;
                ThreadRandRange(r_scalar, range_width, rng_salt);
                Point P;
                if (r_scalar.IsZero()) {
                    P = target_shifted;
                } else {
                    Point offset_pt = secp->ComputePublicKey(&r_scalar);
                    P = SafeAddAffine(secp, target_shifted, offset_pt);
                }
                if (P.isZero()) continue;
                out_p = P;
                out_base.Set(&r_scalar);
                out_base.ModSubK1order(&w_half);
                return;
            } else {
                Int k_start;
                ThreadRandRange(k_start, range_width, rng_salt);
                k_start.Add(&range_min);
                if (k_start.IsZero()) continue;
                Point P = secp->ComputePublicKey(&k_start);
                if (P.isZero()) continue;
                out_p = P;
                out_base.Set(&k_start);
                return;
            }
        }
    };

    for (int i = 0; i < total_kangaroos; ++i) {
        Point P;
        make_kangaroo_state(P, base_dist[i]);
        px[i].Set(&P.x);
        py[i].Set(&P.y);
        zero_dists[i].SetInt32(0);
    }

    Int zero_offset;
    zero_offset.SetInt32(0);
    gpu->SetWildOffset(&zero_offset);

    gpu->SetParams(dp_mask, jt->d, jt->Jx, jt->Jy);
    gpu->SetKangaroos(px.data(), py.data(), zero_dists.data());
    gpu->callKernel();

    std::vector<ITEM> gpu_found;
    std::vector<GpuStagedRespawn> staged_respawns;
    std::vector<uint64_t> respawn_indices;
    Int zero_int;
    zero_int.SetInt32(0);

    while (g_state.worker_active.load()) {
        gpu_found.clear();
        if (!gpu->Launch(gpu_found)) {
            std::cerr << "[-] Fatal GPU #" << gpu_id << ": CUDA kernel execution failed\n";
            delete gpu;
            std::exit(1);
        }

        uint64_t batch_steps = (uint64_t)total_kangaroos * NB_RUN;
        g_state.total_steps += batch_steps;

        respawn_indices.clear();

        if (!gpu_found.empty()) {
            std::vector<DPRecord> local_recs;
            local_recs.reserve(gpu_found.size());

            for (size_t idx = 0; idx < gpu_found.size(); ++idx) {
                const ITEM &item = gpu_found[idx];
                if (item.kIdx >= (uint64_t)total_kangaroos) {
                    continue;
                }

                Int real_dist(&base_dist[item.kIdx]);
                Int d_walk((Int*)&item.d);
                real_dist.ModAddK1order(&d_walk);

                DPRecord rec;
                rec.x_hex = "0x" + ((Int*)&item.x)->GetBase16();
                rec.dist_hex = "0x" + real_dist.GetBase16();
                local_recs.push_back(std::move(rec));

                gpu_dp_count[item.kIdx]++;
                if (gpu_dp_count[item.kIdx] >= 5 && respawn_indices.size() < 64) {
                    gpu_dp_count[item.kIdx] = 0;
                    respawn_indices.push_back(item.kIdx);
                }
            }

            EnqueueWithBackpressure(local_recs);
        }

        if (!staged_respawns.empty()) {
            for (size_t idx = 0; idx < staged_respawns.size(); ++idx) {
                uint64_t kIdx = staged_respawns[idx].kIdx;
                base_dist[kIdx].Set(&staged_respawns[idx].new_base);
                gpu_dp_count[kIdx] = 0;
            }
            staged_respawns.clear();
        }

        if (!respawn_indices.empty()) {
            for (size_t idx = 0; idx < respawn_indices.size(); ++idx) {
                uint64_t kIdx = respawn_indices[idx];
                Point new_P;
                Int new_base;
                make_kangaroo_state(new_P, new_base);
                gpu->SetKangaroo(kIdx, &new_P.x, &new_P.y, &zero_int);
                GpuStagedRespawn sr;
                sr.kIdx = kIdx;
                sr.new_base.Set(&new_base);
                staged_respawns.push_back(sr);
            }
        }
    }

    delete gpu;
}
#endif

static std::string ExtractJsonField(const std::string &json, const std::string &field) {
    std::string key = "\"" + field + "\"";
    size_t pos = json.find(key);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + key.size());
    if (pos == std::string::npos) return "";
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n')) {
        pos++;
    }
    if (pos >= json.size()) return "";
    if (json[pos] == '\"') {
        pos++;
        size_t end = json.find('\"', pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    }
    size_t end = pos;
    while (end < json.size() && json[end] != ',' && json[end] != '}' && json[end] != ']' &&
           json[end] != ' ' && json[end] != '\t' && json[end] != '\r' && json[end] != '\n') {
        end++;
    }
    return json.substr(pos, end - pos);
}

static bool SendBatchReliable(
    const std::string &session_url,
    bool is_wild_mode,
    const std::string &hw_info,
    const std::string &hr_str,
    const std::vector<DPRecord> &batch,
    std::string &out_resp_body,
    bool allow_retry_until_stopped
) {
    std::vector<uint8_t> packet = BuildDpkgPacket(g_state.worker_id, hw_info, hr_str, batch);
    std::string action = is_wild_mode ? "check_wild" : "submit_tame";
    std::string submit_url = BuildApiUrl(session_url, "action=" + action);

    while (true) {
        HttpResult res = HttpPostBinary(submit_url, packet.data(), packet.size());
        if (res.curl_code == CURLE_OK && res.http_code == 200) {
            std::string st = ExtractJsonField(res.body, "status");
            if (st == "OK" || st == "CONTINUE" || st == "BINGO") {
                out_resp_body = std::move(res.body);
                return true;
            }
        }

        if (res.curl_code == CURLE_OK && res.http_code == 400) {
            std::cerr << "[-] Fatal: Server rejected malformed DPKG payload (HTTP 400): " << res.body << "\n";
            std::exit(1);
        }

        if (!allow_retry_until_stopped || g_state.stop_signal.load()) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

// Unified Kangaroo Execution Pipeline (Used identically by Production & Historical --verify)
static int RunKangarooSession(
    Secp256K1 *secp,
    const std::string &session_url,
    const std::vector<int> &active_gpus,
    const std::string &hw_info,
    bool is_verify,
    SessionStats *out_stats
) {
    {
        std::lock_guard<std::mutex> lock(g_state.queue_mutex);
        g_state.dp_queue.clear();
    }
    g_state.running = !g_state.stop_signal.load();
    if (!g_state.running.load()) {
        return 1;
    }

    std::string task_url = BuildApiUrl(session_url, "action=get_task&worker_id=" + g_state.worker_id);
    std::string task_resp;
    while (g_state.running.load()) {
        HttpResult tr = HttpGet(task_url);
        if (tr.curl_code == CURLE_OK && tr.http_code == 200 && !tr.body.empty()) {
            std::string st = ExtractJsonField(tr.body, "status");
            if (st == "BINGO") {
                if (out_stats) out_stats->solved = true;
                return 0;
            }
            if (st == "OK") {
                task_resp = std::move(tr.body);
                break;
            }
        }
        if (is_verify) {
            std::cerr << "[-] Verification get_task failed on " << task_url << "\n";
            return 1;
        }
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }

    if (!g_state.running.load()) {
        return 0;
    }

    std::string active_min_hex;
    std::string active_max_hex;
    std::string active_pub_hex;
    if (!NormalizeHex(ExtractJsonField(task_resp, "range_min"), active_min_hex) ||
        !NormalizeHex(ExtractJsonField(task_resp, "range_max"), active_max_hex) ||
        !NormalizeHex(ExtractJsonField(task_resp, "target_pubkey"), active_pub_hex) ||
        (active_pub_hex.size() != 66 && active_pub_hex.size() != 130)) {
        std::cerr << "[-] Fatal: Invalid range or target_pubkey returned by get_task\n";
        return 1;
    }

    long parsed_bits = 0;
    long parsed_batch = 0;
    long parsed_hb = 0;
    if (!ParseStrictInt(ExtractJsonField(task_resp, "dp_mask_bits"), parsed_bits) || parsed_bits < 4 || parsed_bits > 60) {
        std::cerr << "[-] Fatal: Invalid dp_mask_bits returned by get_task\n";
        return 1;
    }
    if (!ParseStrictInt(ExtractJsonField(task_resp, "batch_limit"), parsed_batch) || parsed_batch < 1 || parsed_batch > 10000) {
        std::cerr << "[-] Fatal: Invalid batch_limit returned by get_task\n";
        return 1;
    }
    if (!ParseStrictInt(ExtractJsonField(task_resp, "heartbeat_sec"), parsed_hb) || parsed_hb < 1 || parsed_hb > 300) {
        std::cerr << "[-] Fatal: Invalid heartbeat_sec returned by get_task\n";
        return 1;
    }

    std::string srv_task = ExtractJsonField(task_resp, "task_type");
    if (srv_task != "TAME" && srv_task != "WILD") {
        std::cerr << "[-] Fatal: Invalid task_type returned by get_task\n";
        return 1;
    }

    int active_dp_bits = (int)parsed_bits;
    size_t batch_limit = (size_t)parsed_batch;
    double heartbeat_sec = (double)parsed_hb;

    Int range_min, range_max;
    range_min.SetBase16((char*)active_min_hex.c_str());
    range_max.SetBase16((char*)active_max_hex.c_str());
    if (range_min.IsGreater(&range_max)) {
        std::cerr << "[-] Fatal: range_min cannot exceed range_max\n";
        return 1;
    }

    Point target_pub;
    bool is_compressed = false;
    if (!secp->ParsePublicKeyHex(active_pub_hex, target_pub, is_compressed) || target_pub.isZero()) {
        std::cerr << "[-] Fatal: Failed to parse curve point target_pubkey\n";
        return 1;
    }

    Int range_width(&range_max);
    range_width.Sub(&range_min);

    JumpTable jt;
    jt.init(secp, range_width);

    bool is_wild_mode = (srv_task == "WILD");
    std::vector<std::thread> workers;

    auto launch_all_workers = [&](bool wild_mode) {
        g_state.worker_active = true;
#ifdef USE_CUDA
        if (g_state.use_gpu) {
            for (size_t g = 0; g < active_gpus.size(); ++g) {
                workers.emplace_back(WorkerGpuThread, active_gpus[g], secp, &jt, active_dp_bits, wild_mode, range_min, range_max, target_pub);
            }
        }
#endif
        if (!g_state.use_gpu || g_state.num_threads > 0) {
            int session_threads = is_verify ? std::min(g_state.num_threads, 2) : g_state.num_threads;
            for (int i = 0; i < session_threads; ++i) {
                if (wild_mode) {
                    workers.emplace_back(WorkerWildThread, i, secp, &jt, active_dp_bits, batch_limit, target_pub, range_min, range_max);
                } else {
                    workers.emplace_back(WorkerTameThread, i, secp, &jt, active_dp_bits, batch_limit, range_min, range_max);
                }
            }
        }
    };

    launch_all_workers(is_wild_mode);

    auto last_send_time = std::chrono::steady_clock::now();
    auto last_rate_time = last_send_time;
    uint64_t last_steps = g_state.total_steps.load();
    double cached_hashrate_mhs = 0.0;
    int verify_batches_sent = 0;
    const int poll_ms = is_verify ? 5 : 250;

    auto format_hashrate = [&](double mhs) -> std::string {
        std::ostringstream hr_ss;
        hr_ss << std::fixed << std::setprecision(2) << mhs << " MH/s";
        return hr_ss.str();
    };

    int exit_rc = 0;

    while (g_state.running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(poll_ms));
        auto now = std::chrono::steady_clock::now();
        double since_send = std::chrono::duration<double>(now - last_send_time).count();

        size_t queued_count = 0;
        {
            std::lock_guard<std::mutex> lock(g_state.queue_mutex);
            queued_count = g_state.dp_queue.size();
        }

        if (queued_count < batch_limit && since_send < heartbeat_sec) {
            continue;
        }

        last_send_time = now;

        double rate_elapsed = std::chrono::duration<double>(now - last_rate_time).count();
        if (rate_elapsed >= (is_verify ? 0.05 : 3.0)) {
            uint64_t cur_steps = g_state.total_steps.load();
            cached_hashrate_mhs = ((cur_steps - last_steps) / rate_elapsed) / 1000000.0;
            last_steps = cur_steps;
            last_rate_time = now;
        }

        std::vector<DPRecord> batch;
        {
            std::lock_guard<std::mutex> lock(g_state.queue_mutex);
            if (!g_state.dp_queue.empty()) {
                size_t take = std::min(batch_limit, g_state.dp_queue.size());
                batch.assign(
                    std::make_move_iterator(g_state.dp_queue.begin()),
                    std::make_move_iterator(g_state.dp_queue.begin() + take)
                );
                g_state.dp_queue.erase(g_state.dp_queue.begin(), g_state.dp_queue.begin() + take);
            }
        }

        std::string hr_str = format_hashrate(cached_hashrate_mhs);
        std::string post_resp;
        if (!SendBatchReliable(session_url, is_wild_mode, hw_info, hr_str, batch, post_resp, !is_verify)) {
            if (!batch.empty()) {
                std::lock_guard<std::mutex> lock(g_state.queue_mutex);
                g_state.dp_queue.insert(g_state.dp_queue.begin(), batch.begin(), batch.end());
            }
            if (is_verify) exit_rc = 1;
            break;
        }

        if (is_wild_mode && out_stats) {
            out_stats->wild_checked += batch.size();
        }

        std::string resp_status = ExtractJsonField(post_resp, "status");
        if (resp_status == "OK" && out_stats) {
            long traps_v = 0;
            if (ParseStrictInt(ExtractJsonField(post_resp, "total_traps"), traps_v) && traps_v >= 0) {
                out_stats->tame_traps = (uint64_t)traps_v;
            }
        }

        auto record_bingo_stats = [&](const std::string &resp_json) {
            if (!out_stats) return;
            out_stats->solved = true;
            long traps_v = 0;
            if (ParseStrictInt(ExtractJsonField(resp_json, "total_traps"), traps_v) && traps_v > 0) {
                out_stats->tame_traps = (uint64_t)traps_v;
            }
            out_stats->key_matched = (ExtractJsonField(resp_json, "key_matched") == "true");
        };

        if (resp_status == "BINGO") {
            record_bingo_stats(post_resp);
            if (!is_verify) {
                std::cout << "[+] BINGO! Puzzle solved and saved to bingo_key.php on Master Server. Stopping worker.\n";
            }
            g_state.worker_active = false;
            g_state.running = false;
            break;
        }

        if (is_verify) {
            verify_batches_sent++;
            if (verify_batches_sent > 60) {
                std::cerr << "[-] Verification exceeded batch limit without collision\n";
                exit_rc = 1;
                break;
            }
        }

        std::string next_task = ExtractJsonField(post_resp, "task_type");
        if (next_task != "TAME" && next_task != "WILD") {
            std::cerr << "[-] Fatal: Server returned invalid task_type: " << next_task << "\n";
            exit_rc = 1;
            break;
        }

        bool want_wild = (next_task == "WILD");
        if (want_wild != is_wild_mode) {
            g_state.worker_active = false;
            for (size_t i = 0; i < workers.size(); ++i) {
                if (workers[i].joinable()) workers[i].join();
            }
            workers.clear();

            if (is_wild_mode) {
                // Switching WILD -> TAME: drain all pending WILD DPs so no collision is missed
                bool bingo_during_flush = false;
                while (!g_state.stop_signal.load()) {
                    std::vector<DPRecord> rem_batch;
                    {
                        std::lock_guard<std::mutex> lock(g_state.queue_mutex);
                        if (g_state.dp_queue.empty()) break;
                        size_t take = std::min(batch_limit, g_state.dp_queue.size());
                        rem_batch.assign(
                            std::make_move_iterator(g_state.dp_queue.begin()),
                            std::make_move_iterator(g_state.dp_queue.begin() + take)
                        );
                        g_state.dp_queue.erase(g_state.dp_queue.begin(), g_state.dp_queue.begin() + take);
                    }
                    std::string flush_resp;
                    if (!SendBatchReliable(session_url, true, hw_info, hr_str, rem_batch, flush_resp, !is_verify)) {
                        break;
                    }
                    if (out_stats) {
                        out_stats->wild_checked += rem_batch.size();
                    }
                    if (ExtractJsonField(flush_resp, "status") == "BINGO") {
                        bingo_during_flush = true;
                        record_bingo_stats(flush_resp);
                        break;
                    }
                }
                if (bingo_during_flush || g_state.stop_signal.load()) {
                    g_state.running = false;
                    break;
                }
            } else {
                // Switching TAME -> WILD: server already committed target_dp Tame traps
                std::lock_guard<std::mutex> lock(g_state.queue_mutex);
                g_state.dp_queue.clear();
                if (out_stats) out_stats->switched_to_wild = true;
            }

            is_wild_mode = want_wild;
            launch_all_workers(is_wild_mode);
        }
    }

    g_state.worker_active = false;
    for (size_t i = 0; i < workers.size(); ++i) {
        if (workers[i].joinable()) workers[i].join();
    }

    if (!is_verify && g_state.stop_signal.load()) {
        std::string hr_str = "0.00 MH/s";
        while (true) {
            std::vector<DPRecord> final_batch;
            {
                std::lock_guard<std::mutex> lock(g_state.queue_mutex);
                if (g_state.dp_queue.empty()) break;
                size_t take = std::min(batch_limit, g_state.dp_queue.size());
                final_batch.assign(
                    std::make_move_iterator(g_state.dp_queue.begin()),
                    std::make_move_iterator(g_state.dp_queue.begin() + take)
                );
                g_state.dp_queue.erase(g_state.dp_queue.begin(), g_state.dp_queue.begin() + take);
            }
            std::string final_resp;
            if (!SendBatchReliable(session_url, is_wild_mode, hw_info, hr_str, final_batch, final_resp, false)) {
                break;
            }
            if (ExtractJsonField(final_resp, "status") == "BINGO") {
                break;
            }
        }
    }

    return exit_rc;
}

static int RunVerification(Secp256K1 *secp, const std::vector<int> &active_gpus, const std::string &hw_info) {
    std::cout << "========================================================================\n";
    std::cout << "[*] End-to-End TAME + WILD + Secp256k1 Historical Puzzle Verification\n";
    std::cout << "[*] Compute Backend: " << hw_info << "\n";
    std::cout << "========================================================================\n";

    Int privOne, privTwo;
    privOne.SetInt32(1);
    privTwo.SetInt32(2);
    Point p1 = secp->ComputePublicKey(&privOne);
    Point p2 = secp->ComputePublicKey(&privTwo);
    Point p1_doubled = secp->DoubleDirect(p1);
    if (!p2.equals(p1_doubled)) {
        std::cerr << "[-] Point doubling 2*G = 2G verification failed\n";
        return 1;
    }
    std::cout << "[+] Secp256k1 Generator Doubling (2*G == G+G): [PASS]\n";

    std::string verify_session_url = BuildApiUrl(g_state.server_url, "verify_mode=1");
    std::string catalog_url = BuildApiUrl(verify_session_url, "action=verify");
    HttpResult catalog_res = HttpGet(catalog_url);
    if (catalog_res.curl_code != CURLE_OK || catalog_res.http_code != 200 || catalog_res.body.empty()) {
        std::cerr << "[-] Failed to initialize verify.db & retrieve historical puzzle catalog\n";
        return 1;
    }
    std::cout << "[+] Ephemeral DB ready: data/verify.db (stale files purged before run)\n";

    struct CatalogEntry {
        int id = 0;
        int bits = 0;
    };
    std::vector<CatalogEntry> catalog;

    size_t p_pos = catalog_res.body.find("\"puzzles\"");
    if (p_pos != std::string::npos) {
        size_t cur = catalog_res.body.find('{', p_pos + 9);
        while (cur != std::string::npos) {
            size_t end_obj = catalog_res.body.find('}', cur);
            if (end_obj == std::string::npos) break;
            std::string item = catalog_res.body.substr(cur, end_obj - cur + 1);
            long id_v = 0, bits_v = 0;
            if (ParseStrictInt(ExtractJsonField(item, "id"), id_v) &&
                ParseStrictInt(ExtractJsonField(item, "bits"), bits_v) &&
                id_v > 0) {
                catalog.push_back({(int)id_v, (int)bits_v});
            }
            cur = catalog_res.body.find('{', end_obj);
        }
    }

    if (catalog.empty()) {
        HttpGet(BuildApiUrl(verify_session_url, "action=verify&cleanup=1"));
        std::cerr << "[-] Historical puzzle catalog is empty or malformed\n";
        return 1;
    }

    int solved_count = 0;
    int final_rc = 0;

    for (size_t idx = 0; idx < catalog.size(); ++idx) {
        if (g_state.stop_signal.load()) {
            final_rc = 1;
            break;
        }
        const CatalogEntry &entry = catalog[idx];
        std::string init_url = BuildApiUrl(verify_session_url, "action=verify&init_id=" + std::to_string(entry.id));
        HttpResult init_res = HttpGet(init_url);
        if (init_res.curl_code != CURLE_OK || init_res.http_code != 200 || ExtractJsonField(init_res.body, "status") != "OK") {
            std::cerr << "  [-] Puzzle #" << entry.id << ": [FAIL - verify.db reset failed]\n";
            final_rc = 1;
            break;
        }

        SessionStats stats;
        int rc = RunKangarooSession(secp, verify_session_url, active_gpus, hw_info, true, &stats);
        if (rc != 0 || !stats.solved || !stats.key_matched || !stats.switched_to_wild ||
            stats.tame_traps == 0 || stats.wild_checked == 0) {
            std::cerr << "  [-] Puzzle #" << entry.id << " (" << entry.bits << "-bit): [FAIL - Private key array or Secp256k1 mismatch]\n";
            final_rc = 1;
            break;
        }

        solved_count++;
        std::cout << "  [+] Puzzle #" << std::setw(3) << entry.id
                  << " (" << std::setw(3) << entry.bits << "-bit)"
                  << " | TAME: " << std::setw(3) << stats.tame_traps
                  << " -> WILD: " << std::setw(3) << stats.wild_checked
                  << " | Expected Key Match [PASS]\n";
    }

    HttpResult clean_res = HttpGet(BuildApiUrl(verify_session_url, "action=verify&cleanup=1"));
    if (clean_res.curl_code == CURLE_OK && clean_res.http_code == 200 && ExtractJsonField(clean_res.body, "status") == "OK") {
        std::cout << "[+] Ephemeral DB deleted: data/verify.db removed cleanly.\n";
    } else {
        std::cerr << "[-] Warning: Failed to confirm remote deletion of data/verify.db\n";
        final_rc = 1;
    }

    std::cout << "========================================================================\n";
    std::cout << "[+] Verified: " << solved_count << "/" << catalog.size()
              << " historical puzzles solved via real TAME + WILD + Secp256k1.\n";
    return (final_rc == 0 && solved_count == (int)catalog.size()) ? 0 : 1;
}

int main(int argc, char **argv) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    std::signal(SIGINT, HandleStopSignal);
    std::signal(SIGTERM, HandleStopSignal);

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-t") == 0 || std::strcmp(argv[i], "-c") == 0 || std::strcmp(argv[i], "-j") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "[-] Fatal: Missing value after " << argv[i] << "\n";
                return 1;
            }
            if (std::strcmp(argv[i + 1], "max") == 0 || std::strcmp(argv[i + 1], "MAX") == 0) {
                g_state.num_threads = (int)std::thread::hardware_concurrency();
                ++i;
            } else {
                long parsed_t = 0;
                if (!ParseStrictInt(argv[++i], parsed_t) || parsed_t <= 0) {
                    std::cerr << "[-] Fatal: Invalid thread count\n";
                    return 1;
                }
                g_state.num_threads = (int)parsed_t;
            }
        } else if (std::strcmp(argv[i], "-m") == 0 || std::strcmp(argv[i], "-max") == 0 ||
                   std::strcmp(argv[i], "--max") == 0 || std::strcmp(argv[i], "-f") == 0 ||
                   std::strcmp(argv[i], "--full") == 0) {
            g_state.num_threads = (int)std::thread::hardware_concurrency();
        } else if (std::strcmp(argv[i], "-u") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "[-] Fatal: Missing worker_id after -u\n";
                return 1;
            }
            g_state.worker_id = argv[++i];
        } else if (std::strcmp(argv[i], "-s") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "[-] Fatal: Missing server_url after -s\n";
                return 1;
            }
            g_state.server_url = argv[++i];
        } else if (std::strcmp(argv[i], "--verify") == 0) {
            g_state.verify_mode = true;
        } else if (std::strcmp(argv[i], "-gpu") == 0) {
            g_state.use_gpu = true;
            if (i + 1 < argc && argv[i + 1][0] >= '0' && argv[i + 1][0] <= '9') {
                std::string list_str = argv[++i];
                size_t start = 0;
                while (start < list_str.size()) {
                    size_t comma = list_str.find(',', start);
                    std::string tok = (comma == std::string::npos) ? list_str.substr(start) : list_str.substr(start, comma - start);
                    long gid = -1;
                    if (!ParseStrictInt(tok, gid) || gid < 0) {
                        std::cerr << "[-] Fatal: Invalid GPU device ID: " << tok << "\n";
                        return 1;
                    }
                    g_state.gpu_device_ids.push_back((int)gid);
                    if (comma == std::string::npos) break;
                    start = comma + 1;
                }
            }
        } else {
            std::cerr << "[-] Fatal: Unknown CLI argument: " << argv[i] << "\n";
            return 1;
        }
    }

    if (g_state.worker_id.empty() || g_state.worker_id.size() > 128) {
        std::cerr << "[-] Fatal: worker_id must be 1..128 bytes\n";
        curl_global_cleanup();
        return 1;
    }
    if (g_state.server_url.empty()) {
        std::cerr << "[-] Fatal: server_url cannot be empty\n";
        curl_global_cleanup();
        return 1;
    }

#ifndef USE_CUDA
    if (g_state.use_gpu) {
        std::cerr << "[-] Fatal: -gpu requested on CPU-only binary (built without USE_CUDA)\n";
        curl_global_cleanup();
        return 1;
    }
#endif

    std::vector<int> active_gpus;
#ifdef USE_CUDA
    if (g_state.use_gpu) {
        int dev_count = 0;
        cudaError_t cnt_err = cudaGetDeviceCount(&dev_count);
        if (cnt_err != cudaSuccess || dev_count <= 0) {
            std::cerr << "[-] Fatal: No CUDA-capable GPU detected\n";
            curl_global_cleanup();
            return 1;
        }
        if (!g_state.gpu_device_ids.empty()) {
            for (size_t i = 0; i < g_state.gpu_device_ids.size(); ++i) {
                int gid = g_state.gpu_device_ids[i];
                if (gid < 0 || gid >= dev_count) {
                    std::cerr << "[-] Fatal: Requested GPU #" << gid << " out of range (0.." << (dev_count - 1) << ")\n";
                    curl_global_cleanup();
                    return 1;
                }
                active_gpus.push_back(gid);
            }
        } else {
            for (int d = 0; d < dev_count; ++d) {
                active_gpus.push_back(d);
            }
        }
    }
#endif

    if (!g_state.use_gpu || g_state.num_threads > 0) {
        if (g_state.num_threads <= 0) {
            g_state.num_threads = (int)std::thread::hardware_concurrency();
            if (g_state.num_threads <= 0) {
                std::cerr << "[-] Fatal: Unable to query CPU hardware_concurrency; specify -t <threads> explicitly\n";
                curl_global_cleanup();
                return 1;
            }
        }
    }

    std::string hw_info;
    if (g_state.use_gpu) {
        hw_info = "NVIDIA CUDA (" + std::to_string(active_gpus.size()) + "x GPU)";
        if (g_state.num_threads > 0) {
            hw_info += " + " + std::to_string(g_state.num_threads) + " CPU Cores";
        }
    } else {
        hw_info = "CPU " + std::to_string(g_state.num_threads) + " Cores (L1-Optimized)";
    }

    SetProcessName("k-engine");

    Secp256K1 secp;
    secp.Init();

    int rc = 0;
    if (g_state.verify_mode) {
        rc = RunVerification(&secp, active_gpus, hw_info);
    } else {
        rc = RunKangarooSession(&secp, g_state.server_url, active_gpus, hw_info, false, nullptr);
    }

    CleanupMainCurlHandle();
    curl_global_cleanup();
    return rc;
}
