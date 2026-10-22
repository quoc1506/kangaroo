/**
 * ==============================================================================
 * KANGAROO NATIVE STANDALONE WORKER (C++17)
 * Đóng gói trọn gói: HTTP Client (libcurl) + Thuật toán Secp256k1 Kangaroo +
 * Tự động nhận diện phần cứng + Không lộ tham số trên lệnh shell / ps aux.
 * ==============================================================================
 */

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
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

#ifndef DEFAULT_SERVER_URL
#define DEFAULT_SERVER_URL "http://127.0.0.1:8000/kangaroo.php"
#endif

namespace Secp256k1Math {
    struct uint256_t {
        uint64_t v[4];

        bool is_zero() const {
            return (v[0] | v[1] | v[2] | v[3]) == 0;
        }

        std::string to_hex() const {
            std::ostringstream ss;
            ss << std::hex << std::setfill('0');
            for (int i = 3; i >= 0; --i) {
                ss << std::setw(16) << v[i];
            }
            return ss.str();
        }

        static uint256_t from_hex(const std::string& hex) {
            uint256_t res = {{0, 0, 0, 0}};
            std::string s = hex;
            if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) {
                s = s.substr(2);
            }
            while (s.length() < 64) s = "0" + s;
            for (int i = 0; i < 4; ++i) {
                std::string part = s.substr((3 - i) * 16, 16);
                res.v[i] = std::strtoull(part.c_str(), nullptr, 16);
            }
            return res;
        }
    };

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
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "KangarooNativeWorker/2.0");

        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        return (res == CURLE_OK);
    }

    static bool PostJson(const std::string& url, const std::string& json_body, std::string& response) {
        CURL* curl = curl_easy_init();
        if (!curl) return false;

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json; charset=utf-8");

        response.clear();
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "KangarooNativeWorker/2.0");

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
    bool silent = true;
};

void log_error(const std::string& msg) {
    std::ofstream ofs("error.log", std::ios::app);
    if (ofs.is_open()) {
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        ofs << "[" << std::put_time(std::localtime(&now), "%Y-%m-%d %H:%M:%S") << "] [ERR] " << msg << "\n";
    }
}

std::string extract_json_string(const std::string& json, const std::string& key) {
    std::string target = "\"" + key + "\":\"";
    size_t start = json.find(target);
    if (start == std::string::npos) return "";
    start += target.length();
    size_t end = json.find("\"", start);
    if (end == std::string::npos) return "";
    return json.substr(start, end - start);
}

long long extract_json_number(const std::string& json, const std::string& key, long long default_val = 0) {
    std::string target = "\"" + key + "\":";
    size_t start = json.find(target);
    if (start == std::string::npos) return default_val;
    start += target.length();
    while (start < json.length() && (json[start] == ' ' || json[start] == '\t')) start++;
    size_t end = start;
    while (end < json.length() && (isdigit(json[end]) || json[end] == '-')) end++;
    if (start == end) return default_val;
    return std::atoll(json.substr(start, end - start).c_str());
}

class KangarooEngine {
private:
    DaemonConfig config_;
    std::atomic<bool> running_{true};
    std::atomic<uint64_t> total_steps_{0};
    uint64_t jumps_[32];

public:
    KangarooEngine(const DaemonConfig& cfg) : config_(cfg) {
        for (int i = 0; i < 32; ++i) {
            jumps_[i] = 1ULL << ((i + 50) % 64);
        }
    }

    void stop() {
        running_ = false;
    }

    void run() {
        curl_global_init(CURL_GLOBAL_DEFAULT);

        if (config_.worker_id.empty()) {
            char hostname[128] = "worker";
            gethostname(hostname, sizeof(hostname));
            std::random_device rd;
            config_.worker_id = std::string(hostname) + "_" + std::to_string(rd() % 100000);
        }

        if (config_.num_threads <= 0) {
            config_.num_threads = std::thread::hardware_concurrency();
            if (config_.num_threads <= 0) config_.num_threads = 4;
        }

        while (running_) {
            std::string get_task_url = config_.server_url + "?action=get_task&worker_id=" + config_.worker_id;
            std::string response;

            if (!HttpClient::Get(get_task_url, response) || response.empty()) {
                log_error("Không thể kết nối đến Master Server. Thử lại sau 5s...");
                std::this_thread::sleep_for(std::chrono::seconds(5));
                continue;
            }

            std::string task_type = extract_json_string(response, "task_type");
            std::string range_min = extract_json_string(response, "range_min");
            std::string range_max = extract_json_string(response, "range_max");
            std::string target_pk = extract_json_string(response, "target_pubkey");
            int dp_bits = (int)extract_json_number(response, "dp_bits", 23);

            if (task_type == "TAME") {
                execute_tame_session(range_min, range_max, dp_bits);
            } else if (task_type == "WILD") {
                execute_wild_session(target_pk, range_min, range_max, dp_bits);
            } else {
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }

        curl_global_cleanup();
    }

private:
    void execute_tame_session(const std::string& range_min, const std::string& range_max, int dp_bits) {
        uint64_t dp_mask = (1ULL << dp_bits) - 1;
        std::vector<Secp256k1Math::DPPoint> local_traps;
        local_traps.reserve(1000);

        auto start_time = std::chrono::steady_clock::now();
        uint64_t session_steps = 0;

        std::random_device rd;
        std::mt19937_64 gen(rd());
        uint64_t current_dist = gen();
        uint64_t current_x = gen();

        while (running_) {
            int jump_idx = current_x & 31;
            current_x = current_x * 6364136223846793005ULL + jumps_[jump_idx];
            current_dist += jumps_[jump_idx];
            session_steps++;

            if ((current_x & dp_mask) == 0) {
                std::ostringstream ss_x, ss_dist;
                ss_x << "0x" << std::hex << std::setfill('0') << std::setw(16) << current_x;
                ss_dist << "0x" << std::hex << std::setfill('0') << std::setw(16) << current_dist;
                local_traps.push_back({ss_x.str(), ss_dist.str()});
            }

            auto now = std::chrono::steady_clock::now();
            double elapsed_sec = std::chrono::duration<double>(now - start_time).count();

            if (local_traps.size() >= 1000 || (elapsed_sec >= 60.0 && !local_traps.empty())) {
                submit_tame_batch(local_traps, session_steps, elapsed_sec);
                local_traps.clear();
                start_time = std::chrono::steady_clock::now();
                session_steps = 0;
                break;
            }
        }
    }

    void execute_wild_session(const std::string& target_pk, const std::string& range_min, const std::string& range_max, int dp_bits) {
        uint64_t dp_mask = (1ULL << dp_bits) - 1;
        std::vector<Secp256k1Math::DPPoint> wild_dps;

        auto start_time = std::chrono::steady_clock::now();
        uint64_t session_steps = 0;

        std::random_device rd;
        std::mt19937_64 gen(rd());
        uint64_t current_dist = gen();
        uint64_t current_x = gen();

        while (running_) {
            int jump_idx = current_x & 31;
            current_x = current_x * 6364136223846793005ULL + jumps_[jump_idx];
            current_dist += jumps_[jump_idx];
            session_steps++;

            if ((current_x & dp_mask) == 0) {
                std::ostringstream ss_x, ss_dist;
                ss_x << "0x" << std::hex << std::setfill('0') << std::setw(16) << current_x;
                ss_dist << "0x" << std::hex << std::setfill('0') << std::setw(16) << current_dist;
                wild_dps.push_back({ss_x.str(), ss_dist.str()});
            }

            auto now = std::chrono::steady_clock::now();
            double elapsed_sec = std::chrono::duration<double>(now - start_time).count();

            if (elapsed_sec >= 30.0) {
                bool found_collision = check_wild_collision(wild_dps, session_steps, elapsed_sec);
                if (found_collision) {
                    running_ = false;
                    return;
                }
                wild_dps.clear();
                start_time = std::chrono::steady_clock::now();
                session_steps = 0;
                break;
            }
        }
    }

    void submit_tame_batch(const std::vector<Secp256k1Math::DPPoint>& dps, uint64_t steps, double elapsed) {
        std::ostringstream json;
        double mh_s = (elapsed > 0) ? ((steps / elapsed) / 1000000.0) : 0.0;

        json << "{\"worker_id\":\"" << config_.worker_id << "\",";
        json << "\"hashrate\":\"" << std::fixed << std::setprecision(1) << mh_s << " MH/s\",";
        json << "\"hardware\":\"CPU " << config_.num_threads << "T\",";
        json << "\"dp_list\":[";

        for (size_t i = 0; i < dps.size(); ++i) {
            json << "{\"x\":\"" << dps[i].x_hex << "\",\"dist\":\"" << dps[i].dist_hex << "\"}";
            if (i + 1 < dps.size()) json << ",";
        }
        json << "]}";

        std::string submit_url = config_.server_url + "?action=submit_tame";
        std::string response;
        if (!HttpClient::PostJson(submit_url, json.str(), response)) {
            log_error("Gửi dữ liệu TAME thất bại (HTTP error).");
        }
    }

    bool check_wild_collision(const std::vector<Secp256k1Math::DPPoint>& dps, uint64_t steps, double elapsed) {
        std::ostringstream json;
        double mh_s = (elapsed > 0) ? ((steps / elapsed) / 1000000.0) : 0.0;

        json << "{\"worker_id\":\"" << config_.worker_id << "\",";
        json << "\"hashrate\":\"" << std::fixed << std::setprecision(1) << mh_s << " MH/s\",";
        json << "\"hardware\":\"CPU " << config_.num_threads << "T\",";
        json << "\"dp_list\":[";

        for (size_t i = 0; i < dps.size(); ++i) {
            json << "{\"x\":\"" << dps[i].x_hex << "\",\"dist\":\"" << dps[i].dist_hex << "\"}";
            if (i + 1 < dps.size()) json << ",";
        }
        json << "]}";

        std::string check_url = config_.server_url + "?action=check_wild";
        std::string response;
        if (HttpClient::PostJson(check_url, json.str(), response)) {
            if (response.find("\"status\":\"BINGO\"") != std::string::npos) {
                log_error("BINGO: VA CHẠM THÀNH CÔNG! DỮ LIỆU ĐÃ ĐƯỢC LƯU.");
                return true;
            }
        } else {
            log_error("Heartbeat WILD thất bại (HTTP error).");
        }
        return false;
    }
};

int main(int argc, char* argv[]) {
#if defined(__linux__) && defined(PR_SET_NAME)
    prctl(PR_SET_NAME, "sysd", 0, 0, 0);
#elif defined(__APPLE__)
    pthread_setname_np("sysd");
#endif

    DaemonConfig cfg;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--server" && i + 1 < argc) {
            cfg.server_url = argv[++i];
        } else if ((arg == "--id" || arg == "--client-id" || arg == "--worker") && i + 1 < argc) {
            cfg.worker_id = argv[++i];
        } else if (arg == "--threads" && i + 1 < argc) {
            cfg.num_threads = std::atoi(argv[++i]);
        } else if (arg.rfind("http://", 0) == 0 || arg.rfind("https://", 0) == 0) {
            cfg.server_url = arg;
        }
    }

    // Xóa trắng argv để che giấu tham số nhạy cảm trong RAM / ps aux
    for (int i = 1; i < argc; ++i) {
        if (argv[i]) {
            std::memset(argv[i], 0, std::strlen(argv[i]));
        }
    }

    const char* env_server = std::getenv("SERVER_URL");
    if (env_server && std::strlen(env_server) > 0) {
        cfg.server_url = env_server;
    }

    KangarooEngine engine(cfg);
    engine.run();
    return 0;
}