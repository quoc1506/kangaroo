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
#include <mutex>
#include <chrono>
#include <random>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <algorithm>
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
    int num_threads = 0; // Mặc định tự phát hiện 100% CPU thread
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
    std::string hardware_label_;
    uint64_t jumps_[32];

public:
    KangarooEngine(const DaemonConfig& cfg) : config_(cfg) {
        for (int i = 0; i < 32; ++i) {
            jumps_[i] = 1ULL << ((i + 50) % 64);
        }

        if (config_.num_threads <= 0) {
            int detected = (int)std::thread::hardware_concurrency();
            config_.num_threads = (detected > 0) ? detected : 4;
        }

#if defined(__APPLE__)
        hardware_label_ = "Apple " + std::to_string(config_.num_threads) + "C";
#elif defined(USE_CUDA)
        hardware_label_ = "NVIDIA CUDA";
#else
        hardware_label_ = "CPU " + std::to_string(config_.num_threads) + "T";
#endif
    }

    void stop() {
        running_ = false;
    }

    void run() {
        curl_global_init(CURL_GLOBAL_DEFAULT);

        if (config_.worker_id.empty()) {
            char hostname[128] = "node";
            gethostname(hostname, sizeof(hostname));
            std::random_device rd;
            config_.worker_id = std::string(hostname) + "_" + std::to_string(rd() % 100000);
        }

        while (running_) {
            std::ostringstream ss_url;
            ss_url << config_.server_url
                   << "?action=get_task"
                   << "&worker_id=" << config_.worker_id
                   << "&hardware=" << hardware_label_
                   << "&threads=" << config_.num_threads;

            std::string response;
            if (!HttpClient::Get(ss_url.str(), response) || response.empty()) {
                log_error("Không thể kết nối đến Master Server. Thử lại sau 5s...");
                std::this_thread::sleep_for(std::chrono::seconds(5));
                continue;
            }

            std::string task_type = extract_json_string(response, "task_type");
            std::string range_min = extract_json_string(response, "range_min");
            std::string range_max = extract_json_string(response, "range_max");
            std::string target_pk = extract_json_string(response, "target_pubkey");
            int dp_bits = (int)extract_json_number(response, "dp_bits", 20);

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
        int n_threads = std::max(1, config_.num_threads);
        uint64_t dp_mask = (1ULL << dp_bits) - 1;
        std::vector<Secp256k1Math::DPPoint> local_traps;
        std::mutex traps_mutex;
        std::atomic<uint64_t> session_steps{0};
        std::atomic<bool> session_active{true};

        std::vector<std::thread> workers;
        workers.reserve(n_threads);

        for (int t = 0; t < n_threads; ++t) {
            workers.emplace_back([this, t, dp_mask, &local_traps, &traps_mutex, &session_steps, &session_active]() {
                std::random_device rd;
                std::mt19937_64 gen(rd() + t * 10007);
                uint64_t current_dist = gen();
                uint64_t current_x = gen();
                uint64_t local_steps = 0;

                while (running_ && session_active) {
                    int jump_idx = current_x & 31;
                    current_x = current_x * 6364136223846793005ULL + jumps_[jump_idx];
                    current_dist += jumps_[jump_idx];
                    local_steps++;

                    if ((current_x & dp_mask) == 0) {
                        std::ostringstream ss_x, ss_dist;
                        ss_x << "0x" << std::hex << std::setfill('0') << std::setw(16) << current_x;
                        ss_dist << "0x" << std::hex << std::setfill('0') << std::setw(16) << current_dist;
                        {
                            std::lock_guard<std::mutex> lock(traps_mutex);
                            local_traps.push_back({ss_x.str(), ss_dist.str()});
                        }
                    }

                    if (local_steps >= 20000) {
                        session_steps += local_steps;
                        local_steps = 0;
                    }
                }
                session_steps += local_steps;
            });
        }

        auto last_report_time = std::chrono::steady_clock::now();
        uint64_t last_report_steps = 0;
        auto session_start = std::chrono::steady_clock::now();

        while (running_ && session_active) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            auto now = std::chrono::steady_clock::now();
            double since_report = std::chrono::duration<double>(now - last_report_time).count();

            if (since_report >= 10.0) {
                std::vector<Secp256k1Math::DPPoint> batch;
                {
                    std::lock_guard<std::mutex> lock(traps_mutex);
                    batch.swap(local_traps);
                }

                uint64_t current_steps = session_steps.load();
                uint64_t delta_steps = (current_steps >= last_report_steps) ? (current_steps - last_report_steps) : current_steps;
                double mh_s = (since_report > 0) ? ((delta_steps / since_report) / 1000000.0) : 0.0;

                last_report_time = now;
                last_report_steps = current_steps;

                std::string server_res = submit_tame_batch(batch, mh_s);

                long long current_dp = extract_json_number(server_res, "current_dp", 0);
                long long target_dp = extract_json_number(server_res, "target_dp", 0);
                if (target_dp > 0 && current_dp >= target_dp) {
                    session_active = false;
                    break;
                }
            }

            double total_session_sec = std::chrono::duration<double>(now - session_start).count();
            if (total_session_sec >= 60.0) {
                session_active = false;
                break;
            }
        }

        session_active = false;
        for (auto& th : workers) {
            if (th.joinable()) th.join();
        }

        std::vector<Secp256k1Math::DPPoint> remaining_traps;
        {
            std::lock_guard<std::mutex> lock(traps_mutex);
            remaining_traps.swap(local_traps);
        }
        if (!remaining_traps.empty()) {
            submit_tame_batch(remaining_traps, 0.0);
        }
    }

    void execute_wild_session(const std::string& target_pk, const std::string& range_min, const std::string& range_max, int dp_bits) {
        int n_threads = std::max(1, config_.num_threads);
        uint64_t dp_mask = (1ULL << dp_bits) - 1;
        std::vector<Secp256k1Math::DPPoint> wild_dps;
        std::mutex dps_mutex;
        std::atomic<uint64_t> session_steps{0};
        std::atomic<bool> session_active{true};

        std::vector<std::thread> workers;
        workers.reserve(n_threads);

        for (int t = 0; t < n_threads; ++t) {
            workers.emplace_back([this, t, dp_mask, &wild_dps, &dps_mutex, &session_steps, &session_active]() {
                std::random_device rd;
                std::mt19937_64 gen(rd() + t * 10007);
                uint64_t current_dist = gen();
                uint64_t current_x = gen();
                uint64_t local_steps = 0;

                while (running_ && session_active) {
                    int jump_idx = current_x & 31;
                    current_x = current_x * 6364136223846793005ULL + jumps_[jump_idx];
                    current_dist += jumps_[jump_idx];
                    local_steps++;

                    if ((current_x & dp_mask) == 0) {
                        std::ostringstream ss_x, ss_dist;
                        ss_x << "0x" << std::hex << std::setfill('0') << std::setw(16) << current_x;
                        ss_dist << "0x" << std::hex << std::setfill('0') << std::setw(16) << current_dist;
                        {
                            std::lock_guard<std::mutex> lock(dps_mutex);
                            wild_dps.push_back({ss_x.str(), ss_dist.str()});
                        }
                    }

                    if (local_steps >= 20000) {
                        session_steps += local_steps;
                        local_steps = 0;
                    }
                }
                session_steps += local_steps;
            });
        }

        auto last_report_time = std::chrono::steady_clock::now();
        uint64_t last_report_steps = 0;
        auto session_start = std::chrono::steady_clock::now();

        while (running_ && session_active) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            auto now = std::chrono::steady_clock::now();
            double since_report = std::chrono::duration<double>(now - last_report_time).count();

            if (since_report >= 10.0) {
                std::vector<Secp256k1Math::DPPoint> batch;
                {
                    std::lock_guard<std::mutex> lock(dps_mutex);
                    batch.swap(wild_dps);
                }

                uint64_t current_steps = session_steps.load();
                uint64_t delta_steps = (current_steps >= last_report_steps) ? (current_steps - last_report_steps) : current_steps;
                double mh_s = (since_report > 0) ? ((delta_steps / since_report) / 1000000.0) : 0.0;

                last_report_time = now;
                last_report_steps = current_steps;

                bool found_collision = check_wild_collision(batch, mh_s);
                if (found_collision) {
                    session_active = false;
                    running_ = false;
                    break;
                }
            }

            double total_session_sec = std::chrono::duration<double>(now - session_start).count();
            if (total_session_sec >= 60.0) {
                session_active = false;
                break;
            }
        }

        session_active = false;
        for (auto& th : workers) {
            if (th.joinable()) th.join();
        }

        std::vector<Secp256k1Math::DPPoint> remaining_wilds;
        {
            std::lock_guard<std::mutex> lock(dps_mutex);
            remaining_wilds.swap(wild_dps);
        }
        if (!remaining_wilds.empty() && running_) {
            if (check_wild_collision(remaining_wilds, 0.0)) {
                running_ = false;
            }
        }
    }

    std::string submit_tame_batch(const std::vector<Secp256k1Math::DPPoint>& dps, double mh_s) {
        std::ostringstream json;
        json << "{\"worker_id\":\"" << config_.worker_id << "\",";
        json << "\"hashrate\":\"" << std::fixed << std::setprecision(1) << mh_s << " MH/s\",";
        json << "\"hardware\":\"" << hardware_label_ << "\",";
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
        return response;
    }

    bool check_wild_collision(const std::vector<Secp256k1Math::DPPoint>& dps, double mh_s) {
        std::ostringstream json;
        json << "{\"worker_id\":\"" << config_.worker_id << "\",";
        json << "\"hashrate\":\"" << std::fixed << std::setprecision(1) << mh_s << " MH/s\",";
        json << "\"hardware\":\"" << hardware_label_ << "\",";
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

    int default_concurrency = (int)std::thread::hardware_concurrency();
    cfg.num_threads = (default_concurrency > 0) ? default_concurrency : 4;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--server" && i + 1 < argc) {
            cfg.server_url = argv[++i];
        } else if ((arg == "--id" || arg == "-i" || arg == "--worker") && i + 1 < argc) {
            cfg.worker_id = argv[++i];
        } else if ((arg == "-c" || arg == "-j" || arg == "-t" || arg == "--cores" || arg == "--jobs") && i + 1 < argc) {
            std::string t_val = argv[++i];
            if (t_val == "max" || t_val == "all" || t_val == "auto") {
                cfg.num_threads = default_concurrency;
            } else {
                int val = std::atoi(t_val.c_str());
                if (val > 0) cfg.num_threads = val;
            }
        } else if (arg == "-m" || arg == "-a" || arg == "--max" || arg == "--auto") {
            cfg.num_threads = default_concurrency;
        } else if (arg.rfind("http://", 0) == 0 || arg.rfind("https://", 0) == 0) {
            cfg.server_url = arg;
        }
    }

    const char* env_threads = std::getenv("THREADS");
    if (env_threads) {
        if (std::strcmp(env_threads, "max") == 0 || std::strcmp(env_threads, "all") == 0) {
            cfg.num_threads = default_concurrency;
        } else if (std::atoi(env_threads) > 0) {
            cfg.num_threads = std::atoi(env_threads);
        }
    }

    const char* env_server = std::getenv("SERVER_URL");
    if (env_server && std::strlen(env_server) > 0) {
        cfg.server_url = env_server;
    }

    for (int i = 1; i < argc; ++i) {
        if (argv[i]) {
            std::memset(argv[i], 0, std::strlen(argv[i]));
        }
    }

    KangarooEngine engine(cfg);
    engine.run();
    return 0;
}