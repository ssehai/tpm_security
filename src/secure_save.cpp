#include "secure_save.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <termios.h>
#include <unistd.h>
#include <sys/wait.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <nlohmann/json.hpp>

#include <gst/gst.h>
#include <gst/app/gstappsink.h>
#include <gst/app/gstappsrc.h>

#include "roi_mask.h"
#include "dataframe.h"

namespace fs = std::filesystem;
using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;

namespace {

static std::mutex g_tpm_mutex;

static std::string now_ts_name() {
    auto t = std::time(nullptr);
    std::tm tm{};
    localtime_r(&t, &tm);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H-%M-%S");
    return oss.str();
}

static std::string safe_name(std::string s) {
    for (auto& c : s) if (c == '/') c = '_';
    return s;
}

static std::string format_duration(double seconds) {
    if (seconds < 0 || !std::isfinite(seconds)) return "--:--:--";
    auto s = static_cast<int64_t>(seconds + 0.5);
    int64_t h = s / 3600;
    int64_t m = (s % 3600) / 60;
    int64_t sec = s % 60;
    std::ostringstream oss;
    oss << std::setw(2) << std::setfill('0') << h << ":"
        << std::setw(2) << std::setfill('0') << m << ":"
        << std::setw(2) << std::setfill('0') << sec;
    return oss.str();
}

struct ProgressMeter {
    std::string label;
    uint64_t total = 0;
    std::chrono::steady_clock::time_point start;
    std::chrono::steady_clock::time_point last_report;
    uint64_t last_value = 0;
    bool enabled = false;

    void start_meter(const std::string& name, uint64_t total_value) {
        label = name;
        total = total_value;
        start = std::chrono::steady_clock::now();
        last_report = start;
        last_value = 0;
        enabled = (total > 0);
        if (enabled) {
            std::cerr << "[*] " << label << " started (total=" << total << ")\n";
        }
    }

    void update(uint64_t value, bool force = false) {
        if (!enabled) return;
        if (value > total) value = total;
        auto now = std::chrono::steady_clock::now();
        auto since = now - last_report;
        if (!force && since < std::chrono::seconds(1) && value < total) return;

        double elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(now - start).count();
        double rate = elapsed > 0.0 ? (double)value / elapsed : 0.0;
        double remaining = (rate > 0.0) ? (double)(total - value) / rate : -1.0;
        int pct = total > 0 ? (int)((double)value * 100.0 / (double)total) : 0;

        std::cerr << "[*] " << label << " " << pct << "% ("
                  << value << "/" << total << ") ETA " << format_duration(remaining) << "\n";
        last_report = now;
        last_value = value;
    }

    void finish(uint64_t value) {
        if (!enabled) return;
        update(value, true);
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(now - start).count();
        std::cerr << "[*] " << label << " done in " << format_duration(elapsed) << "\n";
        enabled = false;
    }
};

static fs::path unique_path(const fs::path& base) {
    if (!fs::exists(base)) return base;
    for (int i = 1; i < 1000; ++i) {
        std::ostringstream oss;
        oss << base.string() << "_" << std::setw(2) << std::setfill('0') << i;
        fs::path cand(oss.str());
        if (!fs::exists(cand)) return cand;
    }
    throw std::runtime_error("unique_path: too many collisions");
}

static std::string read_password_noecho(const std::string& prompt) {
    std::cerr << prompt;
    termios oldt{};
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) throw std::runtime_error("tcgetattr failed");
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) throw std::runtime_error("tcsetattr failed");

    std::string pwd;
    std::getline(std::cin, pwd);

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cerr << "\n";
    return pwd;
}

static std::string get_obj_auth_once() {
    const char* env = std::getenv("TPM_OBJECT_AUTH");
    if (env && std::strlen(env) > 0) return std::string(env);
    return read_password_noecho("TPM object auth (will not echo): ");
}

static std::string b64e(const std::vector<uint8_t>& in) {
    if (in.empty()) return "";
    std::string out;
    out.resize(4 * ((in.size() + 2) / 3));
    int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&out[0]),
                            reinterpret_cast<const unsigned char*>(in.data()),
                            static_cast<int>(in.size()));
    if (n < 0) throw std::runtime_error("EVP_EncodeBlock failed");
    out.resize(n);
    return out;
}

static std::vector<uint8_t> b64d(const std::string& s) {
    if (s.empty()) return {};
    std::vector<uint8_t> out((s.size() * 3) / 4 + 4);
    int n = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                            reinterpret_cast<const unsigned char*>(s.data()),
                            static_cast<int>(s.size()));
    if (n < 0) throw std::runtime_error("EVP_DecodeBlock failed");
    int pad = 0;
    if (!s.empty() && s.back() == '=') pad++;
    if (s.size() >= 2 && s[s.size() - 2] == '=') pad++;
    n -= pad;
    if (n < 0) n = 0;
    out.resize(static_cast<size_t>(n));
    return out;
}

static constexpr int64_t kKstOffsetSec = 9 * 60 * 60;

static uint64_t now_epoch_ms() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    return static_cast<uint64_t>(ms);
}

static uint64_t now_kst_epoch_ms() {
    return now_epoch_ms() + static_cast<uint64_t>(kKstOffsetSec) * 1000ULL;
}

static uint64_t epoch_ns_to_ms_floor(uint64_t epoch_ns) {
    uint64_t ms = epoch_ns / 1000000ULL;
    return (ms / 1000ULL) * 1000ULL;
}

static bool parse_leading_u64(const std::string& s, uint64_t& out) {
    if (s.empty() || s[0] < '0' || s[0] > '9') return false;
    uint64_t val = 0;
    size_t i = 0;
    for (; i < s.size(); ++i) {
        char c = s[i];
        if (c < '0' || c > '9') break;
        uint64_t next = val * 10 + static_cast<uint64_t>(c - '0');
        if (next < val) return false;
        val = next;
    }
    if (i == 0) return false;
    out = val;
    return true;
}

static fs::path cold_day_dir_for_epoch(const fs::path& cold_root,
                                       uint64_t epoch_ns) {
    std::time_t sec = static_cast<std::time_t>(epoch_ns / 1000000000ULL) + kKstOffsetSec;
    std::tm tm{};
    gmtime_r(&sec, &tm);
    std::ostringstream y, m, d;
    y << std::setw(4) << std::setfill('0') << (tm.tm_year + 1900);
    m << std::setw(2) << std::setfill('0') << (tm.tm_mon + 1);
    d << std::setw(2) << std::setfill('0') << tm.tm_mday;
    return cold_root / y.str() / m.str() / d.str();
}

static std::string kst_date_key_from_ms(uint64_t kst_ms) {
    std::time_t sec = static_cast<std::time_t>(kst_ms / 1000ULL);
    std::tm tm{};
    gmtime_r(&sec, &tm);
    std::ostringstream out;
    out << std::setw(4) << std::setfill('0') << (tm.tm_year + 1900)
        << std::setw(2) << std::setfill('0') << (tm.tm_mon + 1)
        << std::setw(2) << std::setfill('0') << tm.tm_mday;
    return out.str();
}

static std::vector<uint8_t> rand_key_32() {
    std::vector<uint8_t> key(32, 0);
    if (RAND_bytes(key.data(), (int)key.size()) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return key;
}

static fs::path resolve_root(const fs::path& base, const fs::path& sub) {
    if (sub.is_absolute()) return sub;
    return base / sub;
}

static uint64_t compute_pts(uint64_t frame_ts_ns,
                            uint64_t seg_start_ns,
                            uint64_t dur_ns,
                            uint64_t& last_pts_ns) {
    uint64_t pts_ns = 0;
    if (frame_ts_ns >= seg_start_ns) {
        pts_ns = frame_ts_ns - seg_start_ns;
    }
    if (pts_ns <= last_pts_ns) {
        pts_ns = last_pts_ns + dur_ns;
    }
    last_pts_ns = pts_ns;
    return pts_ns;
}

template <typename T>
static T meta_get(const json& meta,
                  const char* section,
                  const char* key,
                  const char* legacy_key,
                  const T& default_value) {
    if (section && key) {
        auto sit = meta.find(section);
        if (sit != meta.end() && sit->is_object()) {
            auto kit = sit->find(key);
            if (kit != sit->end() && !kit->is_null()) {
                try { return kit->get<T>(); } catch (...) {}
            }
        }
    }
    if (legacy_key) {
        auto lit = meta.find(legacy_key);
        if (lit != meta.end() && !lit->is_null()) {
            try { return lit->get<T>(); } catch (...) {}
        }
    }
    return default_value;
}

static bool meta_has(const json& meta,
                     const char* section,
                     const char* key,
                     const char* legacy_key) {
    if (section && key) {
        auto sit = meta.find(section);
        if (sit != meta.end() && sit->is_object()) {
            auto kit = sit->find(key);
            if (kit != sit->end() && !kit->is_null()) return true;
        }
    }
    if (legacy_key) {
        auto lit = meta.find(legacy_key);
        if (lit != meta.end() && !lit->is_null()) return true;
    }
    return false;
}

static bool has_suffix(const std::string& s, const std::string& suffix) {
    if (s.size() < suffix.size()) return false;
    return s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static std::string strip_suffix(const std::string& s, const std::string& suffix) {
    if (!has_suffix(s, suffix)) return s;
    return s.substr(0, s.size() - suffix.size());
}

static fs::path default_mask_sidecar_from_meta(const fs::path& meta_path) {
    std::string name = meta_path.filename().string();
    std::string base = strip_suffix(name, ".meta.json");
    if (base == name) {
        base = meta_path.stem().string();
        base = strip_suffix(base, ".meta");
    }
    return meta_path.parent_path() / (base + ".mask.jsonl");
}

struct RoiSidecarInfo {
    std::map<uint64_t, std::vector<secure_save::RoiBox>> boxes_by_frame;
    std::vector<uint8_t> salt;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t fps_num = 30;
    uint32_t fps_den = 1;
    std::string algo;
    std::string iv_scheme;
    bool has_header = false;
};

static RoiSidecarInfo load_roi_sidecar_jsonl(const fs::path& sidecar_path) {
    RoiSidecarInfo out;
    std::ifstream ifs(sidecar_path);
    if (!ifs) return out;

    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty()) continue;
        json j;
        try {
            j = json::parse(line);
        } catch (...) {
            continue;
        }
        std::string type = j.value("type", "");
        if (type == "header") {
            out.has_header = true;
            out.algo = j.value("algo", "");
            out.iv_scheme = j.value("iv_scheme", "");
            std::string salt_b64 = j.value("salt_b64", "");
            if (!salt_b64.empty()) {
                try { out.salt = b64d(salt_b64); } catch (...) {}
            }
            out.width = j.value("w", 0U);
            out.height = j.value("h", 0U);
            out.fps_num = j.value("fps_num", 30U);
            out.fps_den = j.value("fps_den", 1U);
            if (out.fps_num == 0) out.fps_num = 30;
            if (out.fps_den == 0) out.fps_den = 1;
            continue;
        }
        if (type != "frame") continue;
        uint64_t idx = j.value("i", 0ULL);
        std::vector<secure_save::RoiBox> boxes;
        if (j.contains("boxes") && j["boxes"].is_array()) {
            for (const auto& b : j["boxes"]) {
                secure_save::RoiBox rb;
                rb.x = b.value("x", 0);
                rb.y = b.value("y", 0);
                rb.w = b.value("w", 0);
                rb.h = b.value("h", 0);
                rb.id = b.value("id", -1);
                boxes.push_back(rb);
            }
        }
        out.boxes_by_frame[idx] = std::move(boxes);
    }
    return out;
}

static fs::path roi_unmask_video(const fs::path& input_path,
                                 const fs::path& output_path,
                                 const std::vector<uint8_t>& master_key,
                                 const fs::path& sidecar_path) {
    if (master_key.size() != 32) {
        throw std::runtime_error("ROI unmask requires 32-byte master key");
    }

    RoiSidecarInfo sidecar = load_roi_sidecar_jsonl(sidecar_path);
    if (!sidecar.has_header) {
        throw std::runtime_error("ROI sidecar header missing");
    }
    if (sidecar.salt.size() != 12) {
        throw std::runtime_error("ROI sidecar salt missing or invalid");
    }
    if (sidecar.width == 0 || sidecar.height == 0) {
        throw std::runtime_error("ROI sidecar size missing or invalid");
    }
    if (!sidecar.algo.empty() && sidecar.algo != "aes-256-ctr") {
        throw std::runtime_error("Unsupported ROI algo in sidecar: " + sidecar.algo);
    }
    if (!sidecar.iv_scheme.empty() && sidecar.iv_scheme != "sha256(salt|frame|roi)") {
        throw std::runtime_error("Unsupported ROI iv_scheme in sidecar: " + sidecar.iv_scheme);
    }

    uint32_t width = sidecar.width;
    uint32_t height = sidecar.height;
    uint32_t fps_num = sidecar.fps_num;
    uint32_t fps_den = sidecar.fps_den;
    auto& boxes_by_frame = sidecar.boxes_by_frame;
    bool has_boxes = !boxes_by_frame.empty();
    uint64_t max_frame_index = has_boxes ? boxes_by_frame.rbegin()->first : 0;
    if (has_boxes) {
        std::cerr << "[*] ROI unmask: sidecar=" << sidecar_path
                  << " frames=" << boxes_by_frame.size()
                  << " max_frame=" << max_frame_index
                  << " size=" << width << "x" << height
                  << " fps=" << fps_num << "/" << fps_den << "\n";
    } else {
        std::cerr << "[*] ROI unmask: sidecar=" << sidecar_path
                  << " frames=0 (no boxes)" << "\n";
    }

    std::string input_cmd = "ffmpeg -v error -i \"" + input_path.string() +
                            "\" -f rawvideo -pix_fmt rgb24 -";
    FILE* in_pipe = popen(input_cmd.c_str(), "r");
    if (!in_pipe) throw std::runtime_error("ffmpeg input pipe failed");

    std::string fps_str = std::to_string(fps_num) + "/" + std::to_string(fps_den);
    std::string output_cmd = "ffmpeg -v error -y -f rawvideo -pix_fmt rgb24 -s " +
                             std::to_string(width) + "x" + std::to_string(height) +
                              " -framerate " + fps_str + " -i - " +
                             "-c:v ffv1 -level 3 -g 1 -pix_fmt rgb24 \"" +
                              output_path.string() + "\"";
    FILE* out_pipe = popen(output_cmd.c_str(), "w");
    if (!out_pipe) {
        pclose(in_pipe);
        throw std::runtime_error("ffmpeg output pipe failed");
    }

    const size_t frame_size = static_cast<size_t>(width) * height * 3;
    std::vector<uint8_t> frame_buf(frame_size);
    secure_save::RoiMaskerOptions options;
    secure_save::RoiMasker masker(options);
    masker.BeginSegmentWithSalt(master_key.data(), master_key.size(), sidecar.salt);

    uint64_t frame_index = 0;
    size_t masked_frames = 0;
    size_t total_boxes = 0;
    while (true) {
        size_t got = fread(frame_buf.data(), 1, frame_size, in_pipe);
        if (got != frame_size) break;

        auto it = boxes_by_frame.find(frame_index);
        if (it != boxes_by_frame.end() && !it->second.empty()) {
            masker.MaskRgbFrameInPlaceNormalized(frame_buf.data(), width, height,
                                                 static_cast<uint32_t>(width * 3),
                                                 frame_index, it->second);
            masked_frames++;
            total_boxes += it->second.size();
        }

        size_t written = fwrite(frame_buf.data(), 1, frame_size, out_pipe);
        if (written != frame_size) {
            break;
        }
        frame_index++;
    }

    bool input_error = ferror(in_pipe) != 0;
    bool output_error = ferror(out_pipe) != 0;
    errno = 0;
    int in_rc = pclose(in_pipe);
    int in_errno = (in_rc == -1) ? errno : 0;
    errno = 0;
    int out_rc = pclose(out_pipe);
    int out_errno = (out_rc == -1) ? errno : 0;
    auto exit_code = [](int rc) {
        if (rc == -1) return -1;
        if (WIFEXITED(rc)) return WEXITSTATUS(rc);
        if (WIFSIGNALED(rc)) return 128 + WTERMSIG(rc);
        return -1;
    };
    int in_code = exit_code(in_rc);
    int out_code = exit_code(out_rc);
    if (in_code == -1 && in_errno == ECHILD) {
        in_code = 0;
    }
    if (out_code == -1 && out_errno == ECHILD) {
        out_code = 0;
    }
    if (input_error || in_code != 0) {
        throw std::runtime_error("ffmpeg decode failed for roi_unmask (code=" + std::to_string(in_code) + ")");
    }
    if (output_error || out_code != 0) {
        throw std::runtime_error("ffmpeg encode failed for roi_unmask (code=" + std::to_string(out_code) + ")");
    }
    if (has_boxes) {
        uint64_t last_frame = frame_index > 0 ? frame_index - 1 : 0;
        if (last_frame < max_frame_index) {
            std::cerr << "[!] ROI unmask warning: decoded " << frame_index
                      << " frames, sidecar max index " << max_frame_index << "\n";
        }
        std::cerr << "[*] ROI unmask applied: frames=" << frame_index
                  << " masked_frames=" << masked_frames
                  << " boxes=" << total_boxes << "\n";
    }
    return output_path;
}

static bool sealed_key_exists(const fs::path& key_prefix) {
    fs::path pubf = key_prefix; pubf += ".pub";
    fs::path privf = key_prefix; privf += ".priv";
    return fs::exists(pubf) && fs::exists(privf);
}

static void cleanup_hot_dir(const fs::path& hot_dir, int retention_hours) {
    if (retention_hours <= 0) return;
    if (!fs::exists(hot_dir)) return;
    uint64_t cutoff = now_epoch_ms() - static_cast<uint64_t>(retention_hours) * 3600000ULL;

    for (auto& it : fs::directory_iterator(hot_dir)) {
        if (!it.is_regular_file()) continue;
        uint64_t ts = 0;
        if (!parse_leading_u64(it.path().filename().string(), ts)) continue;
        if (ts < cutoff) {
            std::error_code ec;
            fs::remove(it.path(), ec);
        }
    }
}

static bool parse_int_str(const std::string& s, int& out) {
    if (s.empty()) return false;
    int val = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        val = val * 10 + (c - '0');
    }
    out = val;
    return true;
}

static void cleanup_cold_dir(const fs::path& cold_root, int retention_days) {
    if (retention_days <= 0) return;
    if (!fs::exists(cold_root)) return;

    uint64_t cutoff_kst_ms = now_kst_epoch_ms() - static_cast<uint64_t>(retention_days) * 86400000ULL;
    std::string cutoff_key = kst_date_key_from_ms(cutoff_kst_ms);

    for (auto& y_it : fs::directory_iterator(cold_root)) {
        if (!y_it.is_directory()) continue;
        int year = 0;
        if (!parse_int_str(y_it.path().filename().string(), year)) continue;

        for (auto& m_it : fs::directory_iterator(y_it.path())) {
            if (!m_it.is_directory()) continue;
            int month = 0;
            if (!parse_int_str(m_it.path().filename().string(), month)) continue;

            for (auto& d_it : fs::directory_iterator(m_it.path())) {
                if (!d_it.is_directory()) continue;
                int day = 0;
                if (!parse_int_str(d_it.path().filename().string(), day)) continue;

                std::ostringstream key;
                key << std::setw(4) << std::setfill('0') << year
                    << std::setw(2) << std::setfill('0') << month
                    << std::setw(2) << std::setfill('0') << day;
                if (key.str() < cutoff_key) {
                    std::error_code ec;
                    fs::remove_all(d_it.path(), ec);
                }
            }
        }
    }
}


static std::string roi_policy_name(secure_save::SecureSaveConfig::RoiMaskConfig::FailPolicy policy) {
    using Policy = secure_save::SecureSaveConfig::RoiMaskConfig::FailPolicy;
    switch (policy) {
        case Policy::FailOpen: return "fail-open";
        case Policy::FailClose: return "fail-close";
        case Policy::FailHard: return "fail-hard";
    }
    return "unknown";
}

static std::vector<secure_save::RoiBox> to_roi_boxes(const std::vector<secure_save::FrameBox>& boxes) {
    std::vector<secure_save::RoiBox> out;
    out.reserve(boxes.size());
    for (const auto& box : boxes) {
        secure_save::RoiBox r;
        r.x = box.x1;
        r.y = box.y1;
        r.w = box.x2 - box.x1;
        r.h = box.y2 - box.y1;
        r.id = box.track_id;
        out.push_back(r);
    }
    return out;
}

static void fill_black(std::vector<uint8_t>& rgb) {
    std::fill(rgb.begin(), rgb.end(), 0);
}

struct CmdResult {
    int code = -1;
    std::vector<uint8_t> out;
    std::vector<uint8_t> err;
};

static std::string bytes_to_string(const std::vector<uint8_t>& v) {
    return std::string(reinterpret_cast<const char*>(v.data()), v.size());
}

static CmdResult run_cmd(const std::vector<std::string>& args) {
    if (args.empty()) throw std::runtime_error("run_cmd: empty args");

    int outpipe[2];
    int errpipe[2];
    if (pipe(outpipe) != 0) throw std::runtime_error("pipe(out) failed");
    if (pipe(errpipe) != 0) throw std::runtime_error("pipe(err) failed");

    pid_t pid = fork();
    if (pid < 0) throw std::runtime_error("fork failed");

    if (pid == 0) {
        dup2(outpipe[1], STDOUT_FILENO);
        dup2(errpipe[1], STDERR_FILENO);
        close(outpipe[0]);
        close(outpipe[1]);
        close(errpipe[0]);
        close(errpipe[1]);

        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (auto& s : args) argv.push_back(const_cast<char*>(s.c_str()));
        argv.push_back(nullptr);
        execvp(argv[0], argv.data());
        _exit(127);
    }

    close(outpipe[1]);
    close(errpipe[1]);

    CmdResult res;

    auto read_all = [](int fd, std::vector<uint8_t>& dst) {
        uint8_t tmp[4096];
        while (true) {
            ssize_t r = read(fd, tmp, sizeof(tmp));
            if (r < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (r == 0) break;
            dst.insert(dst.end(), tmp, tmp + r);
        }
    };

    std::thread t_out([&](){ read_all(outpipe[0], res.out); close(outpipe[0]); });
    std::thread t_err([&](){ read_all(errpipe[0], res.err); close(errpipe[0]); });

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) res.code = WEXITSTATUS(status);
    else res.code = 128;

    t_out.join();
    t_err.join();
    return res;
}

static void run_cmd_or_throw(const std::vector<std::string>& args) {
    auto r = run_cmd(args);
    if (r.code != 0) {
        std::ostringstream oss;
        oss << "Command failed: ";
        for (auto& a : args) oss << a << " ";
        oss << "\nstdout:\n" << bytes_to_string(r.out)
            << "\nstderr:\n" << bytes_to_string(r.err);
        throw std::runtime_error(oss.str());
    }
}

static std::vector<uint8_t> request_policy_signature(const std::string& server_url,
                                                     const std::vector<uint8_t>& raw_data);

static void ensure_primary(const fs::path& primary_ctx) {
    if (fs::exists(primary_ctx)) return;
    std::cerr << "[*] Creating primary key (owner hierarchy)...\n";
    run_cmd_or_throw({"tpm2_createprimary", "-C", "o", "-c", primary_ctx.string()});
}

static std::vector<uint8_t> tpm_get_random_32() {
    std::lock_guard<std::mutex> lk(g_tpm_mutex);
    fs::path tmp = unique_path(fs::temp_directory_path() / "tpm_rand.bin");
    run_cmd_or_throw({"tpm2_getrandom", "-o", tmp.string(), "32"});
    std::ifstream ifs(tmp, std::ios::binary);
    if (!ifs) {
        throw std::runtime_error("Failed to open TPM random temp file");
    }
    std::vector<uint8_t> out((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    std::error_code ec;
    fs::remove(tmp, ec);
    if (out.size() != 32) throw std::runtime_error("TPM random length != 32");
    return out;
}

static void tpm_seal_key(const std::vector<uint8_t>& key32,
                         const fs::path& key_prefix,
                         const std::string& obj_auth,
                         const fs::path& primary_ctx,
                         const secure_save::PolicyConfig& policy_cfg,
                         std::optional<fs::path>& out_policy_file,
                         std::optional<fs::path>& out_signer_pub_copy) {
    std::lock_guard<std::mutex> lk(g_tpm_mutex);
    ensure_primary(primary_ctx);

    fs::path tmp_key = key_prefix; tmp_key += ".key.bin";
    fs::path pubf = key_prefix; pubf += ".pub";
    fs::path privf = key_prefix; privf += ".priv";

    { std::ofstream ofs(tmp_key, std::ios::binary); ofs.write((char*)key32.data(), key32.size()); }

    std::vector<std::string> cmd = {
        "tpm2_create",
        "-C", primary_ctx.string(),
        "-u", pubf.string(),
        "-r", privf.string(),
        "-i", tmp_key.string(),
        "-a", "fixedtpm|fixedparent|userwithauth"
    };

    if (policy_cfg.enabled) {
        if (policy_cfg.signer_pub.empty()) {
            throw std::runtime_error("policy signer pub not set");
        }
        if (policy_cfg.server_url.empty()) {
            throw std::runtime_error("policy server url not set");
        }
        fs::path signer_copy = key_prefix.parent_path() / "signer.pub";
        fs::copy_file(policy_cfg.signer_pub, signer_copy, fs::copy_options::overwrite_existing);
        fs::path signer_ctx = key_prefix.parent_path() / "signer.ctx";
        fs::path policy_file = key_prefix; policy_file += ".policy";
        fs::path raw_session = policy_file.string() + ".rawsess";
        fs::path session_ctx = policy_file.string() + ".sess";
        fs::path raw_data = policy_file.string() + ".raw";
        fs::path sig_file = policy_file.string() + ".sig";

        run_cmd_or_throw({"tpm2_loadexternal", "-C", "o", "-G", "rsa", "-u", signer_copy.string(), "-c", signer_ctx.string()});

        run_cmd_or_throw({"tpm2_startauthsession", "--policy-session", "-S", raw_session.string()});
        run_cmd_or_throw({
            "tpm2_policysigned",
            "-S", raw_session.string(),
            "-c", signer_ctx.string(),
            "-g", "sha256",
            "--raw-data", raw_data.string()
        });
        run_cmd_or_throw({"tpm2_flushcontext", raw_session.string()});

        std::vector<uint8_t> raw;
        {
            std::ifstream ifs(raw_data, std::ios::binary);
            raw.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
        }
        auto sig = request_policy_signature(policy_cfg.server_url, raw);
        { std::ofstream ofs(sig_file, std::ios::binary); ofs.write((char*)sig.data(), sig.size()); }

        run_cmd_or_throw({"tpm2_startauthsession", "--policy-session", "-S", session_ctx.string()});
        run_cmd_or_throw({
            "tpm2_policysigned",
            "-S", session_ctx.string(),
            "-c", signer_ctx.string(),
            "-g", "sha256",
            "-s", sig_file.string(),
            "-f", "rsassa",
            "-L", policy_file.string()
        });
        run_cmd_or_throw({"tpm2_flushcontext", session_ctx.string()});
        try { run_cmd_or_throw({"tpm2_flushcontext", signer_ctx.string()}); } catch(...) {}

        cmd.push_back("-L");
        cmd.push_back(policy_file.string());

        out_policy_file = policy_file;
        out_signer_pub_copy = signer_copy;

        std::error_code ec;
        fs::remove(signer_ctx, ec);
        fs::remove(session_ctx, ec);
        fs::remove(raw_data, ec);
        fs::remove(sig_file, ec);
    } else {
        cmd.push_back("-p");
        cmd.push_back("str:" + obj_auth);
    }

    run_cmd_or_throw(cmd);

    std::error_code ec;
    fs::remove(tmp_key, ec);
}

static std::vector<uint8_t> request_policy_signature(const std::string& server_url,
                                                     const std::vector<uint8_t>& raw_data) {
    json body;
    body["raw_b64"] = b64e(raw_data);
    fs::path req_file = fs::path("/tmp") / ("policy_req_" + now_ts_name() + ".json");
    fs::path resp_file = fs::path("/tmp") / ("policy_resp_" + now_ts_name() + ".json");
    { std::ofstream ofs(req_file); ofs << body.dump(); }

    CmdResult last;
    bool ok = false;
    for (int attempt = 0; attempt < 20; ++attempt) {
        last = run_cmd({
            "/usr/bin/curl", "-s", "-X", "POST",
            "-H", "Content-Type: application/json",
            "-d", "@" + req_file.string(),
            "-o", resp_file.string(),
            server_url
        });
        if (last.code == 0) {
            ok = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    if (!ok) {
        std::ostringstream oss;
        oss << "policy server request failed (code=" << last.code << "):\n" << bytes_to_string(last.err);
        throw std::runtime_error(oss.str());
    }

    json resp;
    { std::ifstream ifs(resp_file); ifs >> resp; }

    std::error_code ec;
    fs::remove(req_file, ec);
    fs::remove(resp_file, ec);

    if (!resp.contains("sig_b64")) {
        throw std::runtime_error("policy server response missing sig_b64");
    }
    return b64d(resp["sig_b64"].get<std::string>());
}

static std::vector<uint8_t> tpm_unseal_key(const fs::path& key_prefix,
                                           const std::string& obj_auth,
                                           const fs::path& primary_ctx,
                                           const secure_save::PolicyConfig& policy_cfg,
                                           const std::optional<fs::path>& policy_file,
                                           const std::optional<fs::path>& signer_pub_copy) {
    std::lock_guard<std::mutex> lk(g_tpm_mutex);
    ensure_primary(primary_ctx);

    fs::path pubf = key_prefix; pubf += ".pub";
    fs::path privf = key_prefix; privf += ".priv";
    if (!fs::exists(pubf) || !fs::exists(privf)) {
        throw std::runtime_error("sealed key files not found");
    }

    fs::path ctx = key_prefix; ctx += ".ctx";
    run_cmd_or_throw({"tpm2_load","-C", primary_ctx.string(), "-u", pubf.string(), "-r", privf.string(), "-c", ctx.string()});

    CmdResult r;
    if (policy_cfg.enabled) {
        if (policy_cfg.server_url.empty()) {
            throw std::runtime_error("policy server url not set");
        }
        if (!policy_file.has_value() || !signer_pub_copy.has_value()) {
            throw std::runtime_error("policy metadata missing");
        }

        fs::path signer_ctx = key_prefix.parent_path() / "signer.ctx";
        fs::path raw_session = key_prefix.parent_path() / "policy.rawsession";
        fs::path session_ctx = key_prefix.parent_path() / "policy.session";
        fs::path raw_data = key_prefix.parent_path() / "tosign.bin";
        fs::path sig_file = key_prefix.parent_path() / "sig.bin";

        run_cmd_or_throw({"tpm2_loadexternal", "-C", "o", "-G", "rsa", "-u", signer_pub_copy->string(), "-c", signer_ctx.string()});
        run_cmd_or_throw({"tpm2_startauthsession", "--policy-session", "-S", raw_session.string()});
        run_cmd_or_throw({
            "tpm2_policysigned",
            "-S", raw_session.string(),
            "-c", signer_ctx.string(),
            "-g", "sha256",
            "--raw-data", raw_data.string()
        });
        run_cmd_or_throw({"tpm2_flushcontext", raw_session.string()});

        std::vector<uint8_t> raw;
        {
            std::ifstream ifs(raw_data, std::ios::binary);
            raw.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
        }

        auto sig = request_policy_signature(policy_cfg.server_url, raw);
        { std::ofstream ofs(sig_file, std::ios::binary); ofs.write((char*)sig.data(), sig.size()); }

        run_cmd_or_throw({"tpm2_startauthsession", "--policy-session", "-S", session_ctx.string()});
        run_cmd_or_throw({
            "tpm2_policysigned",
            "-S", session_ctx.string(),
            "-c", signer_ctx.string(),
            "-g", "sha256",
            "-s", sig_file.string(),
            "-f", "rsassa"
        });

        r = run_cmd({"tpm2_unseal", "-c", ctx.string(), "-p", "session:" + session_ctx.string()});

        try { run_cmd_or_throw({"tpm2_flushcontext", session_ctx.string()}); } catch(...) {}
        try { run_cmd_or_throw({"tpm2_flushcontext", signer_ctx.string()}); } catch(...) {}

        std::error_code ec;
        fs::remove(signer_ctx, ec);
        fs::remove(raw_data, ec);
        fs::remove(sig_file, ec);
        fs::remove(session_ctx, ec);
    } else {
        r = run_cmd({"tpm2_unseal","-c", ctx.string(), "-p", "str:" + obj_auth});
    }

    try { run_cmd_or_throw({"tpm2_flushcontext", ctx.string()}); } catch(...) {}
    std::error_code ec; fs::remove(ctx, ec);

    if (r.code != 0) throw std::runtime_error("tpm2_unseal failed:\n" + bytes_to_string(r.err));
    if (r.out.size() != 32) throw std::runtime_error("Unexpected key length");
    return std::vector<uint8_t>(r.out.begin(), r.out.end());
}

static std::vector<uint8_t> aes_gcm_encrypt_buf(const std::vector<uint8_t>& key32,
                                                const std::vector<uint8_t>& nonce12,
                                                const std::vector<uint8_t>& plain,
                                                const std::optional<std::vector<uint8_t>>& aad,
                                                std::vector<uint8_t>& out_tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    auto fail = [&](const char* msg) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error(msg);
    };

    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    if (ok != 1) fail("EncryptInit failed");
    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    if (ok != 1) fail("SET_IVLEN failed");
    ok = EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                           (const unsigned char*)key32.data(),
                           (const unsigned char*)nonce12.data());
    if (ok != 1) fail("EncryptInit key/nonce failed");

    if (aad.has_value() && !aad->empty()) {
        int len = 0;
        ok = EVP_EncryptUpdate(ctx, nullptr, &len,
                               (const unsigned char*)aad->data(),
                               (int)aad->size());
        if (ok != 1) fail("AAD update failed");
    }

    std::vector<uint8_t> out(plain.size() + 16);
    int outlen = 0;
    ok = EVP_EncryptUpdate(ctx, out.data(), &outlen,
                           (const unsigned char*)plain.data(),
                           (int)plain.size());
    if (ok != 1) fail("EncryptUpdate failed");

    int finlen = 0;
    ok = EVP_EncryptFinal_ex(ctx, out.data() + outlen, &finlen);
    if (ok != 1) fail("EncryptFinal failed");

    out.resize(outlen + finlen);
    out_tag.assign(16, 0);
    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out_tag.data());
    if (ok != 1) fail("GET_TAG failed");

    EVP_CIPHER_CTX_free(ctx);
    return out;
}

static std::vector<uint8_t> aes_gcm_decrypt_buf(const std::vector<uint8_t>& key32,
                                                const std::vector<uint8_t>& nonce12,
                                                const std::vector<uint8_t>& cipher,
                                                const std::vector<uint8_t>& tag16,
                                                const std::optional<std::vector<uint8_t>>& aad) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    auto fail = [&](const char* msg) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error(msg);
    };

    int ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    if (ok != 1) fail("DecryptInit failed");
    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    if (ok != 1) fail("SET_IVLEN failed");
    ok = EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                           (const unsigned char*)key32.data(),
                           (const unsigned char*)nonce12.data());
    if (ok != 1) fail("DecryptInit key/nonce failed");

    if (aad.has_value() && !aad->empty()) {
        int len = 0;
        ok = EVP_DecryptUpdate(ctx, nullptr, &len,
                               (const unsigned char*)aad->data(),
                               (int)aad->size());
        if (ok != 1) fail("AAD update failed");
    }

    std::vector<uint8_t> out(cipher.size() + 16);
    int outlen = 0;
    ok = EVP_DecryptUpdate(ctx, out.data(), &outlen,
                           (const unsigned char*)cipher.data(),
                           (int)cipher.size());
    if (ok != 1) fail("DecryptUpdate failed");

    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag16.data());
    if (ok != 1) fail("SET_TAG failed");

    int finlen = 0;
    ok = EVP_DecryptFinal_ex(ctx, out.data() + outlen, &finlen);
    if (ok != 1) fail("AES-GCM decrypt failed (tag mismatch or EVP error)");

    out.resize(outlen + finlen);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

struct AesGcmEnc {
    EVP_CIPHER_CTX* ctx = nullptr;
    std::vector<uint8_t> key;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> tag;
    uint64_t plain_bytes = 0;
    uint64_t cipher_bytes = 0;

    void init(const std::vector<uint8_t>& key32,
              const std::vector<uint8_t>& nonce12,
              const std::optional<std::vector<uint8_t>>& aad) {
        key = key32;
        nonce = nonce12;
        tag.assign(16, 0);
        plain_bytes = 0;
        cipher_bytes = 0;

        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

        int ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        if (ok != 1) throw std::runtime_error("EncryptInit failed");

        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        if (ok != 1) throw std::runtime_error("SET_IVLEN failed");

        ok = EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                               (const unsigned char*)key.data(),
                               (const unsigned char*)nonce.data());
        if (ok != 1) throw std::runtime_error("EncryptInit key/nonce failed");

        if (aad.has_value() && !aad->empty()) {
            int len = 0;
            ok = EVP_EncryptUpdate(ctx, nullptr, &len,
                                  (const unsigned char*)aad->data(),
                                  (int)aad->size());
            if (ok != 1) throw std::runtime_error("AAD update failed");
        }
    }

    void update(const uint8_t* data, size_t n, std::ofstream& out) {
        if (!ctx) throw std::runtime_error("enc ctx not initialized");
        plain_bytes += n;

        std::vector<uint8_t> buf(n + 16);
        int outlen = 0;
        int ok = EVP_EncryptUpdate(ctx, buf.data(), &outlen, data, (int)n);
        if (ok != 1) throw std::runtime_error("EncryptUpdate failed");
        if (outlen > 0) {
            out.write((const char*)buf.data(), outlen);
            cipher_bytes += (uint64_t)outlen;
        }
    }

    void finalize(std::ofstream& out) {
        if (!ctx) return;
        std::vector<uint8_t> buf(32);
        int outlen = 0;
        int ok = EVP_EncryptFinal_ex(ctx, buf.data(), &outlen);
        if (ok != 1) throw std::runtime_error("EncryptFinal failed");
        if (outlen > 0) {
            out.write((const char*)buf.data(), outlen);
            cipher_bytes += (uint64_t)outlen;
        }
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
        if (ok != 1) throw std::runtime_error("GET_TAG failed");
        EVP_CIPHER_CTX_free(ctx);
        ctx = nullptr;
    }

    ~AesGcmEnc() {
        if (ctx) EVP_CIPHER_CTX_free(ctx);
    }
};

struct TrackJsonEncWriter {
    bool enabled = false;
    bool write_header = true;
    bool include_empty_frames = true;
    std::string schema = "track-jsonl-v1";
    fs::path enc_path;
    std::ofstream out;
    AesGcmEnc enc;
    std::vector<uint8_t> nonce;
    bool started = false;

    void start(const fs::path& path,
               const std::vector<uint8_t>& key32,
               const std::optional<std::vector<uint8_t>>& aad,
               const std::string& segment_name,
               uint32_t width,
               uint32_t height,
               uint32_t fps_num,
               uint32_t fps_den,
               const secure_save::SecureSaveConfig::TrackConfig& cfg) {
        enabled = cfg.enabled;
        write_header = cfg.write_header;
        include_empty_frames = cfg.include_empty_frames;
        if (!enabled) return;
        enc_path = path;
        out.open(enc_path, std::ios::binary);
        if (!out) throw std::runtime_error("Failed to open track enc output");
        nonce.assign(12, 0);
        if (RAND_bytes(nonce.data(), (int)nonce.size()) != 1) {
            throw std::runtime_error("RAND_bytes failed");
        }
        enc.init(key32, nonce, aad);
        started = true;

        if (write_header) {
            json header;
            header["type"] = "header";
            header["schema"] = schema;
            header["segment"] = segment_name;
            header["bbox_format"] = "x1y1x2y2";
            header["w"] = width;
            header["h"] = height;
            header["fps_num"] = fps_num;
            header["fps_den"] = fps_den;
            write_line(header.dump());
        }
    }

    void on_frame(uint64_t frame_index, const std::vector<secure_save::FrameBox>& boxes) {
        if (!started) return;
        json frame;
        frame["type"] = "frame";
        frame["i"] = frame_index;
        json objects = json::array();
        for (const auto& box : boxes) {
            if (box.track_id < 0) continue;
            json obj;
            obj["id"] = box.track_id;
            obj["x1"] = box.x1;
            obj["y1"] = box.y1;
            obj["x2"] = box.x2;
            obj["y2"] = box.y2;
            objects.push_back(std::move(obj));
        }
        if (objects.empty() && !include_empty_frames) return;
        frame["objects"] = std::move(objects);
        write_line(frame.dump());
    }

    void finish() {
        if (!started) return;
        enc.finalize(out);
        out.close();
        started = false;
    }

    uint64_t plain_bytes() const { return enc.plain_bytes; }
    uint64_t cipher_bytes() const { return enc.cipher_bytes; }
    const std::vector<uint8_t>& nonce_bytes() const { return nonce; }
    const std::vector<uint8_t>& tag_bytes() const { return enc.tag; }

private:
    void write_line(const std::string& line) {
        if (!started) return;
        enc.update(reinterpret_cast<const uint8_t*>(line.data()), line.size(), out);
        const uint8_t newline = '\n';
        enc.update(&newline, 1, out);
    }
};

static void aes_gcm_decrypt_file(const fs::path& in_path,
                                 const fs::path& out_tmp,
                                 const std::vector<uint8_t>& key32,
                                 const std::vector<uint8_t>& nonce12,
                                 const std::vector<uint8_t>& tag16,
                                 const std::optional<std::vector<uint8_t>>& aad,
                                 size_t chunk_size) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    auto fail = [&](const char* msg) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error(msg);
    };

    std::ifstream fin(in_path, std::ios::binary);
    if (!fin) fail("open enc failed");
    std::ofstream fout(out_tmp, std::ios::binary);
    if (!fout) fail("open out tmp failed");

    uint64_t total_bytes = 0;
    std::error_code ec;
    total_bytes = fs::file_size(in_path, ec);
    ProgressMeter progress;
    if (!ec && total_bytes > 0) {
        progress.start_meter("Decrypt " + in_path.filename().string(), total_bytes);
    }

    int ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    if (ok != 1) fail("DecryptInit failed");
    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    if (ok != 1) fail("SET_IVLEN failed");
    ok = EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                           (const unsigned char*)key32.data(),
                           (const unsigned char*)nonce12.data());
    if (ok != 1) fail("DecryptInit key/nonce failed");

    if (aad.has_value() && !aad->empty()) {
        int len = 0;
        ok = EVP_DecryptUpdate(ctx, nullptr, &len,
                              (const unsigned char*)aad->data(),
                              (int)aad->size());
        if (ok != 1) fail("AAD update failed");
    }

    std::vector<uint8_t> inbuf(chunk_size);
    std::vector<uint8_t> outbuf(chunk_size + 16);

    uint64_t done = 0;
    while (fin) {
        fin.read((char*)inbuf.data(), inbuf.size());
        std::streamsize got = fin.gcount();
        if (got <= 0) break;

        done += static_cast<uint64_t>(got);
        progress.update(done);

        int outlen = 0;
        ok = EVP_DecryptUpdate(ctx, outbuf.data(), &outlen, inbuf.data(), (int)got);
        if (ok != 1) fail("DecryptUpdate failed");
        if (outlen > 0) fout.write((char*)outbuf.data(), outlen);
    }

    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag16.data());
    if (ok != 1) fail("SET_TAG failed");

    {
        int outlen = 0;
        ok = EVP_DecryptFinal_ex(ctx, outbuf.data(), &outlen);
        if (ok != 1) fail("AES-GCM decrypt failed (tag mismatch or EVP error)");
        if (outlen > 0) fout.write((char*)outbuf.data(), outlen);
    }

    EVP_CIPHER_CTX_free(ctx);
    progress.finish(done);
}

static void aes_gcm_encrypt_file(const fs::path& in_path,
                                 const fs::path& out_path,
                                 const std::vector<uint8_t>& key32,
                                 const std::vector<uint8_t>& nonce12,
                                 std::vector<uint8_t>& out_tag16,
                                 const std::optional<std::vector<uint8_t>>& aad,
                                 size_t chunk_size,
                                 uint64_t* out_plain_bytes = nullptr,
                                 uint64_t* out_cipher_bytes = nullptr) {
    AesGcmEnc enc;
    std::ifstream fin(in_path, std::ios::binary);
    if (!fin) throw std::runtime_error("open in failed");
    std::ofstream fout(out_path, std::ios::binary);
    if (!fout) throw std::runtime_error("open out failed");

    enc.init(key32, nonce12, aad);
    std::vector<uint8_t> inbuf(std::max<size_t>(1, chunk_size));
    uint64_t done = 0;
    std::error_code ec;
    uint64_t total = fs::file_size(in_path, ec);
    ProgressMeter progress;
    if (!ec && total > 0) {
        progress.start_meter("Encrypt " + in_path.filename().string(), total);
    }
    while (fin) {
        fin.read((char*)inbuf.data(), (std::streamsize)inbuf.size());
        std::streamsize got = fin.gcount();
        if (got <= 0) break;
        enc.update(inbuf.data(), (size_t)got, fout);
        done += static_cast<uint64_t>(got);
        progress.update(done);
    }
    enc.finalize(fout);
    progress.finish(done);
    fout.flush();

    out_tag16 = enc.tag;
    if (out_plain_bytes) *out_plain_bytes = enc.plain_bytes;
    if (out_cipher_bytes) *out_cipher_bytes = enc.cipher_bytes;
}

struct Chunk {
    std::vector<uint8_t> data;
};

class ChunkQueue {
public:
    explicit ChunkQueue(size_t max_chunks) : max_chunks_(max_chunks) {}

    void push(std::vector<uint8_t>&& v) {
        std::unique_lock<std::mutex> lk(m_);
        cv_.wait(lk, [&](){ return closed_ || q_.size() < max_chunks_; });
        if (closed_) return;
        q_.push(Chunk{std::move(v)});
        cv_.notify_all();
    }

    bool pop(Chunk& out) {
        std::unique_lock<std::mutex> lk(m_);
        cv_.wait(lk, [&](){ return closed_ || !q_.empty(); });
        if (!q_.empty()) {
            out = std::move(q_.front());
            q_.pop();
            cv_.notify_all();
            return true;
        }
        return false;
    }

    void close() {
        std::lock_guard<std::mutex> lk(m_);
        closed_ = true;
        cv_.notify_all();
    }

private:
    std::mutex m_;
    std::condition_variable cv_;
    std::queue<Chunk> q_;
    size_t max_chunks_;
    bool closed_ = false;
};

struct SinkCtx {
    ChunkQueue* queue = nullptr;
    std::atomic<bool>* stop_flag = nullptr;
};

static GstFlowReturn on_new_sample(GstAppSink* sink, gpointer user_data) {
    auto* ctx = reinterpret_cast<SinkCtx*>(user_data);
    if (!ctx || !ctx->queue) return GST_FLOW_ERROR;
    if (ctx->stop_flag && ctx->stop_flag->load()) return GST_FLOW_EOS;

    GstSample* sample = gst_app_sink_pull_sample(sink);
    if (!sample) return GST_FLOW_OK;

    GstBuffer* buffer = gst_sample_get_buffer(sample);
    if (!buffer) { gst_sample_unref(sample); return GST_FLOW_OK; }

    GstMapInfo map;
    if (gst_buffer_map(buffer, &map, GST_MAP_READ)) {
        std::vector<uint8_t> v(map.data, map.data + map.size);
        ctx->queue->push(std::move(v));
        gst_buffer_unmap(buffer, &map);
    }

    gst_sample_unref(sample);
    return GST_FLOW_OK;
}

static bool has_gobj_prop(GObject* obj, const char* prop) {
    if (!obj || !prop) return false;
    return g_object_class_find_property(G_OBJECT_GET_CLASS(obj), prop) != nullptr;
}

static void set_prop_if_exists(GObject* obj, const char* prop, int value) {
    if (has_gobj_prop(obj, prop)) {
        g_object_set(obj, prop, value, NULL);
    }
}

static void set_prop_if_exists_bool(GObject* obj, const char* prop, bool value) {
    if (has_gobj_prop(obj, prop)) {
        g_object_set(obj, prop, value ? TRUE : FALSE, NULL);
    }
}

static void set_prop_if_exists(GObject* obj, const char* prop, const char* value) {
    if (has_gobj_prop(obj, prop)) {
        g_object_set(obj, prop, value, NULL);
    }
}

static bool write_all_fd(int fd, const uint8_t* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t written = write(fd, data + off, len - off);
        if (written < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        off += static_cast<size_t>(written);
    }
    return true;
}

static GstElement* build_appsrc_pipeline(uint32_t width,
                                         uint32_t height,
                                         uint32_t fps_num,
                                         uint32_t fps_den,
                                         SinkCtx* sink_ctx,
                                         GstElement** out_appsrc,
                                         GstElement** out_appsink,
                                         bool force_rgb) {
    auto make_encoder = [force_rgb]() -> GstElement* {
        if (force_rgb) {
            GstElement* enc = gst_element_factory_make("avenc_ffv1", "enc");
            if (enc) return enc;
            return gst_element_factory_make("ffv1enc", "enc");
        }
        GstElement* enc = gst_element_factory_make("ffv1enc", "enc");
        if (enc) return enc;
        return gst_element_factory_make("avenc_ffv1", "enc");
    };
    GstElement* pipeline = gst_pipeline_new("appsrc-pipeline");
    GstElement* appsrc = gst_element_factory_make("appsrc", "src");
    GstElement* queue = gst_element_factory_make("queue", "q");
    GstElement* convert = gst_element_factory_make("videoconvert", "conv");
    GstElement* capsfilter = nullptr;
    if (force_rgb) {
        capsfilter = gst_element_factory_make("capsfilter", "force_rgb");
    }
    GstElement* enc = make_encoder();
    GstElement* mux = gst_element_factory_make("matroskamux", "mux");
    GstElement* sink = gst_element_factory_make("appsink", "sink");

    if (!pipeline || !appsrc || !queue || !convert || !mux || !sink) {
        throw std::runtime_error("Failed to create gstreamer elements. Check plugins installed.");
    }
    if (force_rgb && !capsfilter) {
        throw std::runtime_error("Failed to create capsfilter for RGB");
    }

    if (!enc) {
        throw std::runtime_error("FFV1 encoder not available (ffv1enc/avenc_ffv1)");
    }

    GstCaps* caps = gst_caps_new_simple(
        "video/x-raw",
        "format", G_TYPE_STRING, "RGB",
        "width", G_TYPE_INT, (int)width,
        "height", G_TYPE_INT, (int)height,
        "framerate", GST_TYPE_FRACTION, (int)fps_num, (int)fps_den,
        NULL);

    g_object_set(G_OBJECT(appsrc),
                 "caps", caps,
                 "format", GST_FORMAT_TIME,
                 "is-live", TRUE,
                 "block", TRUE,
                 NULL);
    gst_caps_unref(caps);

    if (force_rgb) {
        GstCaps* force_caps = gst_caps_new_simple(
            "video/x-raw",
            "format", G_TYPE_STRING, "RGB",
            NULL);
        g_object_set(G_OBJECT(capsfilter), "caps", force_caps, NULL);
        gst_caps_unref(force_caps);
    }

    set_prop_if_exists(G_OBJECT(enc), "level", 3);

    set_prop_if_exists_bool(G_OBJECT(mux), "streamable", true);

    g_object_set(G_OBJECT(sink),
                 "emit-signals", TRUE,
                 "sync", FALSE,
                 "max-buffers", 200,
                 "drop", FALSE,
                 NULL);

    g_signal_connect(sink, "new-sample", G_CALLBACK(on_new_sample), sink_ctx);

    if (force_rgb) {
        gst_bin_add_many(GST_BIN(pipeline), appsrc, queue, convert, capsfilter, enc, mux, sink, NULL);
        if (!gst_element_link_many(appsrc, queue, convert, capsfilter, enc, mux, sink, NULL)) {
            throw std::runtime_error("Failed to link appsrc pipeline");
        }
    } else {
        gst_bin_add_many(GST_BIN(pipeline), appsrc, queue, convert, enc, mux, sink, NULL);
        if (!gst_element_link_many(appsrc, queue, convert, enc, mux, sink, NULL)) {
            throw std::runtime_error("Failed to link appsrc pipeline");
        }
    }

    if (out_appsrc) *out_appsrc = appsrc;
    if (out_appsink) *out_appsink = sink;
    return pipeline;
}

static GstElement* build_appsrc_pipeline_mp4(uint32_t width,
                                             uint32_t height,
                                             uint32_t fps_num,
                                             uint32_t fps_den,
                                             SinkCtx* sink_ctx,
                                             GstElement** out_appsrc,
                                             GstElement** out_appsink) {
    auto make_encoder = []() -> GstElement* {
        GstElement* enc = gst_element_factory_make("x264enc", "enc");
        if (enc) return enc;
        enc = gst_element_factory_make("avenc_h264", "enc");
        if (enc) return enc;
        return gst_element_factory_make("openh264enc", "enc");
    };
    auto make_mux = []() -> GstElement* {
        GstElement* mux = gst_element_factory_make("qtmux", "mux");
        if (mux) return mux;
        return gst_element_factory_make("mp4mux", "mux");
    };
    GstElement* pipeline = gst_pipeline_new("appsrc-pipeline-mp4");
    GstElement* appsrc = gst_element_factory_make("appsrc", "src");
    GstElement* queue = gst_element_factory_make("queue", "q");
    GstElement* convert = gst_element_factory_make("videoconvert", "conv");
    GstElement* enc = make_encoder();
    GstElement* parse = gst_element_factory_make("h264parse", "parse");
    GstElement* mux = make_mux();
    GstElement* sink = gst_element_factory_make("appsink", "sink");

    if (!pipeline || !appsrc || !queue || !convert || !parse || !mux || !sink) {
        throw std::runtime_error("Failed to create gstreamer elements. Check plugins installed.");
    }
    if (!enc) {
        throw std::runtime_error("H264 encoder not available (x264enc/avenc_h264/openh264enc)");
    }

    GstCaps* caps = gst_caps_new_simple(
        "video/x-raw",
        "format", G_TYPE_STRING, "RGB",
        "width", G_TYPE_INT, (int)width,
        "height", G_TYPE_INT, (int)height,
        "framerate", GST_TYPE_FRACTION, (int)fps_num, (int)fps_den,
        NULL);

    g_object_set(G_OBJECT(appsrc),
                 "caps", caps,
                 "format", GST_FORMAT_TIME,
                 "is-live", TRUE,
                 "block", TRUE,
                 NULL);
    gst_caps_unref(caps);

    set_prop_if_exists(G_OBJECT(enc), "tune", "zerolatency");
    set_prop_if_exists(G_OBJECT(enc), "speed-preset", 1);
    set_prop_if_exists(G_OBJECT(enc), "key-int-max", (int)fps_num);
    set_prop_if_exists(G_OBJECT(enc), "bitrate", 2000);
    set_prop_if_exists_bool(G_OBJECT(mux), "faststart", true);

    g_object_set(G_OBJECT(sink),
                 "emit-signals", TRUE,
                 "sync", FALSE,
                 "max-buffers", 200,
                 "drop", FALSE,
                 NULL);

    g_signal_connect(sink, "new-sample", G_CALLBACK(on_new_sample), sink_ctx);

    gst_bin_add_many(GST_BIN(pipeline), appsrc, queue, convert, enc, parse, mux, sink, NULL);
    if (!gst_element_link_many(appsrc, queue, convert, enc, parse, mux, sink, NULL)) {
        throw std::runtime_error("Failed to link appsrc pipeline");
    }

    if (out_appsrc) *out_appsrc = appsrc;
    if (out_appsink) *out_appsink = sink;
    return pipeline;
}

struct EncPipeline {
    GstElement* pipeline = nullptr;
    GstElement* appsrc = nullptr;
    ChunkQueue queue{400};
    SinkCtx sink_ctx{};
    std::atomic<bool> stop{false};
    std::atomic<uint64_t> encrypt_ns{0};
    std::thread writer;
    std::ofstream fout;
    AesGcmEnc enc;
    bool started = false;
    bool use_ffmpeg = false;
    uint32_t ffmpeg_width = 0;
    uint32_t ffmpeg_height = 0;
    uint32_t ffmpeg_fps_num = 30;
    uint32_t ffmpeg_fps_den = 1;
    int ffmpeg_in = -1;
    int ffmpeg_out = -1;
    pid_t ffmpeg_pid = -1;
    std::thread ffmpeg_reader;
    std::exception_ptr ffmpeg_reader_error;

    void start(const fs::path& enc_path,
               const std::vector<uint8_t>& key,
               const std::vector<uint8_t>& nonce,
               const std::optional<std::vector<uint8_t>>& aad) {
        fout.open(enc_path, std::ios::binary);
        if (!fout) throw std::runtime_error("Failed to open enc output");
        enc.init(key, nonce, aad);

        if (use_ffmpeg) {
            if (ffmpeg_width == 0 || ffmpeg_height == 0) {
                throw std::runtime_error("ffmpeg pipeline missing width/height");
            }
            if (ffmpeg_fps_num == 0 || ffmpeg_fps_den == 0) {
                throw std::runtime_error("ffmpeg pipeline missing fps");
            }
            int in_pipe[2];
            int out_pipe[2];
            if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0) {
                throw std::runtime_error("pipe() failed for ffmpeg");
            }
            pid_t pid = fork();
            if (pid < 0) {
                close(in_pipe[0]);
                close(in_pipe[1]);
                close(out_pipe[0]);
                close(out_pipe[1]);
                throw std::runtime_error("fork() failed for ffmpeg");
            }
            if (pid == 0) {
                dup2(in_pipe[0], STDIN_FILENO);
                dup2(out_pipe[1], STDOUT_FILENO);
                close(in_pipe[0]);
                close(in_pipe[1]);
                close(out_pipe[0]);
                close(out_pipe[1]);

                std::string size = std::to_string(ffmpeg_width) + "x" + std::to_string(ffmpeg_height);
                std::string fps = std::to_string(ffmpeg_fps_num) + "/" + std::to_string(ffmpeg_fps_den);
                std::vector<std::string> cmd = {
                    "ffmpeg", "-v", "error",
                    "-f", "rawvideo",
                    "-pix_fmt", "rgb24",
                    "-s", size,
                    "-framerate", fps,
                    "-i", "-",
                    "-an",
                    "-c:v", "ffv1",
                    "-level", "3",
                    "-g", "1",
                    "-pix_fmt", "rgb24",
                    "-f", "matroska",
                    "-"
                };
                std::vector<char*> argv;
                argv.reserve(cmd.size() + 1);
                for (auto& s : cmd) argv.push_back(const_cast<char*>(s.c_str()));
                argv.push_back(nullptr);
                execvp(argv[0], argv.data());
                _exit(127);
            }

            close(in_pipe[0]);
            close(out_pipe[1]);
            ffmpeg_in = in_pipe[1];
            ffmpeg_out = out_pipe[0];
            ffmpeg_pid = pid;

            ffmpeg_reader_error = nullptr;
            ffmpeg_reader = std::thread([this]() {
                try {
                    std::vector<uint8_t> buf(256 * 1024);
                    while (true) {
                        ssize_t r = read(ffmpeg_out, buf.data(), buf.size());
                        if (r == 0) break;
                        if (r < 0) {
                            if (errno == EINTR) continue;
                            throw std::runtime_error("ffmpeg pipe read failed");
                        }
                        auto t0 = std::chrono::steady_clock::now();
                        enc.update(buf.data(), static_cast<size_t>(r), fout);
                        auto t1 = std::chrono::steady_clock::now();
                        auto delta = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
                        encrypt_ns.fetch_add(static_cast<uint64_t>(delta), std::memory_order_relaxed);
                    }
                } catch (...) {
                    ffmpeg_reader_error = std::current_exception();
                }
                if (ffmpeg_out >= 0) {
                    close(ffmpeg_out);
                    ffmpeg_out = -1;
                }
            });
            started = true;
            return;
        }

        sink_ctx.queue = &queue;
        sink_ctx.stop_flag = &stop;

        writer = std::thread([&](){
            try {
                Chunk c;
                while (queue.pop(c)) {
                    if (!c.data.empty()) {
                        auto start = std::chrono::steady_clock::now();
                        enc.update(c.data.data(), c.data.size(), fout);
                        auto end = std::chrono::steady_clock::now();
                        auto delta = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
                        encrypt_ns.fetch_add(static_cast<uint64_t>(delta), std::memory_order_relaxed);
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "[!] writer error: " << e.what() << "\n";
                stop.store(true);
            }
        });
        started = true;
    }

    void push_frame(const std::vector<uint8_t>& rgb, uint64_t pts_ns, uint64_t dur_ns) {
        if (use_ffmpeg) {
            if (ffmpeg_in < 0) return;
            if (!write_all_fd(ffmpeg_in, rgb.data(), rgb.size())) {
                throw std::runtime_error("ffmpeg stdin write failed");
            }
            (void)pts_ns;
            (void)dur_ns;
            return;
        }
        if (!pipeline || !appsrc) return;
        GstBuffer* buffer = gst_buffer_new_allocate(NULL, rgb.size(), NULL);
        gst_buffer_fill(buffer, 0, rgb.data(), rgb.size());
        GST_BUFFER_PTS(buffer) = pts_ns;
        GST_BUFFER_DURATION(buffer) = dur_ns;
        gst_app_src_push_buffer(GST_APP_SRC(appsrc), buffer);
    }

    void begin_pipeline(uint32_t width,
                        uint32_t height,
                        uint32_t fps_num,
                        uint32_t fps_den,
                        bool lossless) {
        if (lossless) {
            use_ffmpeg = true;
            ffmpeg_width = width;
            ffmpeg_height = height;
            ffmpeg_fps_num = fps_num;
            ffmpeg_fps_den = fps_den;
            return;
        } else {
            pipeline = build_appsrc_pipeline_mp4(width, height, fps_num, fps_den, &sink_ctx, &appsrc, nullptr);
        }
        GstBus* bus = gst_element_get_bus(pipeline);
        gst_element_set_state(pipeline, GST_STATE_PLAYING);
        if (bus) gst_object_unref(bus);
    }

    void end_pipeline() {
        if (use_ffmpeg) {
            if (ffmpeg_in >= 0) {
                close(ffmpeg_in);
                ffmpeg_in = -1;
            }
            int status = 0;
            bool waited = false;
            if (ffmpeg_pid > 0) {
                pid_t w = waitpid(ffmpeg_pid, &status, 0);
                if (w < 0) {
                    if (errno != ECHILD) {
                        throw std::runtime_error("waitpid failed for ffmpeg");
                    }
                    std::cerr << "[!] waitpid failed for ffmpeg (ECHILD)" << "\n";
                } else {
                    waited = true;
                }
            }
            if (ffmpeg_reader.joinable()) {
                ffmpeg_reader.join();
            }
            if (ffmpeg_reader_error) {
                std::rethrow_exception(ffmpeg_reader_error);
            }
            auto exit_code = [](int rc) {
                if (rc == -1) return -1;
                if (WIFEXITED(rc)) return WEXITSTATUS(rc);
                if (WIFSIGNALED(rc)) return 128 + WTERMSIG(rc);
                return -1;
            };
            if (waited) {
                int code = exit_code(status);
                if (code != 0) {
                    throw std::runtime_error("ffmpeg encoder failed (code=" + std::to_string(code) + ")");
                }
            }

            enc.finalize(fout);
            fout.close();
            use_ffmpeg = false;
            ffmpeg_pid = -1;
            started = false;
            return;
        }
        if (!pipeline || !appsrc) return;
        gst_app_src_end_of_stream(GST_APP_SRC(appsrc));

        GstBus* bus = gst_element_get_bus(pipeline);
        GstMessage* msg = gst_bus_timed_pop_filtered(
            bus,
            GST_CLOCK_TIME_NONE,
            (GstMessageType)(GST_MESSAGE_ERROR | GST_MESSAGE_EOS)
        );
        if (msg) {
            gst_message_unref(msg);
        }

        queue.close();
        if (writer.joinable()) writer.join();
        stop.store(true);

        enc.finalize(fout);
        fout.close();

        gst_element_set_state(pipeline, GST_STATE_NULL);
        if (bus) gst_object_unref(bus);
        if (pipeline) gst_object_unref(pipeline);
        pipeline = nullptr;
        appsrc = nullptr;
        started = false;
    }
};

struct PlainPipeline {
    GstElement* pipeline = nullptr;
    GstElement* appsrc = nullptr;
    ChunkQueue queue{400};
    SinkCtx sink_ctx{};
    std::atomic<bool> stop{false};
    std::atomic<uint64_t> write_ns{0};
    std::thread writer;
    std::ofstream fout;
    uint64_t plain_bytes = 0;
    bool started = false;

    void start(const fs::path& out_path) {
        fout.open(out_path, std::ios::binary);
        if (!fout) throw std::runtime_error("Failed to open output file");

        sink_ctx.queue = &queue;
        sink_ctx.stop_flag = &stop;

        writer = std::thread([&](){
            try {
                Chunk c;
                while (queue.pop(c)) {
                    if (!c.data.empty()) {
                        auto start = std::chrono::steady_clock::now();
                        fout.write((const char*)c.data.data(), c.data.size());
                        auto end = std::chrono::steady_clock::now();
                        auto delta = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
                        write_ns.fetch_add(static_cast<uint64_t>(delta), std::memory_order_relaxed);
                        plain_bytes += c.data.size();
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "[!] writer error: " << e.what() << "\n";
                stop.store(true);
            }
        });
        started = true;
    }

    void push_frame(const std::vector<uint8_t>& rgb, uint64_t pts_ns, uint64_t dur_ns) {
        if (!pipeline || !appsrc) return;
        GstBuffer* buffer = gst_buffer_new_allocate(NULL, rgb.size(), NULL);
        gst_buffer_fill(buffer, 0, rgb.data(), rgb.size());
        GST_BUFFER_PTS(buffer) = pts_ns;
        GST_BUFFER_DURATION(buffer) = dur_ns;
        gst_app_src_push_buffer(GST_APP_SRC(appsrc), buffer);
    }

    void begin_pipeline(uint32_t width, uint32_t height, uint32_t fps_num, uint32_t fps_den) {
        pipeline = build_appsrc_pipeline(width, height, fps_num, fps_den,
                                         &sink_ctx, &appsrc, nullptr, false);
        GstBus* bus = gst_element_get_bus(pipeline);
        gst_element_set_state(pipeline, GST_STATE_PLAYING);
        if (bus) gst_object_unref(bus);
    }

    void end_pipeline() {
        if (!pipeline || !appsrc) return;
        gst_app_src_end_of_stream(GST_APP_SRC(appsrc));

        GstBus* bus = gst_element_get_bus(pipeline);
        GstMessage* msg = gst_bus_timed_pop_filtered(
            bus,
            GST_CLOCK_TIME_NONE,
            (GstMessageType)(GST_MESSAGE_ERROR | GST_MESSAGE_EOS)
        );
        if (msg) {
            gst_message_unref(msg);
        }

        queue.close();
        if (writer.joinable()) writer.join();
        stop.store(true);

        fout.close();

        gst_element_set_state(pipeline, GST_STATE_NULL);
        if (bus) gst_object_unref(bus);
        if (pipeline) gst_object_unref(pipeline);
        pipeline = nullptr;
        appsrc = nullptr;
        started = false;
    }
};

struct DayKeyState {
    std::vector<uint8_t> key;
    fs::path prefix;
    std::optional<fs::path> policy_file;
    std::optional<fs::path> signer_pub_copy;
};

struct HotSegmentWriter {
    std::string segment_name;
    fs::path hot_dir;
    fs::path video_path;
    fs::path meta_path;

    uint64_t start_ns = 0;
    uint64_t last_ts_ns = 0;
    uint64_t segment_len_ns = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t fps_num = 30;
    uint32_t fps_den = 1;

    secure_save::SecureSaveConfig::RoiMaskConfig roi_cfg;
    std::vector<uint8_t> roi_video_salt;
    std::unique_ptr<secure_save::RoiMasker> roi_masker;
    std::unique_ptr<secure_save::IRoiMetadataSink> roi_metadata;
    fs::path roi_meta_path;
    fs::path roi_meta_enc_path;
    std::vector<uint8_t> roi_meta_nonce;
    std::vector<uint8_t> roi_meta_tag;
    uint64_t roi_meta_plaintext_bytes = 0;
    uint64_t roi_meta_ciphertext_bytes = 0;
    size_t roi_frames_total = 0;
    size_t roi_frames_masked = 0;
    size_t roi_boxes_total = 0;

    PlainPipeline full;
    std::chrono::steady_clock::time_point start_wall;
    ProgressMeter enc_progress;

    void init(const fs::path& hot_root,
              const std::string& camera_id,
              uint32_t w,
              uint32_t h,
              uint32_t fpsn,
              uint32_t fpsd,
              uint64_t start_ts_ns,
              uint64_t seg_len_ns,
              const secure_save::SecureSaveConfig::RoiMaskConfig& roi_cfg_in) {
        start_ns = start_ts_ns;
        last_ts_ns = start_ts_ns;
        segment_len_ns = seg_len_ns;
        width = w;
        height = h;
        fps_num = fpsn;
        fps_den = fpsd;
        roi_cfg = roi_cfg_in;

        uint64_t start_ms = epoch_ns_to_ms_floor(start_ts_ns);
        fs::path base = hot_root / std::to_string(start_ms);
        fs::path base_unique = unique_path(base);
        segment_name = base_unique.filename().string();
        hot_dir = hot_root;
        fs::create_directories(hot_dir);

        video_path = base_unique; video_path += ".mp4";
        meta_path = base_unique; meta_path += ".meta.json";

        if (roi_cfg.enabled) {
            secure_save::RoiMaskerOptions options;
            options.strict_stride_check = roi_cfg.strict_stride_check;
            roi_masker = std::make_unique<secure_save::RoiMasker>(options);
            auto roi_key = rand_key_32();
            roi_masker->BeginSegment(roi_key.data(), roi_key.size());
            roi_video_salt = roi_masker->GetVideoSalt();
            if (roi_cfg.write_sidecar) {
                roi_meta_path = base_unique; roi_meta_path += ".mask.jsonl";
                roi_metadata = std::make_unique<secure_save::RoiMetadataJsonlWriter>(roi_meta_path);
                roi_metadata->OnSegmentBegin(segment_name, roi_video_salt, width, height, fps_num, fps_den);
            }
            roi_frames_total = 0;
            roi_frames_masked = 0;
            roi_boxes_total = 0;
        }

        full.begin_pipeline(width, height, fps_num, fps_den);
        full.start(video_path);
        start_wall = std::chrono::steady_clock::now();
        if (segment_len_ns > 0) {
            enc_progress.start_meter("Hot segment " + segment_name, segment_len_ns);
        }
    }

    void push(const std::vector<uint8_t>& frame,
              uint64_t pts_ns,
              uint64_t dur_ns,
              uint64_t epoch_ns) {
        last_ts_ns = epoch_ns;
        full.push_frame(frame, pts_ns, dur_ns);
        if (segment_len_ns > 0 && epoch_ns >= start_ns) {
            uint64_t done = epoch_ns - start_ns;
            if (done > segment_len_ns) done = segment_len_ns;
            enc_progress.update(done);
        }
    }

    void finish(const std::string& camera_id) {
        if (roi_metadata) {
            roi_metadata->OnSegmentEnd();
        }
        full.end_pipeline();
        if (segment_len_ns > 0) {
            enc_progress.finish(segment_len_ns);
        }

        auto encode_end = std::chrono::steady_clock::now();
        uint64_t encode_ns = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(encode_end - start_wall).count());

        ordered_json meta = ordered_json::object();
        meta["version"] = 9;
        meta["_comment"] = "Hot segment metadata grouped by purpose.";

        ordered_json identity = ordered_json::object();
        identity["_comment"] = "Who/where this segment belongs to.";
        identity["created_at_name"] = segment_name;
        identity["camera_id"] = camera_id;
        identity["view"] = "full";
        identity["bundle_dir"] = hot_dir.filename().string();
        identity["source_filename"] = safe_name(camera_id) + "_" + segment_name + "_full.mp4";
        meta["identity"] = std::move(identity);

        ordered_json segment = ordered_json::object();
        segment["_comment"] = "Segment time range in epoch nanoseconds.";
        segment["start_ns"] = start_ns;
        segment["end_ns"] = last_ts_ns;
        meta["segment"] = std::move(segment);

        ordered_json video = ordered_json::object();
        video["_comment"] = "Video shape and timing.";
        video["file"] = video_path.filename().string();
        video["width"] = width;
        video["height"] = height;
        video["fps_num"] = fps_num;
        video["fps_den"] = fps_den;
        meta["video"] = std::move(video);

        ordered_json payload = ordered_json::object();
        payload["_comment"] = "Hot payload is plain (not encrypted).";
        payload["encrypted"] = false;
        payload["cipher"] = "none";
        payload["plaintext_bytes"] = full.plain_bytes;
        meta["payload"] = std::move(payload);

        ordered_json roi = ordered_json::object();
        roi["_comment"] = "ROI masking metadata. Unmask parameters are stored in sidecar header.";
        roi["enabled"] = roi_cfg.enabled;
        if (roi_cfg.enabled) {
            roi["missing_policy"] = roi_policy_name(roi_cfg.missing_roi_policy);
            roi["error_policy"] = roi_policy_name(roi_cfg.mask_error_policy);
            if (roi_cfg.write_sidecar && !roi_meta_path.empty()) {
                roi["sidecar"] = roi_meta_path.filename().string();
            }
        }
        meta["roi"] = std::move(roi);

        { std::ofstream ofs(meta_path); ofs << meta.dump(2); }

        auto to_sec = [](uint64_t ns) { return static_cast<double>(ns) / 1e9; };
        std::cerr << "[*] Hot segment timings (s): recv+encode=" << to_sec(encode_ns) << "\n";
        std::cerr << "[*] Hot segment done. File: " << video_path << "\n";
        if (roi_cfg.enabled) {
            std::cerr << "[*] Hot segment ROI: frames=" << roi_frames_total
                      << " masked_frames=" << roi_frames_masked
                      << " boxes=" << roi_boxes_total << "\n";
        }
        if (roi_masker) {
            roi_masker->Clear();
        }
    }
};

struct ColdSegmentWriter {
    std::string segment_name;
    std::string created_at;
    fs::path segment_dir;
    fs::path primary_ctx;
    fs::path enc_full_path;
    fs::path meta_full_path;
    fs::path day_key_prefix;

    uint64_t start_ns = 0;
    uint64_t last_ts_ns = 0;
    uint64_t segment_len_ns = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t fps_num = 30;
    uint32_t fps_den = 1;

    std::vector<uint8_t> key_full;
    std::vector<uint8_t> nonce_full;
    std::vector<uint8_t> aad;

    std::vector<uint8_t> day_key;
    std::optional<fs::path> day_policy_file;
    std::optional<fs::path> day_signer_pub;

    secure_save::SecureSaveConfig::RoiMaskConfig roi_cfg;
    secure_save::SecureSaveConfig::TrackConfig track_cfg;
    std::vector<uint8_t> roi_video_salt;
    std::unique_ptr<secure_save::RoiMasker> roi_masker;
    std::unique_ptr<secure_save::IRoiMetadataSink> roi_metadata;
    fs::path roi_meta_path;
    fs::path roi_meta_enc_path;
    std::vector<uint8_t> roi_meta_nonce;
    std::vector<uint8_t> roi_meta_tag;
    uint64_t roi_meta_plaintext_bytes = 0;
    uint64_t roi_meta_ciphertext_bytes = 0;
    size_t roi_frames_total = 0;
    size_t roi_frames_masked = 0;
    size_t roi_boxes_total = 0;

    TrackJsonEncWriter track_writer;

    EncPipeline full;
    std::chrono::steady_clock::time_point start_wall;
    ProgressMeter enc_progress;

    void init(const fs::path& cold_root,
              const std::string& camera_id,
              uint32_t w,
              uint32_t h,
              uint32_t fpsn,
              uint32_t fpsd,
              uint64_t start_ts_ns,
              uint64_t seg_len_ns,
              const DayKeyState& day_key_state,
              const secure_save::SecureSaveConfig::RoiMaskConfig& roi_cfg_in,
              const secure_save::SecureSaveConfig::TrackConfig& track_cfg_in) {
        start_ns = start_ts_ns;
        last_ts_ns = start_ts_ns;
        segment_len_ns = seg_len_ns;
        width = w;
        height = h;
        fps_num = fpsn;
        fps_den = fpsd;
        day_key = day_key_state.key;
        day_key_prefix = day_key_state.prefix;
        day_policy_file = day_key_state.policy_file;
        day_signer_pub = day_key_state.signer_pub_copy;
        roi_cfg = roi_cfg_in;
        track_cfg = track_cfg_in;

        segment_dir = cold_day_dir_for_epoch(cold_root, start_ts_ns);
        fs::create_directories(segment_dir);
        primary_ctx = fs::absolute(cold_root) / "primary.ctx";

        uint64_t start_ms = epoch_ns_to_ms_floor(start_ts_ns);
        fs::path base = segment_dir / std::to_string(start_ms);
        fs::path base_unique = unique_path(base);
        segment_name = base_unique.filename().string();
        created_at = segment_name;

        enc_full_path = base_unique; enc_full_path += ".enc";
        meta_full_path = base_unique; meta_full_path += ".meta.json";
        key_full = tpm_get_random_32();
        nonce_full.assign(12, 0);
        if (RAND_bytes(nonce_full.data(), (int)nonce_full.size()) != 1) {
            throw std::runtime_error("RAND_bytes failed");
        }

        if (roi_cfg.enabled) {
            secure_save::RoiMaskerOptions options;
            options.strict_stride_check = roi_cfg.strict_stride_check;
            roi_masker = std::make_unique<secure_save::RoiMasker>(options);
            roi_masker->BeginSegment(key_full.data(), key_full.size());
            roi_video_salt = roi_masker->GetVideoSalt();
            roi_meta_enc_path.clear();
            roi_meta_nonce.clear();
            roi_meta_tag.clear();
            roi_meta_plaintext_bytes = 0;
            roi_meta_ciphertext_bytes = 0;
            if (roi_cfg.write_sidecar) {
                roi_meta_path = base_unique; roi_meta_path += ".mask.jsonl";
                roi_metadata = std::make_unique<secure_save::RoiMetadataJsonlWriter>(roi_meta_path);
                roi_metadata->OnSegmentBegin(segment_name, roi_video_salt, width, height, fps_num, fps_den);
            }
            roi_frames_total = 0;
            roi_frames_masked = 0;
            roi_boxes_total = 0;
        }

        std::string aad_s = "camera=" + camera_id + ";created_at=" + created_at;
        aad.assign(aad_s.begin(), aad_s.end());
        auto aad_opt = std::optional<std::vector<uint8_t>>(aad);

        bool lossless = roi_cfg.enabled && roi_cfg.write_sidecar;
        full.begin_pipeline(width, height, fps_num, fps_den, lossless);
        full.start(enc_full_path, key_full, nonce_full, aad_opt);

        start_wall = std::chrono::steady_clock::now();
        if (segment_len_ns > 0) {
            enc_progress.start_meter("Cold segment " + segment_name, segment_len_ns);
        }
    }

    void push(const std::vector<uint8_t>& frame,
              uint64_t pts_ns,
              uint64_t dur_ns,
              uint64_t epoch_ns) {
        last_ts_ns = epoch_ns;
        full.push_frame(frame, pts_ns, dur_ns);
        if (segment_len_ns > 0 && epoch_ns >= start_ns) {
            uint64_t done = epoch_ns - start_ns;
            if (done > segment_len_ns) done = segment_len_ns;
            enc_progress.update(done);
        }
    }

    void finish(const std::string& camera_id,
                const secure_save::BundleConfig& bcfg) {
        if (roi_metadata) {
            roi_metadata->OnSegmentEnd();
        }
        full.end_pipeline();
        if (segment_len_ns > 0) {
            enc_progress.finish(segment_len_ns);
        }

        auto encode_end = std::chrono::steady_clock::now();
        uint64_t encode_ns = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(encode_end - start_wall).count());
        uint64_t aes_ns = full.encrypt_ns.load(std::memory_order_relaxed);

        if (day_key.size() != 32) {
            throw std::runtime_error("day key length invalid");
        }
        std::vector<uint8_t> wrap_nonce(12, 0);
        if (RAND_bytes(wrap_nonce.data(), (int)wrap_nonce.size()) != 1) {
            throw std::runtime_error("RAND_bytes failed");
        }
        std::vector<uint8_t> wrap_tag;
        std::vector<uint8_t> wrapped_key = aes_gcm_encrypt_buf(
            day_key, wrap_nonce, key_full, std::nullopt, wrap_tag);

        if (roi_cfg.enabled && roi_cfg.write_sidecar && !roi_meta_path.empty() && fs::exists(roi_meta_path)) {
            roi_meta_nonce.assign(12, 0);
            if (RAND_bytes(roi_meta_nonce.data(), (int)roi_meta_nonce.size()) != 1) {
                throw std::runtime_error("RAND_bytes failed for roi sidecar nonce");
            }
            roi_meta_enc_path = roi_meta_path.parent_path() / (roi_meta_path.stem().string() + ".enc");
            auto aad_opt = std::optional<std::vector<uint8_t>>(aad);
            aes_gcm_encrypt_file(roi_meta_path, roi_meta_enc_path, key_full, roi_meta_nonce, roi_meta_tag,
                                 aad_opt, bcfg.chunk_size, &roi_meta_plaintext_bytes, &roi_meta_ciphertext_bytes);
            std::error_code rm_ec;
            fs::remove(roi_meta_path, rm_ec);
            if (rm_ec) {
                throw std::runtime_error("Failed to remove plaintext roi sidecar: " + roi_meta_path.string());
            }
        }

        auto write_meta = [&](const fs::path& meta_path,
                              const std::string& view,
                              const fs::path& enc_path,
                              const std::vector<uint8_t>& nonce,
                              const std::vector<uint8_t>& tag,
                              uint64_t plain_bytes,
                              uint64_t cipher_bytes) {
            ordered_json meta = ordered_json::object();
            meta["version"] = 9;
            meta["_comment"] = "Cold encrypted segment metadata grouped by purpose.";

            ordered_json identity = ordered_json::object();
            identity["_comment"] = "Who/where this segment belongs to.";
            identity["created_at_name"] = created_at;
            identity["camera_id"] = camera_id;
            identity["view"] = view;
            identity["bundle_dir"] = segment_dir.filename().string();
            identity["source_filename"] = safe_name(camera_id) + "_" + created_at + "_" + view + ".mkv";
            meta["identity"] = std::move(identity);

            ordered_json segment = ordered_json::object();
            segment["_comment"] = "Segment time range in epoch nanoseconds.";
            segment["start_ns"] = start_ns;
            segment["end_ns"] = last_ts_ns;
            meta["segment"] = std::move(segment);

            ordered_json video = ordered_json::object();
            video["_comment"] = "Video shape and timing.";
            video["width"] = width;
            video["height"] = height;
            video["fps_num"] = fps_num;
            video["fps_den"] = fps_den;
            meta["video"] = std::move(video);

            ordered_json payload = ordered_json::object();
            payload["_comment"] = "Encrypted payload information.";
            payload["encrypted"] = true;
            payload["cipher"] = "AES-256-GCM";
            payload["enc_file"] = enc_path.filename().string();
            payload["chunk_size"] = bcfg.chunk_size;
            payload["plaintext_bytes"] = plain_bytes;
            payload["ciphertext_bytes"] = cipher_bytes;
            meta["payload"] = std::move(payload);

            ordered_json crypto = ordered_json::object();
            crypto["_comment"] = "Content and wrapped-key crypto material.";
            crypto["aad_b64"] = aad.empty() ? nullptr : b64e(aad);
            crypto["nonce_b64"] = b64e(nonce);
            crypto["tag_b64"] = b64e(tag);
            crypto["key_wrap_alg"] = "AES-256-GCM";
            crypto["wrapped_key_b64"] = b64e(wrapped_key);
            crypto["wrap_nonce_b64"] = b64e(wrap_nonce);
            crypto["wrap_tag_b64"] = b64e(wrap_tag);
            meta["crypto"] = std::move(crypto);

            ordered_json tpm = ordered_json::object();
            tpm["_comment"] = "TPM sealed-key artifacts.";
            tpm["day_key_prefix"] = day_key_prefix.string();
            tpm["day_sealed_pub"] = day_key_prefix.filename().string() + ".pub";
            tpm["day_sealed_priv"] = day_key_prefix.filename().string() + ".priv";
            tpm["primary_ctx"] = primary_ctx.string();
            meta["tpm"] = std::move(tpm);

            ordered_json policy = ordered_json::object();
            policy["_comment"] = "Policy-signed unseal settings.";
            bool policy_signed = day_policy_file.has_value() && day_signer_pub.has_value();
            policy["signed"] = policy_signed;
            if (policy_signed) {
                policy["day_policy_file"] = day_policy_file->filename().string();
                policy["day_policy_signer_pub"] = day_signer_pub->filename().string();
            }
            meta["policy"] = std::move(policy);

            ordered_json roi = ordered_json::object();
            roi["_comment"] = "ROI masking metadata. Unmask parameters are stored in sidecar header.";
            roi["enabled"] = roi_cfg.enabled;
            if (roi_cfg.enabled) {
                roi["missing_policy"] = roi_policy_name(roi_cfg.missing_roi_policy);
                roi["error_policy"] = roi_policy_name(roi_cfg.mask_error_policy);
                if (!roi_meta_enc_path.empty()) {
                    roi["enc_file"] = roi_meta_enc_path.filename().string();
                    roi["nonce_b64"] = b64e(roi_meta_nonce);
                    roi["tag_b64"] = b64e(roi_meta_tag);
                    roi["aad_b64"] = aad.empty() ? nullptr : b64e(aad);
                    roi["plaintext_bytes"] = roi_meta_plaintext_bytes;
                    roi["ciphertext_bytes"] = roi_meta_ciphertext_bytes;
                }
            }
            meta["roi"] = std::move(roi);

            if (track_cfg.enabled && track_writer.started) {
                ordered_json track = ordered_json::object();
                track["_comment"] = "Encrypted tracking jsonl metadata.";
                track["schema"] = "track-jsonl-v1";
                track["bbox_format"] = "x1y1x2y2";
                track["enc_file"] = track_writer.enc_path.filename().string();
                track["nonce_b64"] = b64e(track_writer.nonce_bytes());
                track["tag_b64"] = b64e(track_writer.tag_bytes());
                track["aad_b64"] = aad.empty() ? nullptr : b64e(aad);
                track["plaintext_bytes"] = track_writer.plain_bytes();
                track["ciphertext_bytes"] = track_writer.cipher_bytes();
                track["include_empty_frames"] = track_cfg.include_empty_frames;
                meta["track"] = std::move(track);
            }

            { std::ofstream ofs(meta_path); ofs << meta.dump(2); }
        };

        write_meta(meta_full_path, "full", enc_full_path,
                   nonce_full, full.enc.tag, full.enc.plain_bytes, full.enc.cipher_bytes);

        auto to_sec = [](uint64_t ns) { return static_cast<double>(ns) / 1e9; };
        std::cerr << "[*] Cold segment timings (s): recv+encode=" << to_sec(encode_ns)
                  << ", aes=" << to_sec(aes_ns) << "\n";
        std::cerr << "[*] Cold segment done. File: " << enc_full_path << "\n";
        if (roi_cfg.enabled) {
            std::cerr << "[*] Cold segment ROI: frames=" << roi_frames_total
                      << " masked_frames=" << roi_frames_masked
                      << " boxes=" << roi_boxes_total << "\n";
        }
        if (roi_masker) {
            roi_masker->Clear();
        }
    }
};

static const std::vector<uint8_t>* apply_roi_mask_for_segment(
    const secure_save::FramePacket& frame,
    uint64_t frame_index,
    const secure_save::SecureSaveConfig::RoiMaskConfig& roi_cfg,
    secure_save::RoiMasker* roi_masker,
    secure_save::IRoiMetadataSink* roi_metadata,
    std::vector<uint8_t>& masked_out,
    size_t* frames_total,
    size_t* frames_masked,
    size_t* boxes_total) {
    if (!roi_masker || !roi_cfg.enabled) {
        return &frame.rgb;
    }

    masked_out = frame.rgb;
    uint32_t stride = frame.width * 3;
    size_t required = static_cast<size_t>(frame.height) * stride;
    std::vector<secure_save::RoiBox> record_boxes;

    if (masked_out.size() < required) {
        auto policy = roi_cfg.mask_error_policy;
        if (policy == secure_save::SecureSaveConfig::RoiMaskConfig::FailPolicy::FailHard) {
            throw std::runtime_error("RGB frame size too small for ROI masking");
        }
        if (policy == secure_save::SecureSaveConfig::RoiMaskConfig::FailPolicy::FailClose) {
            fill_black(masked_out);
            record_boxes = {secure_save::RoiBox{0, 0, (int32_t)frame.width, (int32_t)frame.height, -1}};
        }
    } else {
        auto boxes = to_roi_boxes(frame.boxes);
        secure_save::RoiMaskerOptions options;
        options.strict_stride_check = roi_cfg.strict_stride_check;
        try {
            record_boxes = secure_save::RoiMasker::NormalizeBoxes(
                boxes, frame.width, frame.height, stride, options);

            if (record_boxes.empty()) {
                auto policy = roi_cfg.missing_roi_policy;
                if (policy == secure_save::SecureSaveConfig::RoiMaskConfig::FailPolicy::FailHard) {
                    throw std::runtime_error("Missing ROI boxes");
                }
                if (policy == secure_save::SecureSaveConfig::RoiMaskConfig::FailPolicy::FailClose) {
                    record_boxes = secure_save::RoiMasker::NormalizeBoxes(
                        {secure_save::RoiBox{0, 0, (int32_t)frame.width, (int32_t)frame.height, -1}},
                        frame.width, frame.height, stride, options);
                }
            }

            if (!record_boxes.empty()) {
                roi_masker->mask(
                    masked_out.data(), frame.width, frame.height, stride, frame_index, record_boxes);
            }
        } catch (const std::exception&) {
            auto policy = roi_cfg.mask_error_policy;
            if (policy == secure_save::SecureSaveConfig::RoiMaskConfig::FailPolicy::FailHard) {
                throw;
            }
            if (policy == secure_save::SecureSaveConfig::RoiMaskConfig::FailPolicy::FailClose) {
                fill_black(masked_out);
                record_boxes = {secure_save::RoiBox{0, 0, (int32_t)frame.width, (int32_t)frame.height, -1}};
            } else {
                record_boxes.clear();
            }
        }
    }

    if (roi_metadata) {
        roi_metadata->OnFrame(frame_index, record_boxes);
    }
    if (frames_total) {
        (*frames_total)++;
    }
    if (!record_boxes.empty()) {
        if (frames_masked) {
            (*frames_masked)++;
        }
        if (boxes_total) {
            (*boxes_total) += record_boxes.size();
        }
    }
    return &masked_out;
}

struct SegmentInfo {
    fs::path meta_path;
    uint64_t start_ns = 0;
    uint64_t end_ns = 0;
    std::string view;
};

static std::vector<SegmentInfo> find_segments(const fs::path& root,
                                              uint64_t start_ns,
                                              uint64_t end_ns,
                                              const std::string& view) {
    std::vector<SegmentInfo> out;
    if (!fs::exists(root)) return out;

    for (auto& dir : fs::directory_iterator(root)) {
        if (!dir.is_directory()) continue;
        for (auto& it : fs::recursive_directory_iterator(dir.path())) {
            if (!it.is_regular_file()) continue;
            if (it.path().extension() != ".json") continue;
            if (it.path().filename().string().find(".meta.json") == std::string::npos) continue;

            json meta;
            try { std::ifstream ifs(it.path()); ifs >> meta; } catch (...) { continue; }
            if (meta_has(meta, "payload", "encrypted", "encrypted")) {
                if (!meta_get<bool>(meta, "payload", "encrypted", "encrypted", false)) continue;
            }
            std::string cipher = meta_get<std::string>(meta, "payload", "cipher", "cipher", "");
            if (!cipher.empty() && cipher != "AES-256-GCM") continue;
            bool has_start = meta_has(meta, "segment", "start_ns", "segment_start_ns");
            bool has_end = meta_has(meta, "segment", "end_ns", "segment_end_ns");
            if (!has_start || !has_end) continue;
            std::string meta_view = meta_get<std::string>(meta, "identity", "view", "view", "");
            if (view != "both") {
                if (meta_view != view) {
                    if (!(meta_view == "full" && (view == "person" || view == "background"))) {
                        continue;
                    }
                }
            }

            uint64_t seg_start = meta_get<uint64_t>(meta, "segment", "start_ns", "segment_start_ns", 0ULL);
            uint64_t seg_end = meta_get<uint64_t>(meta, "segment", "end_ns", "segment_end_ns", 0ULL);
            if (seg_end < start_ns || seg_start > end_ns) continue;

            out.push_back({it.path(), seg_start, seg_end, meta_view});
        }
    }

    std::sort(out.begin(), out.end(), [](const SegmentInfo& a, const SegmentInfo& b){
        return a.start_ns < b.start_ns;
    });
    return out;
}

static fs::path decrypt_segment_to_tmp(const fs::path& meta_path,
                                       const secure_save::BundleConfig& cfg,
                                       const fs::path& tmp_dir,
                                       std::map<std::string, std::vector<uint8_t>>* day_key_cache,
                                       const std::function<std::vector<uint8_t>(const fs::path&,
                                                                              const fs::path&,
                                                                              const std::optional<fs::path>&,
                                                                              const std::optional<fs::path>&)>& unseal_cb,
                                       std::vector<uint8_t>* out_key) {
    json meta;
    { std::ifstream ifs(meta_path); ifs >> meta; }
    fs::path base_dir = meta_path.parent_path();

    fs::path enc_path = base_dir / meta_get<std::string>(meta, "payload", "enc_file", "enc_file", "");
    fs::path primary_ctx = meta_get<std::string>(meta, "tpm", "primary_ctx", "primary_ctx", "primary.ctx");
    if (!primary_ctx.is_absolute()) {
        primary_ctx = base_dir / primary_ctx;
    }
    bool wrapped_key = meta_has(meta, "crypto", "wrapped_key_b64", "wrapped_key_b64")
        && meta_has(meta, "crypto", "wrap_nonce_b64", "wrap_nonce_b64")
        && meta_has(meta, "crypto", "wrap_tag_b64", "wrap_tag_b64")
        && meta_has(meta, "tpm", "day_key_prefix", "day_key_prefix");

    auto nonce = b64d(meta_get<std::string>(meta, "crypto", "nonce_b64", "nonce_b64", ""));
    auto tag = b64d(meta_get<std::string>(meta, "crypto", "tag_b64", "tag_b64", ""));

    std::optional<std::vector<uint8_t>> aad;
    if (meta_has(meta, "crypto", "aad_b64", "aad_b64")) {
        aad = b64d(meta_get<std::string>(meta, "crypto", "aad_b64", "aad_b64", ""));
    }

    size_t chunk_size = (size_t)meta_get<uint64_t>(meta, "payload", "chunk_size", "chunk_size",
                                                   static_cast<uint64_t>(cfg.chunk_size));

    std::string source_filename = meta_get<std::string>(meta, "identity", "source_filename", "source_filename",
                                                        "segment.mp4");
    fs::create_directories(tmp_dir);
    fs::path base = tmp_dir / (source_filename + ".dec.mkv");
    fs::path tmp_out = unique_path(base);

    bool policy_signed = meta_get<bool>(meta, "policy", "signed", "policy_signed", false);

    if (!unseal_cb) {
        throw std::runtime_error("unseal callback not set");
    }

    std::vector<uint8_t> key;
    auto t_unseal_start = std::chrono::steady_clock::now();
    auto t_unseal_end = t_unseal_start;

    if (wrapped_key) {
        fs::path day_key_prefix = meta_get<std::string>(meta, "tpm", "day_key_prefix", "day_key_prefix", "");
        if (day_key_prefix.empty()) {
            throw std::runtime_error("day_key_prefix missing in meta");
        }
        if (!day_key_prefix.is_absolute()) {
            day_key_prefix = base_dir / day_key_prefix;
        }

        std::optional<fs::path> policy_file;
        std::optional<fs::path> signer_pub_copy;
        if (policy_signed) {
            std::string policy_name = meta_get<std::string>(meta, "policy", "day_policy_file", "day_policy_file", "");
            std::string signer_name = meta_get<std::string>(meta, "policy", "day_policy_signer_pub", "day_policy_signer_pub", "");
            if (policy_name.empty() || signer_name.empty()) {
                throw std::runtime_error("policy metadata missing in meta");
            }
            fs::path day_dir = day_key_prefix.parent_path();
            policy_file = day_dir / policy_name;
            signer_pub_copy = day_dir / signer_name;
        }

        std::vector<uint8_t> day_key;
        std::string cache_key = day_key_prefix.string();
        if (day_key_cache) {
            auto it = day_key_cache->find(cache_key);
            if (it != day_key_cache->end()) {
                day_key = it->second;
            }
        }

        if (day_key.empty()) {
            t_unseal_start = std::chrono::steady_clock::now();
            day_key = unseal_cb(day_key_prefix, primary_ctx, policy_file, signer_pub_copy);
            t_unseal_end = std::chrono::steady_clock::now();
            if (day_key_cache) {
                (*day_key_cache)[cache_key] = day_key;
            }
        }

        auto wrapped = b64d(meta_get<std::string>(meta, "crypto", "wrapped_key_b64", "wrapped_key_b64", ""));
        auto wrap_nonce = b64d(meta_get<std::string>(meta, "crypto", "wrap_nonce_b64", "wrap_nonce_b64", ""));
        auto wrap_tag = b64d(meta_get<std::string>(meta, "crypto", "wrap_tag_b64", "wrap_tag_b64", ""));
        key = aes_gcm_decrypt_buf(day_key, wrap_nonce, wrapped, wrap_tag, std::nullopt);
        if (key.size() != 32) {
            throw std::runtime_error("Unexpected wrapped key length");
        }
    } else {
        fs::path key_prefix = base_dir / meta_get<std::string>(meta, "tpm", "key_prefix", "key_prefix", "");
        std::optional<fs::path> policy_file;
        std::optional<fs::path> signer_pub_copy;
        if (policy_signed) {
            policy_file = base_dir / meta_get<std::string>(meta, "policy", "policy_file", "policy_file", "");
            signer_pub_copy = base_dir / meta_get<std::string>(meta, "policy", "policy_signer_pub", "policy_signer_pub", "");
            if (policy_file->empty() || signer_pub_copy->empty()) {
                throw std::runtime_error("policy metadata missing in meta");
            }
        }

        t_unseal_start = std::chrono::steady_clock::now();
        key = unseal_cb(key_prefix, primary_ctx, policy_file, signer_pub_copy);
        t_unseal_end = std::chrono::steady_clock::now();
    }

    if (out_key) {
        *out_key = key;
    }

    auto t_dec_start = std::chrono::steady_clock::now();
    aes_gcm_decrypt_file(enc_path, tmp_out, key, nonce, tag, aad, chunk_size);
    auto t_dec_end = std::chrono::steady_clock::now();

    auto to_sec = [](const std::chrono::steady_clock::time_point& a,
                     const std::chrono::steady_clock::time_point& b) {
        return std::chrono::duration_cast<std::chrono::duration<double>>(b - a).count();
    };
    std::cerr << "[*] Decrypt timings (s): tpm_unseal=" << to_sec(t_unseal_start, t_unseal_end)
              << ", aes=" << to_sec(t_dec_start, t_dec_end) << "\n";
    return tmp_out;
}

static fs::path ffmpeg_slice(const fs::path& input,
                             const fs::path& output,
                             double start_sec,
                             double end_sec) {
    std::ostringstream ss_start;
    std::ostringstream ss_end;
    ss_start << std::fixed << std::setprecision(3) << start_sec;
    ss_end << std::fixed << std::setprecision(3) << end_sec;

    run_cmd_or_throw({
        "ffmpeg",
        "-y",
        "-i", input.string(),
        "-ss", ss_start.str(),
        "-to", ss_end.str(),
        "-c:v", "libx264",
        "-preset", "veryfast",
        "-crf", "18",
        "-pix_fmt", "yuv420p",
        "-an",
        output.string()
    });
    return output;
}

static fs::path ffmpeg_slice_lossless(const fs::path& input,
                                      const fs::path& output,
                                      double start_sec,
                                      double end_sec) {
    std::ostringstream ss_start, ss_end;
    ss_start << std::fixed << std::setprecision(6) << start_sec;
    ss_end << std::fixed << std::setprecision(6) << end_sec;
    std::vector<std::string> cmd = {
        "ffmpeg", "-v", "error",
        "-y",
        "-i", input.string(),
        "-ss", ss_start.str(),
        "-to", ss_end.str(),
        "-c:v", "ffv1",
        "-level", "3",
        "-g", "1",
        "-pix_fmt", "rgb24",
        "-an",
        output.string()
    };
    run_cmd_or_throw(cmd);
    return output;
}

static fs::path ffmpeg_concat(const std::vector<fs::path>& inputs,
                              const fs::path& output,
                              const fs::path& tmp_dir) {
    if (inputs.empty()) return output;

    std::vector<std::string> cmd = {"ffmpeg", "-y"};
    for (const auto& p : inputs) {
        cmd.push_back("-i");
        cmd.push_back(p.string());
    }

    std::ostringstream filter;
    for (size_t i = 0; i < inputs.size(); ++i) {
        filter << "[" << i << ":v]";
    }
    filter << "concat=n=" << inputs.size() << ":v=1:a=0[outv]";

    cmd.push_back("-filter_complex");
    cmd.push_back(filter.str());
    cmd.push_back("-map");
    cmd.push_back("[outv]");
    cmd.push_back("-c:v");
    cmd.push_back("libx264");
    cmd.push_back("-preset");
    cmd.push_back("veryfast");
    cmd.push_back("-crf");
    cmd.push_back("18");
    cmd.push_back("-pix_fmt");
    cmd.push_back("yuv420p");
    cmd.push_back("-an");
    cmd.push_back(output.string());

    run_cmd_or_throw(cmd);
    return output;
}

static fs::path ffmpeg_concat_lossless(const std::vector<fs::path>& inputs,
                                       const fs::path& output,
                                       const fs::path& tmp_dir) {
    if (inputs.empty()) return output;
    fs::create_directories(tmp_dir);
    fs::path list_path = tmp_dir / ("concat_" + now_ts_name() + ".txt");
    {
        std::ofstream ofs(list_path);
        for (const auto& p : inputs) {
            ofs << "file '" << p.string() << "'\n";
        }
    }

    std::vector<std::string> cmd = {
        "ffmpeg", "-v", "error",
        "-y",
        "-f", "concat",
        "-safe", "0",
        "-i", list_path.string(),
        "-c:v", "ffv1",
        "-level", "3",
        "-g", "1",
        "-pix_fmt", "rgb24",
        "-an",
        output.string()
    };
    run_cmd_or_throw(cmd);
    std::error_code ec;
    fs::remove(list_path, ec);
    return output;
}

static fs::path concat_jsonl_files(const std::vector<fs::path>& inputs,
                                   const fs::path& output) {
    if (inputs.empty()) return output;
    std::ofstream out(output, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("Failed to open jsonl output");
    }
    std::vector<char> buf(64 * 1024);
    for (size_t i = 0; i < inputs.size(); ++i) {
        std::ifstream in(inputs[i], std::ios::binary);
        if (!in) {
            throw std::runtime_error("Failed to open jsonl input");
        }
        while (in) {
            in.read(buf.data(), (std::streamsize)buf.size());
            std::streamsize got = in.gcount();
            if (got > 0) {
                out.write(buf.data(), got);
            }
        }
        if (!out) {
            throw std::runtime_error("Failed to write jsonl output");
        }
        if (i + 1 < inputs.size()) {
            out.write("\n", 1);
        }
    }
    return output;
}

static fs::path ffmpeg_transcode_to_mp4(const fs::path& input,
                                        const fs::path& output) {
    std::vector<std::string> cmd = {
        "ffmpeg", "-v", "error",
        "-y",
        "-i", input.string(),
        "-c:v", "libx264",
        "-preset", "veryfast",
        "-crf", "18",
        "-pix_fmt", "yuv420p",
        "-an",
        output.string()
    };
    run_cmd_or_throw(cmd);
    return output;
}

}  // namespace

namespace secure_save {

SecureSave::SecureSave(SecureSaveConfig config)
    : config_(std::move(config)) {
    gst_init(nullptr, nullptr);
}

std::vector<FrameBox> build_track_boxes_from_tracking(const std::vector<TrackingBuffer>& tracking_buffers,
                                                      uint32_t width,
                                                      uint32_t height) {
    std::vector<FrameBox> out;
    out.reserve(tracking_buffers.size());
    int32_t w = static_cast<int32_t>(width);
    int32_t h = static_cast<int32_t>(height);
    for (const auto& track : tracking_buffers) {
        if (track.track_id < 0) continue;
        const auto& obs = track.last_observation;
        if (obs[0] < 0.0f || obs[1] < 0.0f || obs[2] <= obs[0] || obs[3] <= obs[1]) continue;
        int32_t x1 = static_cast<int32_t>(std::lround(obs[0]));
        int32_t y1 = static_cast<int32_t>(std::lround(obs[1]));
        int32_t x2 = static_cast<int32_t>(std::lround(obs[2]));
        int32_t y2 = static_cast<int32_t>(std::lround(obs[3]));
        if (w > 0 && h > 0) {
            x1 = std::clamp(x1, 0, w);
            y1 = std::clamp(y1, 0, h);
            x2 = std::clamp(x2, 0, w);
            y2 = std::clamp(y2, 0, h);
        }
        if (x2 <= x1 || y2 <= y1) continue;
        out.push_back(FrameBox{x1, y1, x2, y2, track.track_id});
    }
    return out;
}

FramePacket build_frame_packet_from_unified(const UnifiedBuffer& unified,
                                            const std::vector<TrackingBuffer>& tracking_buffers,
                                            uint64_t timestamp_ns,
                                            uint32_t fps_num,
                                            uint32_t fps_den) {
    FramePacket frame;
    if (unified.raw_frame.empty()) {
        return frame;
    }
    if (unified.raw_frame.type() != CV_8UC3) {
        throw std::runtime_error("UnifiedBuffer raw_frame must be CV_8UC3");
    }
    frame.width = static_cast<uint32_t>(unified.raw_frame.cols);
    frame.height = static_cast<uint32_t>(unified.raw_frame.rows);
    frame.fps_num = fps_num == 0 ? 30 : fps_num;
    frame.fps_den = fps_den == 0 ? 1 : fps_den;
    frame.timestamp_ns = timestamp_ns;

    size_t bytes = static_cast<size_t>(frame.width) * frame.height * 3;
    frame.rgb.resize(bytes);
    if (unified.raw_frame.isContinuous()) {
        std::memcpy(frame.rgb.data(), unified.raw_frame.data, bytes);
    } else {
        size_t row_bytes = static_cast<size_t>(frame.width) * 3;
        for (uint32_t y = 0; y < frame.height; ++y) {
            const uint8_t* src = unified.raw_frame.ptr<uint8_t>(y);
            std::memcpy(frame.rgb.data() + row_bytes * y, src, row_bytes);
        }
    }

    frame.boxes = build_track_boxes_from_tracking(tracking_buffers, frame.width, frame.height);
    return frame;
}

static uint64_t frames_per_segment(uint32_t fps_num, uint32_t fps_den, int segment_seconds) {
    if (fps_num == 0 || fps_den == 0 || segment_seconds <= 0) return 0;
    uint64_t num = static_cast<uint64_t>(segment_seconds) * static_cast<uint64_t>(fps_num);
    return (num + static_cast<uint64_t>(fps_den) - 1ULL) / static_cast<uint64_t>(fps_den);
}

std::vector<fs::path> SecureSave::encrypt(const std::vector<FramePacket>& frames,
                                          const fs::path& out_dir,
                                          const std::string& camera_id,
                                          int segment_seconds) {
    std::vector<fs::path> outputs;
    if (frames.empty()) return outputs;

    bool hot_enabled = config_.storage.hot_enabled;
    bool cold_enabled = config_.storage.cold_enabled;
    if (!hot_enabled && !cold_enabled) return outputs;

    int hot_seconds = config_.storage.hot_segment_seconds;
    if (hot_seconds <= 0) hot_seconds = 1;
    int cold_seconds = config_.storage.cold_segment_seconds;
    if (cold_seconds <= 0) cold_seconds = config_.segment_seconds;
    if (segment_seconds > 0) cold_seconds = segment_seconds;
    if (cold_seconds <= 0) cold_seconds = 60;

    fs::path hot_root = resolve_root(out_dir, config_.storage.hot_dir);
    fs::path cold_root = resolve_root(out_dir, config_.storage.cold_dir);

    if (cold_enabled) {
        if (!config_.bundle.policy.server_url.empty() || !config_.bundle.policy.signer_pub.empty()) {
            config_.bundle.policy.enabled = true;
        }

        if (config_.bundle.policy.enabled) {
            if (config_.bundle.policy.server_url.empty() || config_.bundle.policy.signer_pub.empty()) {
                throw std::runtime_error("PolicySigned requires server_url and signer_pub");
            }
            if (!fs::exists(config_.bundle.policy.signer_pub)) {
                throw std::runtime_error("Policy signer pub not found: " + config_.bundle.policy.signer_pub.string());
            }
        }

        std::string obj_auth = config_.object_auth;
        if (!config_.bundle.policy.enabled && obj_auth.empty()) {
            obj_auth = get_obj_auth_once();
            config_.object_auth = obj_auth;
        }
    }

    std::unique_ptr<HotSegmentWriter> hot;
    std::unique_ptr<ColdSegmentWriter> cold;
    uint64_t last_pts_hot = 0;
    uint64_t last_pts_cold = 0;
    uint64_t hot_frame_index = 0;
    uint64_t hot_frames_per_segment = 0;
    uint64_t cold_frame_index = 0;

    ProgressMeter overall_progress;
    overall_progress.start_meter("Encrypt frames", frames.size());

    std::map<std::string, DayKeyState> day_key_cache;
    fs::path primary_ctx = fs::absolute(cold_root) / "primary.ctx";

    auto get_day_key = [&](uint64_t start_ts_ns) -> DayKeyState& {
        fs::path day_dir = cold_day_dir_for_epoch(cold_root, start_ts_ns);
        fs::create_directories(day_dir);
        fs::path day_prefix = fs::absolute(day_dir / "day_key");
        std::string cache_key = day_prefix.string();

        auto it = day_key_cache.find(cache_key);
        if (it != day_key_cache.end()) {
            return it->second;
        }

        DayKeyState state;
        state.prefix = day_prefix;
        if (sealed_key_exists(day_prefix)) {
            std::optional<fs::path> policy_file;
            std::optional<fs::path> signer_pub_copy;
            fs::path policy_path = day_prefix; policy_path += ".policy";
            fs::path signer_path = day_prefix.parent_path() / "signer.pub";
            if (fs::exists(policy_path) && fs::exists(signer_path)) {
                policy_file = policy_path;
                signer_pub_copy = signer_path;
            }
            state.key = this->tpm_unseal(day_prefix, primary_ctx, policy_file, signer_pub_copy);
            state.policy_file = policy_file;
            state.signer_pub_copy = signer_pub_copy;
        } else {
            state.key = tpm_get_random_32();
            auto artifacts = this->tpm_seal(state.key, day_prefix, primary_ctx);
            state.policy_file = artifacts.policy_file;
            state.signer_pub_copy = artifacts.signer_pub_copy;
        }

        auto res = day_key_cache.emplace(cache_key, std::move(state));
        return res.first->second;
    };

    for (size_t i = 0; i < frames.size(); ++i) {
        const auto& frame = frames[i];
        if (frame.rgb.empty()) continue;
        overall_progress.update(i + 1);

        uint64_t dur_ns = (uint64_t)1000000000ULL * frame.fps_den / frame.fps_num;

        if (hot_enabled) {
            if (!hot) {
                hot = std::make_unique<HotSegmentWriter>();
                hot->init(hot_root, camera_id, frame.width, frame.height, frame.fps_num, frame.fps_den,
                          frame.timestamp_ns, (uint64_t)hot_seconds * 1000000000ULL, config_.roi_mask);
                last_pts_hot = 0;
                hot_frame_index = 0;
                hot_frames_per_segment = frames_per_segment(frame.fps_num, frame.fps_den, hot_seconds);
            }

            uint64_t hot_len_ns = (uint64_t)hot_seconds * 1000000000ULL;
            bool rotate_hot = false;
            if (hot_frames_per_segment > 0) {
                rotate_hot = (hot_frame_index >= hot_frames_per_segment);
            } else {
                rotate_hot = (frame.timestamp_ns - hot->start_ns >= hot_len_ns);
            }
            if (rotate_hot) {
                hot->finish(camera_id);
                outputs.push_back(hot->video_path);
                cleanup_hot_dir(hot_root, config_.storage.hot_retention_hours);
                hot = std::make_unique<HotSegmentWriter>();
                hot->init(hot_root, camera_id, frame.width, frame.height, frame.fps_num, frame.fps_den,
                          frame.timestamp_ns, (uint64_t)hot_seconds * 1000000000ULL, config_.roi_mask);
                last_pts_hot = 0;
                hot_frame_index = 0;
                hot_frames_per_segment = frames_per_segment(frame.fps_num, frame.fps_den, hot_seconds);
            }

            uint64_t pts_hot = compute_pts(frame.timestamp_ns, hot->start_ns, dur_ns, last_pts_hot);
            std::vector<uint8_t> masked_hot;
            const std::vector<uint8_t>* out_hot = apply_roi_mask_for_segment(
                frame, hot_frame_index, hot->roi_cfg, hot->roi_masker.get(), hot->roi_metadata.get(), masked_hot,
                &hot->roi_frames_total, &hot->roi_frames_masked, &hot->roi_boxes_total);
            hot->push(*out_hot, pts_hot, dur_ns, frame.timestamp_ns);
            hot_frame_index++;
        }

        if (cold_enabled) {
            if (!cold) {
                cold = std::make_unique<ColdSegmentWriter>();
                DayKeyState& day_state = get_day_key(frame.timestamp_ns);
                cold->init(cold_root, camera_id, frame.width, frame.height, frame.fps_num, frame.fps_den,
                           frame.timestamp_ns, (uint64_t)cold_seconds * 1000000000ULL,
                           day_state, config_.roi_mask, config_.track);
                last_pts_cold = 0;
                cold_frame_index = 0;
            }

            uint64_t cold_len_ns = (uint64_t)cold_seconds * 1000000000ULL;
            if (frame.timestamp_ns - cold->start_ns >= cold_len_ns) {
                cold->finish(camera_id, config_.bundle);
                outputs.push_back(cold->enc_full_path);
                cleanup_cold_dir(cold_root, config_.storage.cold_retention_days);
                cold = std::make_unique<ColdSegmentWriter>();
                DayKeyState& day_state = get_day_key(frame.timestamp_ns);
                cold->init(cold_root, camera_id, frame.width, frame.height, frame.fps_num, frame.fps_den,
                           frame.timestamp_ns, (uint64_t)cold_seconds * 1000000000ULL,
                           day_state, config_.roi_mask, config_.track);
                last_pts_cold = 0;
                cold_frame_index = 0;
            }

            uint64_t pts_cold = compute_pts(frame.timestamp_ns, cold->start_ns, dur_ns, last_pts_cold);
            std::vector<uint8_t> masked_cold;
            const std::vector<uint8_t>* out_cold = apply_roi_mask_for_segment(
                frame, cold_frame_index, cold->roi_cfg, cold->roi_masker.get(), cold->roi_metadata.get(), masked_cold,
                &cold->roi_frames_total, &cold->roi_frames_masked, &cold->roi_boxes_total);
            cold->track_writer.on_frame(cold_frame_index, frame.boxes);
            cold->push(*out_cold, pts_cold, dur_ns, frame.timestamp_ns);
            cold_frame_index++;
        }
    }

    if (hot) {
        hot->finish(camera_id);
        outputs.push_back(hot->video_path);
        cleanup_hot_dir(hot_root, config_.storage.hot_retention_hours);
    }
    if (cold) {
        cold->finish(camera_id, config_.bundle);
        outputs.push_back(cold->enc_full_path);
        cleanup_cold_dir(cold_root, config_.storage.cold_retention_days);
    }

    overall_progress.finish(frames.size());

    return outputs;
}

std::vector<fs::path> SecureSave::encrypt_stream(const FrameSource& next_frame,
                                                  const fs::path& out_dir,
                                                  const std::string& camera_id,
                                                  int segment_seconds) {
    std::vector<fs::path> outputs;
    if (!next_frame) return outputs;

    bool hot_enabled = config_.storage.hot_enabled;
    bool cold_enabled = config_.storage.cold_enabled;
    if (!hot_enabled && !cold_enabled) return outputs;

    int hot_seconds = config_.storage.hot_segment_seconds;
    if (hot_seconds <= 0) hot_seconds = 1;
    int cold_seconds = config_.storage.cold_segment_seconds;
    if (cold_seconds <= 0) cold_seconds = config_.segment_seconds;
    if (segment_seconds > 0) cold_seconds = segment_seconds;
    if (cold_seconds <= 0) cold_seconds = 60;

    fs::path hot_root = resolve_root(out_dir, config_.storage.hot_dir);
    fs::path cold_root = resolve_root(out_dir, config_.storage.cold_dir);

    if (cold_enabled) {
        if (!config_.bundle.policy.server_url.empty() || !config_.bundle.policy.signer_pub.empty()) {
            config_.bundle.policy.enabled = true;
        }

        if (config_.bundle.policy.enabled) {
            if (config_.bundle.policy.server_url.empty() || config_.bundle.policy.signer_pub.empty()) {
                throw std::runtime_error("PolicySigned requires server_url and signer_pub");
            }
            if (!fs::exists(config_.bundle.policy.signer_pub)) {
                throw std::runtime_error("Policy signer pub not found: " + config_.bundle.policy.signer_pub.string());
            }
        }

        std::string obj_auth = config_.object_auth;
        if (!config_.bundle.policy.enabled && obj_auth.empty()) {
            obj_auth = get_obj_auth_once();
            config_.object_auth = obj_auth;
        }
    }

    std::unique_ptr<HotSegmentWriter> hot;
    std::unique_ptr<ColdSegmentWriter> cold;
    uint64_t last_pts_hot = 0;
    uint64_t last_pts_cold = 0;
    uint64_t hot_frame_index = 0;
    uint64_t hot_frames_per_segment = 0;
    uint64_t cold_frame_index = 0;

    std::map<std::string, DayKeyState> day_key_cache;
    fs::path primary_ctx = fs::absolute(cold_root) / "primary.ctx";

    auto get_day_key = [&](uint64_t start_ts_ns) -> DayKeyState& {
        fs::path day_dir = cold_day_dir_for_epoch(cold_root, start_ts_ns);
        fs::create_directories(day_dir);
        fs::path day_prefix = fs::absolute(day_dir / "day_key");
        std::string cache_key = day_prefix.string();

        auto it = day_key_cache.find(cache_key);
        if (it != day_key_cache.end()) {
            return it->second;
        }

        DayKeyState state;
        state.prefix = day_prefix;
        if (sealed_key_exists(day_prefix)) {
            std::optional<fs::path> policy_file;
            std::optional<fs::path> signer_pub_copy;
            fs::path policy_path = day_prefix; policy_path += ".policy";
            fs::path signer_path = day_prefix.parent_path() / "signer.pub";
            if (fs::exists(policy_path) && fs::exists(signer_path)) {
                policy_file = policy_path;
                signer_pub_copy = signer_path;
            }
            state.key = this->tpm_unseal(day_prefix, primary_ctx, policy_file, signer_pub_copy);
            state.policy_file = policy_file;
            state.signer_pub_copy = signer_pub_copy;
        } else {
            state.key = tpm_get_random_32();
            auto artifacts = this->tpm_seal(state.key, day_prefix, primary_ctx);
            state.policy_file = artifacts.policy_file;
            state.signer_pub_copy = artifacts.signer_pub_copy;
        }

        auto res = day_key_cache.emplace(cache_key, std::move(state));
        return res.first->second;
    };

    FramePacket frame;
    bool has_any = false;
    uint64_t frame_index = 0;
    while (next_frame(frame)) {
        uint64_t current_index = frame_index++;
        if (frame.rgb.empty()) {
            continue;
        }
        has_any = true;

        uint64_t dur_ns = (uint64_t)1000000000ULL * frame.fps_den / frame.fps_num;

        if (hot_enabled) {
            if (!hot) {
                hot = std::make_unique<HotSegmentWriter>();
                hot->init(hot_root, camera_id, frame.width, frame.height, frame.fps_num, frame.fps_den,
                          frame.timestamp_ns, (uint64_t)hot_seconds * 1000000000ULL, config_.roi_mask);
                last_pts_hot = 0;
                hot_frame_index = 0;
                hot_frames_per_segment = frames_per_segment(frame.fps_num, frame.fps_den, hot_seconds);
            }

            uint64_t hot_len_ns = (uint64_t)hot_seconds * 1000000000ULL;
            bool rotate_hot = false;
            if (hot_frames_per_segment > 0) {
                rotate_hot = (hot_frame_index >= hot_frames_per_segment);
            } else {
                rotate_hot = (frame.timestamp_ns - hot->start_ns >= hot_len_ns);
            }
            if (rotate_hot) {
                hot->finish(camera_id);
                outputs.push_back(hot->video_path);
                cleanup_hot_dir(hot_root, config_.storage.hot_retention_hours);
                hot = std::make_unique<HotSegmentWriter>();
                hot->init(hot_root, camera_id, frame.width, frame.height, frame.fps_num, frame.fps_den,
                          frame.timestamp_ns, (uint64_t)hot_seconds * 1000000000ULL, config_.roi_mask);
                last_pts_hot = 0;
                hot_frame_index = 0;
                hot_frames_per_segment = frames_per_segment(frame.fps_num, frame.fps_den, hot_seconds);
            }

            uint64_t pts_hot = compute_pts(frame.timestamp_ns, hot->start_ns, dur_ns, last_pts_hot);
            std::vector<uint8_t> masked_hot;
            const std::vector<uint8_t>* out_hot = apply_roi_mask_for_segment(
                frame, hot_frame_index, hot->roi_cfg, hot->roi_masker.get(), hot->roi_metadata.get(), masked_hot,
                &hot->roi_frames_total, &hot->roi_frames_masked, &hot->roi_boxes_total);
            hot->push(*out_hot, pts_hot, dur_ns, frame.timestamp_ns);
            hot_frame_index++;
        }

        if (cold_enabled) {
            if (!cold) {
                cold = std::make_unique<ColdSegmentWriter>();
                DayKeyState& day_state = get_day_key(frame.timestamp_ns);
                cold->init(cold_root, camera_id, frame.width, frame.height, frame.fps_num, frame.fps_den,
                           frame.timestamp_ns, (uint64_t)cold_seconds * 1000000000ULL,
                           day_state, config_.roi_mask, config_.track);
                last_pts_cold = 0;
                cold_frame_index = 0;
            }

            uint64_t cold_len_ns = (uint64_t)cold_seconds * 1000000000ULL;
            if (frame.timestamp_ns - cold->start_ns >= cold_len_ns) {
                cold->finish(camera_id, config_.bundle);
                outputs.push_back(cold->enc_full_path);
                cleanup_cold_dir(cold_root, config_.storage.cold_retention_days);
                cold = std::make_unique<ColdSegmentWriter>();
                DayKeyState& day_state = get_day_key(frame.timestamp_ns);
                cold->init(cold_root, camera_id, frame.width, frame.height, frame.fps_num, frame.fps_den,
                           frame.timestamp_ns, (uint64_t)cold_seconds * 1000000000ULL,
                           day_state, config_.roi_mask, config_.track);
                last_pts_cold = 0;
                cold_frame_index = 0;
            }

            uint64_t pts_cold = compute_pts(frame.timestamp_ns, cold->start_ns, dur_ns, last_pts_cold);
            std::vector<uint8_t> masked_cold;
            const std::vector<uint8_t>* out_cold = apply_roi_mask_for_segment(
                frame, cold_frame_index, cold->roi_cfg, cold->roi_masker.get(), cold->roi_metadata.get(), masked_cold,
                &cold->roi_frames_total, &cold->roi_frames_masked, &cold->roi_boxes_total);
            cold->track_writer.on_frame(cold_frame_index, frame.boxes);
            cold->push(*out_cold, pts_cold, dur_ns, frame.timestamp_ns);
            cold_frame_index++;
        }
    }

    if (!has_any) {
        return outputs;
    }

    if (hot) {
        hot->finish(camera_id);
        outputs.push_back(hot->video_path);
        cleanup_hot_dir(hot_root, config_.storage.hot_retention_hours);
    }
    if (cold) {
        cold->finish(camera_id, config_.bundle);
        outputs.push_back(cold->enc_full_path);
        cleanup_cold_dir(cold_root, config_.storage.cold_retention_days);
    }

    return outputs;
}

std::map<std::string, fs::path> SecureSave::decrypt(const fs::path& bundle_root,
                                                    const fs::path& response_dir,
                                                    uint64_t start_ms,
                                                    uint64_t end_ms,
                                                    const std::string& view,
                                                    bool enable_roi_unmask) {
    if (!config_.bundle.policy.server_url.empty() || !config_.bundle.policy.signer_pub.empty()) {
        config_.bundle.policy.enabled = true;
    }

    if (config_.bundle.policy.enabled) {
        if (config_.bundle.policy.server_url.empty() || config_.bundle.policy.signer_pub.empty()) {
            throw std::runtime_error("PolicySigned requires server_url and signer_pub");
        }
        if (!fs::exists(config_.bundle.policy.signer_pub)) {
            throw std::runtime_error("Policy signer pub not found: " + config_.bundle.policy.signer_pub.string());
        }
    }

    std::string obj_auth = config_.object_auth;
    if (!config_.bundle.policy.enabled && obj_auth.empty()) {
        obj_auth = get_obj_auth_once();
        config_.object_auth = obj_auth;
    }

    uint64_t start_ns = start_ms * 1000000ULL;
    uint64_t end_ns = end_ms * 1000000ULL + 999999ULL;

    fs::create_directories(response_dir);
    fs::path tmp_dir = response_dir / "tmp";

    auto segments = find_segments(bundle_root, start_ns, end_ns, view);
    if (segments.empty()) {
        throw std::runtime_error("No segments found");
    }

    std::map<std::string, std::vector<fs::path>> view_outputs;
    std::vector<fs::path> track_outputs;
    std::map<std::string, std::vector<uint8_t>> day_key_cache;
    auto unseal_cb = [this](const fs::path& key_prefix,
                            const fs::path& primary_ctx,
                            const std::optional<fs::path>& policy_file,
                            const std::optional<fs::path>& signer_pub_copy) {
        return this->tpm_unseal(key_prefix, primary_ctx, policy_file, signer_pub_copy);
    };

    for (const auto& seg : segments) {
        json meta;
        { std::ifstream ifs(seg.meta_path); ifs >> meta; }

        uint64_t cipher_bytes = meta_get<uint64_t>(meta, "payload", "ciphertext_bytes", "ciphertext_bytes", 0ULL);
        uint64_t plain_bytes = meta_get<uint64_t>(meta, "payload", "plaintext_bytes", "plaintext_bytes", 0ULL);
        if (cipher_bytes == 0 || plain_bytes == 0) {
            continue;
        }

        uint64_t fps_num = meta_get<uint64_t>(meta, "video", "fps_num", "fps_num", 30ULL);
        uint64_t fps_den = meta_get<uint64_t>(meta, "video", "fps_den", "fps_den", 1ULL);
        if (fps_num == 0) fps_num = 30;
        if (fps_den == 0) fps_den = 1;
        uint64_t frame_duration_ns = 1000000000ULL * fps_den / fps_num;
        size_t chunk_size = (size_t)meta_get<uint64_t>(meta, "payload", "chunk_size", "chunk_size",
                                                       static_cast<uint64_t>(config_.bundle.chunk_size));

        std::vector<uint8_t> key_full;
        fs::path dec_path = decrypt_segment_to_tmp(seg.meta_path, config_.bundle, tmp_dir,
                                                   &day_key_cache, unseal_cb, &key_full);

        fs::path roi_sidecar;
        fs::path roi_sidecar_tmp;
        if (meta_has(meta, "roi", "enc_file", nullptr)
            && meta_has(meta, "roi", "nonce_b64", nullptr)
            && meta_has(meta, "roi", "tag_b64", nullptr)
            && key_full.size() == 32) {
            fs::path roi_enc = seg.meta_path.parent_path()
                / meta_get<std::string>(meta, "roi", "enc_file", nullptr, "");
            if (fs::exists(roi_enc)) {
                auto roi_nonce = b64d(meta_get<std::string>(meta, "roi", "nonce_b64", nullptr, ""));
                auto roi_tag = b64d(meta_get<std::string>(meta, "roi", "tag_b64", nullptr, ""));
                std::optional<std::vector<uint8_t>> roi_aad;
                if (meta_has(meta, "roi", "aad_b64", nullptr)) {
                    roi_aad = b64d(meta_get<std::string>(meta, "roi", "aad_b64", nullptr, ""));
                } else if (meta_has(meta, "crypto", "aad_b64", "aad_b64")) {
                    roi_aad = b64d(meta_get<std::string>(meta, "crypto", "aad_b64", "aad_b64", ""));
                }
                roi_sidecar_tmp = tmp_dir / (seg.meta_path.stem().string() + ".mask.jsonl");
                aes_gcm_decrypt_file(roi_enc, roi_sidecar_tmp, key_full, roi_nonce, roi_tag, roi_aad, chunk_size);
                roi_sidecar = roi_sidecar_tmp;
            }
        }
        if (roi_sidecar.empty()) {
            std::string sidecar_name = meta_get<std::string>(meta, "roi", "sidecar", "roi_sidecar", "");
            fs::path fallback = sidecar_name.empty()
                ? default_mask_sidecar_from_meta(seg.meta_path)
                : (seg.meta_path.parent_path() / sidecar_name);
            if (fs::exists(fallback)) {
                roi_sidecar = fallback;
            }
        }

        bool track_added = false;
        if (!roi_sidecar.empty() && fs::exists(roi_sidecar)) {
            fs::path track_out = tmp_dir / (seg.meta_path.stem().string() + ".track.jsonl");
            fs::copy_file(roi_sidecar, track_out, fs::copy_options::overwrite_existing);
            track_outputs.push_back(track_out);
            track_added = true;
        }
        if (!track_added
            && meta_has(meta, "track", "enc_file", "track_enc_file")
            && meta_has(meta, "track", "nonce_b64", "track_nonce_b64")
            && meta_has(meta, "track", "tag_b64", "track_tag_b64")) {
            fs::path track_enc = seg.meta_path.parent_path()
                / meta_get<std::string>(meta, "track", "enc_file", "track_enc_file", "");
            if (fs::exists(track_enc) && key_full.size() == 32) {
                auto track_nonce = b64d(meta_get<std::string>(meta, "track", "nonce_b64", "track_nonce_b64", ""));
                auto track_tag = b64d(meta_get<std::string>(meta, "track", "tag_b64", "track_tag_b64", ""));
                std::optional<std::vector<uint8_t>> track_aad;
                if (meta_has(meta, "track", "aad_b64", "track_aad_b64")) {
                    track_aad = b64d(meta_get<std::string>(meta, "track", "aad_b64", "track_aad_b64", ""));
                } else if (meta_has(meta, "crypto", "aad_b64", "aad_b64")) {
                    track_aad = b64d(meta_get<std::string>(meta, "crypto", "aad_b64", "aad_b64", ""));
                }
                fs::path track_out = tmp_dir / (seg.meta_path.stem().string() + ".track.jsonl");
                aes_gcm_decrypt_file(track_enc, track_out, key_full, track_nonce, track_tag, track_aad, chunk_size);
                track_outputs.push_back(track_out);
            }
        }

        uint64_t slice_start_ns = 0;
        uint64_t slice_end_ns = 0;
        if (start_ns > seg.start_ns) {
            slice_start_ns = start_ns - seg.start_ns;
        }
        uint64_t seg_end_inclusive = seg.end_ns + frame_duration_ns;
        uint64_t seg_end = seg_end_inclusive;
        uint64_t effective_end_ns = end_ns;
        if (end_ns >= seg.end_ns && end_ns < seg_end_inclusive) {
            effective_end_ns = seg_end_inclusive;
        }
        if (effective_end_ns < seg_end_inclusive) {
            seg_end = effective_end_ns;
        }
        if (seg_end > seg.start_ns) {
            slice_end_ns = seg_end - seg.start_ns;
        }
        double slice_start = (double)slice_start_ns / 1e9;
        double slice_end = (double)slice_end_ns / 1e9;

        fs::path slice_input = dec_path;
        fs::path unmask_path;
        bool do_unmask = false;
        bool roi_enabled = meta_get<bool>(meta, "roi", "enabled", "roi_mask", false);
        if (enable_roi_unmask && roi_enabled) {
            if (!roi_sidecar.empty() && fs::exists(roi_sidecar)) {
                unmask_path = tmp_dir / (seg.meta_path.stem().string() + ".unmask.mkv");
                roi_unmask_video(dec_path, unmask_path, key_full, roi_sidecar);
                slice_input = unmask_path;
                do_unmask = true;
            }
        }

        uint64_t segment_duration_ns = seg_end_inclusive - seg.start_ns;
        bool full_slice = (slice_start_ns == 0) && (slice_end_ns >= segment_duration_ns);

        fs::path slice_path;
        bool created_slice = false;
        if (full_slice) {
            slice_path = slice_input;
        } else {
            slice_path = tmp_dir / (seg.meta_path.stem().string() + "_slice.mkv");
            ffmpeg_slice_lossless(slice_input, slice_path, slice_start, slice_end);
            created_slice = true;
        }

        std::error_code ec;
        if (created_slice) {
            fs::remove(dec_path, ec);
            if (do_unmask && !unmask_path.empty()) {
                fs::remove(unmask_path, ec);
            }
        }
        if (!roi_sidecar_tmp.empty()) {
            std::error_code roi_ec;
            fs::remove(roi_sidecar_tmp, roi_ec);
        }

        if (ec || slice_path.empty() || !fs::exists(slice_path)) {
            continue;
        }

        const std::string output_view = (view == "both") ? seg.view : view;
        view_outputs[output_view].push_back(slice_path);
    }

    if (view_outputs.empty()) {
        throw std::runtime_error("No valid slices");
    }

    std::map<std::string, fs::path> outputs;
    for (auto& kv : view_outputs) {
        fs::path lossless_path;
        if (kv.second.size() == 1) {
            lossless_path = kv.second.front();
        } else {
            lossless_path = tmp_dir / ("merged_" + kv.first + "_" + now_ts_name() + ".mkv");
            ffmpeg_concat_lossless(kv.second, lossless_path, tmp_dir);
            for (const auto& p : kv.second) {
                std::error_code ec;
                fs::remove(p, ec);
            }
        }

        const std::string video_ts = now_ts_name();
        const std::string video_name = (kv.first == "full")
            ? (video_ts + ".mp4")
            : (kv.first + "_" + video_ts + ".mp4");
        fs::path final_path = response_dir / video_name;
        ffmpeg_transcode_to_mp4(lossless_path, final_path);
        outputs[kv.first] = final_path;
        std::error_code ec;
        fs::remove(lossless_path, ec);
    }

    if (!track_outputs.empty()) {
        fs::path track_path = response_dir / (now_ts_name() + ".mask.jsonl");
        concat_jsonl_files(track_outputs, track_path);
        outputs["track"] = track_path;
        for (const auto& p : track_outputs) {
            std::error_code ec;
            fs::remove(p, ec);
        }
    }

    return outputs;
}

SealArtifacts SecureSave::tpm_seal(const std::vector<uint8_t>& key32,
                                   const fs::path& key_prefix,
                                   const fs::path& primary_ctx) {
    if (!config_.bundle.policy.server_url.empty() || !config_.bundle.policy.signer_pub.empty()) {
        config_.bundle.policy.enabled = true;
    }

    if (config_.bundle.policy.enabled) {
        if (config_.bundle.policy.server_url.empty() || config_.bundle.policy.signer_pub.empty()) {
            throw std::runtime_error("PolicySigned requires server_url and signer_pub");
        }
        if (!fs::exists(config_.bundle.policy.signer_pub)) {
            throw std::runtime_error("Policy signer pub not found: " + config_.bundle.policy.signer_pub.string());
        }
    }

    std::string obj_auth = config_.object_auth;
    if (!config_.bundle.policy.enabled && obj_auth.empty()) {
        obj_auth = get_obj_auth_once();
    }

    std::optional<fs::path> policy_file;
    std::optional<fs::path> signer_pub_copy;
    tpm_seal_key(key32, key_prefix, obj_auth, primary_ctx, config_.bundle.policy, policy_file, signer_pub_copy);

    SealArtifacts artifacts;
    artifacts.policy_file = policy_file;
    artifacts.signer_pub_copy = signer_pub_copy;
    return artifacts;
}

std::vector<uint8_t> SecureSave::tpm_unseal(const fs::path& key_prefix,
                                            const fs::path& primary_ctx,
                                            const std::optional<fs::path>& policy_file,
                                            const std::optional<fs::path>& signer_pub_copy) {
    if (!config_.bundle.policy.server_url.empty() || !config_.bundle.policy.signer_pub.empty()) {
        config_.bundle.policy.enabled = true;
    }

    std::string obj_auth = config_.object_auth;
    if (!config_.bundle.policy.enabled && obj_auth.empty()) {
        obj_auth = get_obj_auth_once();
    }

    secure_save::PolicyConfig policy_cfg = config_.bundle.policy;
    if (policy_file.has_value() || signer_pub_copy.has_value()) {
        policy_cfg.enabled = true;
    }

    return tpm_unseal_key(key_prefix, obj_auth, primary_ctx, policy_cfg, policy_file, signer_pub_copy);
}

}  // namespace secure_save
