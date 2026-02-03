#include "secure_save.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <functional>
#include <map>
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

namespace fs = std::filesystem;
using json = nlohmann::json;

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
    auto r = run_cmd({"tpm2_getrandom", "32"});
    if (r.code != 0) throw std::runtime_error("tpm2_getrandom failed:\n" + bytes_to_string(r.err));
    if (r.out.size() != 32) throw std::runtime_error("TPM random length != 32");
    return r.out;
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

static GstElement* build_appsrc_pipeline(uint32_t width,
                                        uint32_t height,
                                        uint32_t fps_num,
                                        uint32_t fps_den,
                                        SinkCtx* sink_ctx,
                                        GstElement** out_appsrc,
                                        GstElement** out_appsink) {
    GstElement* pipeline = gst_pipeline_new("appsrc-pipeline");
    GstElement* appsrc = gst_element_factory_make("appsrc", "src");
    GstElement* queue = gst_element_factory_make("queue", "q");
    GstElement* convert = gst_element_factory_make("videoconvert", "conv");
    GstElement* enc = gst_element_factory_make("x264enc", "enc");
    GstElement* parse = gst_element_factory_make("h264parse", "parse");
    GstElement* mux = gst_element_factory_make("matroskamux", "mux");
    GstElement* sink = gst_element_factory_make("appsink", "sink");

    if (!pipeline || !appsrc || !queue || !convert || !enc || !parse || !mux || !sink) {
        throw std::runtime_error("Failed to create gstreamer elements. Check plugins installed.");
    }

    GstCaps* caps = gst_caps_new_simple(
        "video/x-raw",
        "format", G_TYPE_STRING, "BGR",
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

    g_object_set(G_OBJECT(enc),
                 "tune", 0x00000004,
                 "speed-preset", 1,
                 "key-int-max", (int)fps_num,
                 "bitrate", 2000,
                 NULL);

    g_object_set(G_OBJECT(mux), "streamable", TRUE, NULL);

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

    void start(const fs::path& enc_path,
               const std::vector<uint8_t>& key,
               const std::vector<uint8_t>& nonce,
               const std::optional<std::vector<uint8_t>>& aad) {
        fout.open(enc_path, std::ios::binary);
        if (!fout) throw std::runtime_error("Failed to open enc output");
        enc.init(key, nonce, aad);

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

    void push_frame(const std::vector<uint8_t>& bgr, uint64_t pts_ns, uint64_t dur_ns) {
        if (!pipeline || !appsrc) return;
        GstBuffer* buffer = gst_buffer_new_allocate(NULL, bgr.size(), NULL);
        gst_buffer_fill(buffer, 0, bgr.data(), bgr.size());
        GST_BUFFER_PTS(buffer) = pts_ns;
        GST_BUFFER_DURATION(buffer) = dur_ns;
        gst_app_src_push_buffer(GST_APP_SRC(appsrc), buffer);
    }

    void begin_pipeline(uint32_t width, uint32_t height, uint32_t fps_num, uint32_t fps_den) {
        pipeline = build_appsrc_pipeline(width, height, fps_num, fps_den, &sink_ctx, &appsrc, nullptr);
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

struct SegmentWriter {
    std::string created_at;
    fs::path bundle_dir;
    fs::path primary_ctx;
    fs::path full_dir;
    fs::path enc_full_path;
    fs::path meta_full_path;
    fs::path key_full_prefix;

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

    std::optional<fs::path> policy_full_file;
    std::optional<fs::path> signer_pub_full;

    EncPipeline full;
    std::chrono::steady_clock::time_point start_wall;
    ProgressMeter enc_progress;
    std::function<secure_save::SealArtifacts(const std::vector<uint8_t>&,
                                             const fs::path&,
                                             const fs::path&)> seal_cb;

    void init(const fs::path& out_dir,
              const std::string& camera_id,
              uint32_t w,
              uint32_t h,
              uint32_t fpsn,
              uint32_t fpsd,
              uint64_t start_ts_ns,
              uint64_t seg_len_ns,
              const secure_save::BundleConfig& bcfg,
              std::function<secure_save::SealArtifacts(const std::vector<uint8_t>&,
                                                       const fs::path&,
                                                       const fs::path&)> seal_cb_in) {
        created_at = now_ts_name();
        bundle_dir = out_dir / (created_at + "_" + safe_name(camera_id));
        bundle_dir = unique_path(bundle_dir);
        fs::create_directories(bundle_dir);
        primary_ctx = fs::absolute(out_dir) / "primary.ctx";
        start_ns = start_ts_ns;
        last_ts_ns = start_ts_ns;
        segment_len_ns = seg_len_ns;
        width = w;
        height = h;
        fps_num = fpsn;
        fps_den = fpsd;
        seal_cb = std::move(seal_cb_in);

        std::string base = bundle_dir.filename().string();
        full_dir = bundle_dir / "full";
        fs::create_directories(full_dir);

        enc_full_path = full_dir / (base + "_full.enc");
        meta_full_path = full_dir / (base + "_full.meta.json");
        key_full_prefix = full_dir / (base + "_full");

        key_full = tpm_get_random_32();
        nonce_full.assign(12, 0);
        if (RAND_bytes(nonce_full.data(), (int)nonce_full.size()) != 1) {
            throw std::runtime_error("RAND_bytes failed");
        }

        std::string aad_s = "camera=" + camera_id + ";created_at=" + created_at;
        aad.assign(aad_s.begin(), aad_s.end());
        auto aad_opt = std::optional<std::vector<uint8_t>>(aad);

        full.begin_pipeline(width, height, fps_num, fps_den);
        full.start(enc_full_path, key_full, nonce_full, aad_opt);
        start_wall = std::chrono::steady_clock::now();
        if (segment_len_ns > 0) {
            enc_progress.start_meter("Encrypt " + bundle_dir.filename().string(), segment_len_ns);
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
        full.end_pipeline();
        if (segment_len_ns > 0) {
            enc_progress.finish(segment_len_ns);
        }

        auto encode_end = std::chrono::steady_clock::now();
        uint64_t encode_ns = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(encode_end - start_wall).count());
        uint64_t aes_ns = full.encrypt_ns.load(std::memory_order_relaxed);

        std::cerr << "[*] TPM sealing start\n";
        std::cerr.flush();
        auto seal_start = std::chrono::steady_clock::now();
        if (!seal_cb) {
            throw std::runtime_error("seal callback not set");
        }
        auto full_artifacts = seal_cb(key_full, key_full_prefix, primary_ctx);
        policy_full_file = full_artifacts.policy_file;
        signer_pub_full = full_artifacts.signer_pub_copy;
        auto seal_end = std::chrono::steady_clock::now();
        std::cerr << "[*] TPM sealing done\n";
        std::cerr.flush();
        uint64_t seal_ns = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(seal_end - seal_start).count());

        std::string base = bundle_dir.filename().string();
        auto write_meta = [&](const fs::path& meta_path,
                              const std::string& view,
                              const fs::path& enc_path,
                              const fs::path& key_prefix,
                              const std::vector<uint8_t>& nonce,
                              const std::vector<uint8_t>& tag,
                              uint64_t plain_bytes,
                              uint64_t cipher_bytes,
                              const std::optional<fs::path>& policy_file,
                              const std::optional<fs::path>& signer_pub_copy) {
            json meta;
            meta["version"] = 6;
            meta["cipher"] = "AES-256-GCM";
            meta["created_at_name"] = created_at;
            meta["camera_id"] = camera_id;
            meta["view"] = view;
            meta["bundle_dir"] = bundle_dir.filename().string();
            meta["enc_file"] = enc_path.filename().string();
            meta["nonce_b64"] = b64e(nonce);
            meta["tag_b64"] = b64e(tag);
            meta["aad_b64"] = aad.empty() ? nullptr : b64e(aad);
            meta["key_prefix"] = key_prefix.filename().string();
            meta["sealed_pub"] = key_prefix.filename().string() + ".pub";
            meta["sealed_priv"] = key_prefix.filename().string() + ".priv";
            meta["primary_ctx"] = primary_ctx.string();
            if (bcfg.policy.enabled && policy_file.has_value() && signer_pub_copy.has_value()) {
                meta["policy_signed"] = true;
                meta["policy_file"] = policy_file->filename().string();
                meta["policy_signer_pub"] = signer_pub_copy->filename().string();
            } else {
                meta["policy_signed"] = false;
            }
            meta["chunk_size"] = bcfg.chunk_size;
            meta["plaintext_bytes"] = plain_bytes;
            meta["ciphertext_bytes"] = cipher_bytes;
            meta["segment_start_ns"] = start_ns;
            meta["segment_end_ns"] = last_ts_ns;
            meta["width"] = width;
            meta["height"] = height;
            meta["fps_num"] = fps_num;
            meta["fps_den"] = fps_den;
            meta["source_filename"] = safe_name(camera_id) + "_" + created_at + "_" + view + ".mp4";
            { std::ofstream ofs(meta_path); ofs << meta.dump(2); }
        };

        write_meta(meta_full_path, "full", enc_full_path, key_full_prefix,
                   nonce_full, full.enc.tag, full.enc.plain_bytes, full.enc.cipher_bytes,
                   policy_full_file, signer_pub_full);

        auto to_sec = [](uint64_t ns) { return static_cast<double>(ns) / 1e9; };
        std::cerr << "[*] Segment timings (s): recv+encode=" << to_sec(encode_ns)
                  << ", aes=" << to_sec(aes_ns)
                  << ", tpm_seal=" << to_sec(seal_ns) << "\n";
        std::cerr << "[*] Segment done. Bundle: " << bundle_dir << "\n";
    }
};

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
            if (!meta.contains("segment_start_ns") || !meta.contains("segment_end_ns")) continue;
            std::string meta_view = meta.value("view", "");
            if (view != "both") {
                if (meta_view != view) {
                    if (!(meta_view == "full" && (view == "person" || view == "background"))) {
                        continue;
                    }
                }
            }

            uint64_t seg_start = meta["segment_start_ns"].get<uint64_t>();
            uint64_t seg_end = meta["segment_end_ns"].get<uint64_t>();
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
                                       const std::function<std::vector<uint8_t>(const fs::path&,
                                                                              const fs::path&,
                                                                              const std::optional<fs::path>&,
                                                                              const std::optional<fs::path>&)>& unseal_cb) {
    json meta;
    { std::ifstream ifs(meta_path); ifs >> meta; }
    fs::path base_dir = meta_path.parent_path();

    fs::path enc_path = base_dir / meta.at("enc_file").get<std::string>();
    fs::path primary_ctx = meta.value("primary_ctx", "primary.ctx");
    if (!primary_ctx.is_absolute()) {
        primary_ctx = base_dir / primary_ctx;
    }
    fs::path key_prefix = base_dir / meta.at("key_prefix").get<std::string>();

    auto nonce = b64d(meta.at("nonce_b64").get<std::string>());
    auto tag = b64d(meta.at("tag_b64").get<std::string>());

    std::optional<std::vector<uint8_t>> aad;
    if (meta.contains("aad_b64") && !meta["aad_b64"].is_null()) {
        aad = b64d(meta["aad_b64"].get<std::string>());
    }

    size_t chunk_size = (size_t)meta.value("chunk_size", (int)cfg.chunk_size);

    std::string source_filename = meta.value("source_filename", "segment.mp4");
    fs::create_directories(tmp_dir);
    fs::path base = tmp_dir / (source_filename + ".dec.mp4");
    fs::path tmp_out = unique_path(base);

    bool policy_signed = meta.value("policy_signed", false);
    secure_save::PolicyConfig policy_cfg = cfg.policy;
    policy_cfg.enabled = policy_signed;

    std::optional<fs::path> policy_file;
    std::optional<fs::path> signer_pub_copy;
    if (policy_signed) {
        policy_file = base_dir / meta.value("policy_file", "");
        signer_pub_copy = base_dir / meta.value("policy_signer_pub", "");
        if (policy_file->empty() || signer_pub_copy->empty()) {
            throw std::runtime_error("policy metadata missing in meta");
        }
    }

    if (!unseal_cb) {
        throw std::runtime_error("unseal callback not set");
    }

    auto t_unseal_start = std::chrono::steady_clock::now();
    auto key = unseal_cb(key_prefix, primary_ctx, policy_file, signer_pub_copy);
    auto t_unseal_end = std::chrono::steady_clock::now();

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
        "-crf", "23",
        "-pix_fmt", "yuv420p",
        "-an",
        output.string()
    });
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
    cmd.push_back("23");
    cmd.push_back("-pix_fmt");
    cmd.push_back("yuv420p");
    cmd.push_back("-an");
    cmd.push_back(output.string());

    run_cmd_or_throw(cmd);
    return output;
}

}  // namespace

namespace secure_save {

SecureSave::SecureSave(SecureSaveConfig config)
    : config_(std::move(config)) {
    gst_init(nullptr, nullptr);
}

std::vector<fs::path> SecureSave::encrypt(const std::vector<FramePacket>& frames,
                                          const fs::path& out_dir,
                                          const std::string& camera_id,
                                          int segment_seconds) {
    std::vector<fs::path> bundles;
    if (frames.empty()) return bundles;

    int seg_seconds = segment_seconds > 0 ? segment_seconds : config_.segment_seconds;
    if (seg_seconds <= 0) seg_seconds = 600;

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

    std::unique_ptr<SegmentWriter> current;
    ProgressMeter overall_progress;
    overall_progress.start_meter("Encrypt frames", frames.size());
    uint64_t last_pts_ns = 0;

    auto seal_cb = [this](const std::vector<uint8_t>& key,
                          const fs::path& key_prefix,
                          const fs::path& primary_ctx) {
        return this->tpm_seal(key, key_prefix, primary_ctx);
    };

    for (size_t i = 0; i < frames.size(); ++i) {
        const auto& frame = frames[i];
        if (frame.bgr.empty()) continue;
        overall_progress.update(i + 1);

        if (!current) {
            current = std::make_unique<SegmentWriter>();
            current->init(out_dir, camera_id, frame.width, frame.height, frame.fps_num, frame.fps_den,
                          frame.timestamp_ns, (uint64_t)segment_seconds * 1000000000ULL, config_.bundle, seal_cb);
            last_pts_ns = 0;
        }

        uint64_t seg_start = current->start_ns;
    uint64_t seg_len_ns = (uint64_t)seg_seconds * 1000000000ULL;
        if (frame.timestamp_ns - seg_start >= seg_len_ns) {
            current->finish(camera_id, config_.bundle);
            bundles.push_back(current->bundle_dir);
            current = std::make_unique<SegmentWriter>();
            current->init(out_dir, camera_id, frame.width, frame.height, frame.fps_num, frame.fps_den,
                          frame.timestamp_ns, (uint64_t)seg_seconds * 1000000000ULL, config_.bundle, seal_cb);
            last_pts_ns = 0;
        }

        uint64_t dur_ns = (uint64_t)1000000000ULL * frame.fps_den / frame.fps_num;
        uint64_t pts_ns = 0;
        if (frame.timestamp_ns >= current->start_ns) {
            pts_ns = frame.timestamp_ns - current->start_ns;
        }
        if (pts_ns <= last_pts_ns) {
            pts_ns = last_pts_ns + dur_ns;
        }
        last_pts_ns = pts_ns;

        current->push(frame.bgr, pts_ns, dur_ns, frame.timestamp_ns);
    }

    if (current) {
        current->finish(camera_id, config_.bundle);
        bundles.push_back(current->bundle_dir);
    }

    overall_progress.finish(frames.size());

    return bundles;
}

std::vector<fs::path> SecureSave::encrypt_stream(const FrameSource& next_frame,
                                                  const fs::path& out_dir,
                                                  const std::string& camera_id,
                                                  int segment_seconds) {
    std::vector<fs::path> bundles;
    if (!next_frame) return bundles;

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

    int seg_seconds = segment_seconds > 0 ? segment_seconds : config_.segment_seconds;
    if (seg_seconds <= 0) seg_seconds = 600;

    std::unique_ptr<SegmentWriter> current;
    uint64_t last_pts_ns = 0;

    auto seal_cb = [this](const std::vector<uint8_t>& key,
                          const fs::path& key_prefix,
                          const fs::path& primary_ctx) {
        return this->tpm_seal(key, key_prefix, primary_ctx);
    };

    FramePacket frame;
    bool has_any = false;
    while (next_frame(frame)) {
        if (frame.bgr.empty()) {
            continue;
        }
        has_any = true;

        if (!current) {
            current = std::make_unique<SegmentWriter>();
            current->init(out_dir, camera_id, frame.width, frame.height, frame.fps_num, frame.fps_den,
                          frame.timestamp_ns, (uint64_t)seg_seconds * 1000000000ULL, config_.bundle, seal_cb);
            last_pts_ns = 0;
        }

        uint64_t seg_start = current->start_ns;
        uint64_t seg_len_ns = (uint64_t)seg_seconds * 1000000000ULL;
        if (frame.timestamp_ns - seg_start >= seg_len_ns) {
            current->finish(camera_id, config_.bundle);
            bundles.push_back(current->bundle_dir);
            current = std::make_unique<SegmentWriter>();
            current->init(out_dir, camera_id, frame.width, frame.height, frame.fps_num, frame.fps_den,
                          frame.timestamp_ns, (uint64_t)seg_seconds * 1000000000ULL, config_.bundle, seal_cb);
            last_pts_ns = 0;
        }

        uint64_t dur_ns = (uint64_t)1000000000ULL * frame.fps_den / frame.fps_num;
        uint64_t pts_ns = 0;
        if (frame.timestamp_ns >= current->start_ns) {
            pts_ns = frame.timestamp_ns - current->start_ns;
        }
        if (pts_ns <= last_pts_ns) {
            pts_ns = last_pts_ns + dur_ns;
        }
        last_pts_ns = pts_ns;

        current->push(frame.bgr, pts_ns, dur_ns, frame.timestamp_ns);
    }

    if (!has_any) {
        return bundles;
    }

    if (current) {
        current->finish(camera_id, config_.bundle);
        bundles.push_back(current->bundle_dir);
    }

    return bundles;
}

std::map<std::string, fs::path> SecureSave::decrypt(const fs::path& bundle_root,
                                                    const fs::path& response_dir,
                                                    uint64_t start_ms,
                                                    uint64_t end_ms,
                                                    const std::string& view) {
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
    auto unseal_cb = [this](const fs::path& key_prefix,
                            const fs::path& primary_ctx,
                            const std::optional<fs::path>& policy_file,
                            const std::optional<fs::path>& signer_pub_copy) {
        return this->tpm_unseal(key_prefix, primary_ctx, policy_file, signer_pub_copy);
    };

    for (const auto& seg : segments) {
        json meta;
        { std::ifstream ifs(seg.meta_path); ifs >> meta; }

        uint64_t cipher_bytes = meta.value("ciphertext_bytes", 0ULL);
        uint64_t plain_bytes = meta.value("plaintext_bytes", 0ULL);
        if (cipher_bytes == 0 || plain_bytes == 0) {
            continue;
        }

        uint64_t fps_num = meta.value("fps_num", 30ULL);
        uint64_t fps_den = meta.value("fps_den", 1ULL);
        if (fps_num == 0) fps_num = 30;
        if (fps_den == 0) fps_den = 1;
        uint64_t frame_duration_ns = 1000000000ULL * fps_den / fps_num;

        fs::path dec_path = decrypt_segment_to_tmp(seg.meta_path, config_.bundle, tmp_dir, unseal_cb);

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

        fs::path slice_path = response_dir / (seg.meta_path.stem().string() + "_slice.mp4");
        ffmpeg_slice(dec_path, slice_path, slice_start, slice_end);

        std::error_code ec;
        fs::remove(dec_path, ec);

        if (ec || !fs::exists(slice_path)) {
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
        if (kv.second.size() == 1) {
            outputs[kv.first] = kv.second.front();
        } else {
            fs::path final_path = response_dir / ("merged_" + kv.first + "_" + now_ts_name() + ".mp4");
            ffmpeg_concat(kv.second, final_path, tmp_dir);
            for (const auto& p : kv.second) {
                std::error_code ec;
                fs::remove(p, ec);
            }
            outputs[kv.first] = final_path;
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
