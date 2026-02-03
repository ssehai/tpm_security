#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace secure_save {

struct PolicyConfig {
    bool enabled = false;
    std::filesystem::path signer_pub;
    std::string server_url;
};

struct BundleConfig {
    size_t chunk_size = 4 * 1024 * 1024;
    PolicyConfig policy;
};

struct SecureSaveConfig {
    BundleConfig bundle;
    std::string object_auth;
    int segment_seconds = 600;
};

struct FrameBox {
    int32_t x1 = 0;
    int32_t y1 = 0;
    int32_t x2 = 0;
    int32_t y2 = 0;
};

struct FramePacket {
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t fps_num = 30;
    uint32_t fps_den = 1;
    uint64_t timestamp_ns = 0;
    std::vector<uint8_t> bgr;
    std::vector<FrameBox> boxes;
};

using FrameSource = std::function<bool(FramePacket&)>;

struct SealArtifacts {
    std::optional<std::filesystem::path> policy_file;
    std::optional<std::filesystem::path> signer_pub_copy;
};

class SecureSave {
public:
    explicit SecureSave(SecureSaveConfig config);

    // Usage example:
    //   secure_save::SecureSaveConfig cfg;
    //   cfg.bundle.policy.server_url = "http://127.0.0.1:8102/approve";
    //   cfg.bundle.policy.signer_pub = "test_results/policy_keys/signer.pub";
    //   cfg.bundle.policy.enabled = true;
    //   secure_save::SecureSave saver(cfg);
    //   auto bundles = saver.encrypt(frames, "bundles_out", "cam1", 20);
    //   auto outputs = saver.decrypt("bundles_out", "/dev/shm/tpm_responses", start_ms, end_ms, "both");

    std::vector<std::filesystem::path> encrypt(const std::vector<FramePacket>& frames,
                                               const std::filesystem::path& out_dir,
                                               const std::string& camera_id,
                                               int segment_seconds);

    std::vector<std::filesystem::path> encrypt_stream(const FrameSource& next_frame,
                                                      const std::filesystem::path& out_dir,
                                                      const std::string& camera_id,
                                                      int segment_seconds);

    std::map<std::string, std::filesystem::path> decrypt(const std::filesystem::path& bundle_root,
                                                        const std::filesystem::path& response_dir,
                                                        uint64_t start_ms,
                                                        uint64_t end_ms,
                                                        const std::string& view);

private:
    SealArtifacts tpm_seal(const std::vector<uint8_t>& key32,
                           const std::filesystem::path& key_prefix,
                           const std::filesystem::path& primary_ctx);

    std::vector<uint8_t> tpm_unseal(const std::filesystem::path& key_prefix,
                                    const std::filesystem::path& primary_ctx,
                                    const std::optional<std::filesystem::path>& policy_file,
                                    const std::optional<std::filesystem::path>& signer_pub_copy);

    SecureSaveConfig config_;
};

}  // namespace secure_save
