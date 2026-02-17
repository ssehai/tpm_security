#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

struct UnifiedBuffer;
struct TrackingBuffer;

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
    struct StorageConfig {
        bool hot_enabled = true;
        bool cold_enabled = true;
        int hot_segment_seconds = 1;
        int cold_segment_seconds = 60;
        int hot_retention_hours = 2;
        int cold_retention_days = 30;
        std::filesystem::path hot_dir = "hot";
        std::filesystem::path cold_dir = "cold";
    } storage;
    struct RoiMaskConfig {
        enum class FailPolicy { FailOpen, FailClose, FailHard };
        bool enabled = true;
        bool merge_overlaps = true;
        bool strict_stride_check = true;
        bool write_sidecar = true;
        bool unmask_on_decrypt = false;
        FailPolicy missing_roi_policy = FailPolicy::FailOpen;
        FailPolicy mask_error_policy = FailPolicy::FailHard;
    } roi_mask;
    struct TrackConfig {
        bool enabled = true;
        bool write_header = true;
        bool include_empty_frames = true;
    } track;
};

struct FrameBox {
    int32_t x1 = 0;
    int32_t y1 = 0;
    int32_t x2 = 0;
    int32_t y2 = 0;
    int32_t track_id = -1;
};

struct FramePacket {
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t fps_num = 30;
    uint32_t fps_den = 1;
    uint64_t timestamp_ns = 0;
    std::vector<uint8_t> rgb;
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

std::vector<FrameBox> build_track_boxes_from_tracking(const std::vector<TrackingBuffer>& tracking_buffers,
                                                      uint32_t width,
                                                      uint32_t height);

FramePacket build_frame_packet_from_unified(const ::UnifiedBuffer& unified,
                                            const std::vector<TrackingBuffer>& tracking_buffers,
                                            uint64_t timestamp_ns,
                                            uint32_t fps_num,
                                            uint32_t fps_den);

}  // namespace secure_save
