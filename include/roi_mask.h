#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace secure_save {

struct RoiBox {
    int32_t x = 0;
    int32_t y = 0;
    int32_t w = 0;
    int32_t h = 0;
    int32_t id = -1;
};

struct RoiMaskerOptions {
    bool strict_stride_check = true;
};

class RoiMasker {
public:
    explicit RoiMasker(RoiMaskerOptions options = {});

    void BeginSegment(const uint8_t* master_key, size_t key_len);
    void BeginSegmentWithSalt(const uint8_t* master_key,
                              size_t key_len,
                              const std::vector<uint8_t>& video_salt);
    std::vector<uint8_t> GetVideoSalt() const;

    static std::vector<RoiBox> NormalizeBoxes(const std::vector<RoiBox>& boxes,
                                              uint32_t width,
                                              uint32_t height,
                                              uint32_t stride,
                                              const RoiMaskerOptions& options);

    void MaskRgbFrameInPlace(uint8_t* frame,
                             uint32_t width,
                             uint32_t height,
                             uint32_t stride,
                             uint64_t frame_index,
                             const std::vector<RoiBox>& boxes);

    void mask(uint8_t* frame,
              uint32_t width,
              uint32_t height,
              uint32_t stride,
              uint64_t frame_index,
              const std::vector<RoiBox>& boxes);

    void unmask(uint8_t* frame,
                uint32_t width,
                uint32_t height,
                uint32_t stride,
                uint64_t frame_index,
                const std::vector<RoiBox>& boxes);

    void MaskRgbFrameInPlaceNormalized(uint8_t* frame,
                                       uint32_t width,
                                       uint32_t height,
                                       uint32_t stride,
                                       uint64_t frame_index,
                                       const std::vector<RoiBox>& boxes);

    void Clear();
    ~RoiMasker();

private:
    RoiMaskerOptions options_;
    std::vector<uint8_t> video_salt_;
    std::vector<uint8_t> key_seg_;
};

class IRoiMetadataSink {
public:
    virtual ~IRoiMetadataSink() = default;

    virtual void OnSegmentBegin(const std::string& segment_name,
                                const std::vector<uint8_t>& video_salt,
                                uint32_t width,
                                uint32_t height,
                                uint32_t fps_num,
                                uint32_t fps_den) = 0;

    virtual void OnFrame(uint64_t frame_index, const std::vector<RoiBox>& boxes) = 0;
    virtual void OnSegmentEnd() = 0;
};

class RoiMetadataJsonlWriter : public IRoiMetadataSink {
public:
    explicit RoiMetadataJsonlWriter(const std::filesystem::path& path);

    void OnSegmentBegin(const std::string& segment_name,
                        const std::vector<uint8_t>& video_salt,
                        uint32_t width,
                        uint32_t height,
                        uint32_t fps_num,
                        uint32_t fps_den) override;

    void OnFrame(uint64_t frame_index, const std::vector<RoiBox>& boxes) override;
    void OnSegmentEnd() override;

private:
    std::ofstream out_;
    std::string algo_ = "aes-256-ctr";
    std::string iv_scheme_ = "sha256(salt|frame|roi)";
};

}  // namespace secure_save
