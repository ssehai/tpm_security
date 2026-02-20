#include "roi_mask.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <stdexcept>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <nlohmann/json.hpp>

namespace secure_save {

namespace {

constexpr size_t kSaltLen = 12;
constexpr size_t kKeyLen = 32;
constexpr size_t kIvLen = 16;
constexpr const char* kHkdfInfo = "roi-bgr-ctr-v1";

static void write_be32(uint8_t* out, uint32_t v) {
    out[0] = static_cast<uint8_t>((v >> 24) & 0xff);
    out[1] = static_cast<uint8_t>((v >> 16) & 0xff);
    out[2] = static_cast<uint8_t>((v >> 8) & 0xff);
    out[3] = static_cast<uint8_t>(v & 0xff);
}

static void write_be64(uint8_t* out, uint64_t v) {
    out[0] = static_cast<uint8_t>((v >> 56) & 0xff);
    out[1] = static_cast<uint8_t>((v >> 48) & 0xff);
    out[2] = static_cast<uint8_t>((v >> 40) & 0xff);
    out[3] = static_cast<uint8_t>((v >> 32) & 0xff);
    out[4] = static_cast<uint8_t>((v >> 24) & 0xff);
    out[5] = static_cast<uint8_t>((v >> 16) & 0xff);
    out[6] = static_cast<uint8_t>((v >> 8) & 0xff);
    out[7] = static_cast<uint8_t>(v & 0xff);
}

static std::vector<uint8_t> hkdf_sha256(const uint8_t* ikm,
                                        size_t ikm_len,
                                        const uint8_t* salt,
                                        size_t salt_len,
                                        const uint8_t* info,
                                        size_t info_len,
                                        size_t out_len) {
    std::vector<uint8_t> out(out_len, 0);
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) throw std::runtime_error("HKDF ctx create failed");

    if (EVP_PKEY_derive_init(pctx) != 1) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("HKDF derive init failed");
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) != 1) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("HKDF set md failed");
    }
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len) != 1) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("HKDF set salt failed");
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)ikm_len) != 1) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("HKDF set key failed");
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)info_len) != 1) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("HKDF set info failed");
    }

    size_t len = out_len;
    if (EVP_PKEY_derive(pctx, out.data(), &len) != 1 || len != out_len) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("HKDF derive failed");
    }
    EVP_PKEY_CTX_free(pctx);
    return out;
}

static bool boxes_overlap(const RoiBox& a, const RoiBox& b) {
    int32_t ax0 = a.x;
    int32_t ay0 = a.y;
    int32_t ax1 = a.x + a.w;
    int32_t ay1 = a.y + a.h;
    int32_t bx0 = b.x;
    int32_t by0 = b.y;
    int32_t bx1 = b.x + b.w;
    int32_t by1 = b.y + b.h;
    return ax0 <= bx1 && ax1 >= bx0 && ay0 <= by1 && ay1 >= by0;
}

static RoiBox merge_boxes(const RoiBox& a, const RoiBox& b) {
    int32_t x0 = std::min(a.x, b.x);
    int32_t y0 = std::min(a.y, b.y);
    int32_t x1 = std::max(a.x + a.w, b.x + b.w);
    int32_t y1 = std::max(a.y + a.h, b.y + b.h);
    return RoiBox{x0, y0, x1 - x0, y1 - y0, -1};
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

}  // namespace

RoiMasker::RoiMasker(RoiMaskerOptions options)
    : options_(options) {}

void RoiMasker::BeginSegment(const uint8_t* master_key, size_t key_len) {
    if (!master_key || key_len != kKeyLen) {
        throw std::runtime_error("BeginSegment requires 32-byte master key");
    }
    video_salt_.assign(kSaltLen, 0);
    if (RAND_bytes(video_salt_.data(), (int)video_salt_.size()) != 1) {
        throw std::runtime_error("RAND_bytes failed for video_salt");
    }
    key_seg_ = hkdf_sha256(master_key, key_len,
                           video_salt_.data(), video_salt_.size(),
                           reinterpret_cast<const uint8_t*>(kHkdfInfo),
                           std::strlen(kHkdfInfo),
                           kKeyLen);
}

void RoiMasker::BeginSegmentWithSalt(const uint8_t* master_key,
                                     size_t key_len,
                                     const std::vector<uint8_t>& video_salt) {
    if (!master_key || key_len != kKeyLen) {
        throw std::runtime_error("BeginSegmentWithSalt requires 32-byte master key");
    }
    if (video_salt.size() != kSaltLen) {
        throw std::runtime_error("BeginSegmentWithSalt requires 12-byte video salt");
    }
    video_salt_ = video_salt;
    key_seg_ = hkdf_sha256(master_key, key_len,
                           video_salt_.data(), video_salt_.size(),
                           reinterpret_cast<const uint8_t*>(kHkdfInfo),
                           std::strlen(kHkdfInfo),
                           kKeyLen);
}

std::vector<uint8_t> RoiMasker::GetVideoSalt() const {
    return video_salt_;
}

std::vector<RoiBox> RoiMasker::NormalizeBoxes(const std::vector<RoiBox>& boxes,
                                              uint32_t width,
                                              uint32_t height,
                                              uint32_t stride,
                                              const RoiMaskerOptions& options) {
    std::vector<RoiBox> out;
    out.reserve(boxes.size());
    int32_t w = static_cast<int32_t>(width);
    int32_t h = static_cast<int32_t>(height);

    for (const auto& box : boxes) {
        int32_t x0 = box.x;
        int32_t y0 = box.y;
        int32_t x1 = box.x + box.w;
        int32_t y1 = box.y + box.h;

        int32_t cx0 = std::max<int32_t>(0, x0);
        int32_t cy0 = std::max<int32_t>(0, y0);
        int32_t cx1 = std::min<int32_t>(w, x1);
        int32_t cy1 = std::min<int32_t>(h, y1);

        int32_t cw = cx1 - cx0;
        int32_t ch = cy1 - cy0;
        if (cw <= 0 || ch <= 0) {
            continue;
        }

        int64_t x_bytes = static_cast<int64_t>(cx0) * 3;
        int64_t w_bytes = static_cast<int64_t>(cw) * 3;
        if (x_bytes + w_bytes > static_cast<int64_t>(stride)) {
            if (options.strict_stride_check) {
                throw std::runtime_error("ROI exceeds stride");
            }
            continue;
        }
        out.push_back(RoiBox{cx0, cy0, cw, ch, box.id});
    }

    std::sort(out.begin(), out.end(), [](const RoiBox& a, const RoiBox& b) {
        if (a.y != b.y) return a.y < b.y;
        if (a.x != b.x) return a.x < b.x;
        if (a.h != b.h) return a.h < b.h;
        return a.w < b.w;
    });

    if (out.empty()) {
        return out;
    }

    std::vector<RoiBox> merged;
    for (const auto& box : out) {
        bool did_merge = false;
        for (auto& m : merged) {
            if (boxes_overlap(m, box)) {
                m = merge_boxes(m, box);
                did_merge = true;
                break;
            }
        }
        if (!did_merge) {
            merged.push_back(box);
        }
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (size_t i = 0; i < merged.size(); ++i) {
            for (size_t j = i + 1; j < merged.size(); ++j) {
                if (boxes_overlap(merged[i], merged[j])) {
                    merged[i] = merge_boxes(merged[i], merged[j]);
                    merged.erase(merged.begin() + static_cast<long>(j));
                    changed = true;
                    break;
                }
            }
            if (changed) break;
        }
    }

    std::sort(merged.begin(), merged.end(), [](const RoiBox& a, const RoiBox& b) {
        if (a.y != b.y) return a.y < b.y;
        if (a.x != b.x) return a.x < b.x;
        if (a.h != b.h) return a.h < b.h;
        return a.w < b.w;
    });

    return merged;
}

void RoiMasker::MaskRgbFrameInPlace(uint8_t* frame,
                                    uint32_t width,
                                    uint32_t height,
                                    uint32_t stride,
                                    uint64_t frame_index,
                                    const std::vector<RoiBox>& boxes) {
    auto normalized = NormalizeBoxes(boxes, width, height, stride, options_);
    MaskRgbFrameInPlaceNormalized(frame, width, height, stride, frame_index, normalized);
}

void RoiMasker::mask(uint8_t* frame,
                     uint32_t width,
                     uint32_t height,
                     uint32_t stride,
                     uint64_t frame_index,
                     const std::vector<RoiBox>& boxes) {
    MaskRgbFrameInPlace(frame, width, height, stride, frame_index, boxes);
}

void RoiMasker::unmask(uint8_t* frame,
                       uint32_t width,
                       uint32_t height,
                       uint32_t stride,
                       uint64_t frame_index,
                       const std::vector<RoiBox>& boxes) {
    MaskRgbFrameInPlace(frame, width, height, stride, frame_index, boxes);
}

void RoiMasker::MaskRgbFrameInPlaceNormalized(uint8_t* frame,
                                              uint32_t width,
                                              uint32_t height,
                                              uint32_t stride,
                                              uint64_t frame_index,
                                              const std::vector<RoiBox>& boxes) {
    if (!frame) throw std::runtime_error("Frame pointer is null");
    if (key_seg_.size() != kKeyLen) throw std::runtime_error("Segment key missing");
    if (video_salt_.size() != kSaltLen) throw std::runtime_error("Video salt missing");
    if (boxes.empty()) return;

    for (uint32_t roi_index = 0; roi_index < boxes.size(); ++roi_index) {
        const auto& box = boxes[roi_index];

        std::array<uint8_t, kSaltLen + 8 + 4> input{};
        std::memcpy(input.data(), video_salt_.data(), kSaltLen);
        write_be64(input.data() + kSaltLen, frame_index);
        write_be32(input.data() + kSaltLen + 8, roi_index);

        std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
        SHA256(input.data(), input.size(), digest.data());

        std::array<uint8_t, kIvLen> iv{};
        std::memcpy(iv.data(), digest.data(), kIvLen);

        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
            EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_ctr(), nullptr,
                               key_seg_.data(), iv.data()) != 1) {
            throw std::runtime_error("EVP_EncryptInit_ex failed");
        }

        for (int32_t r = 0; r < box.h; ++r) {
            size_t row_off = static_cast<size_t>(box.y + r) * stride +
                             static_cast<size_t>(box.x) * 3;
            uint8_t* row_ptr = frame + row_off;
            int len = box.w * 3;
            int outlen = 0;
            if (EVP_EncryptUpdate(ctx.get(), row_ptr, &outlen, row_ptr, len) != 1) {
                throw std::runtime_error("EVP_EncryptUpdate failed");
            }
            if (outlen != len) {
                throw std::runtime_error("Unexpected CTR output length");
            }
        }

        unsigned char final_buf[16];
        int final_len = 0;
        if (EVP_EncryptFinal_ex(ctx.get(), final_buf, &final_len) != 1) {
            throw std::runtime_error("EVP_EncryptFinal_ex failed");
        }
    }
    (void)width;
    (void)height;
}

void RoiMasker::Clear() {
    if (!key_seg_.empty()) {
        OPENSSL_cleanse(key_seg_.data(), key_seg_.size());
        key_seg_.clear();
    }
    video_salt_.clear();
}

RoiMasker::~RoiMasker() {
    Clear();
}

RoiMetadataJsonlWriter::RoiMetadataJsonlWriter(const std::filesystem::path& path) {
    out_.open(path, std::ios::out | std::ios::trunc);
    if (!out_) {
        throw std::runtime_error("Failed to open ROI sidecar");
    }
}

void RoiMetadataJsonlWriter::OnSegmentBegin(const std::string& segment_name,
                                            const std::vector<uint8_t>& video_salt,
                                            uint32_t width,
                                            uint32_t height,
                                            uint32_t fps_num,
                                            uint32_t fps_den) {
    nlohmann::ordered_json header = nlohmann::ordered_json::object();
    header["type"] = "header";
    header["segment"] = segment_name;
    header["algo"] = algo_;
    header["iv_scheme"] = iv_scheme_;
    header["salt_b64"] = b64e(video_salt);
    header["w"] = width;
    header["h"] = height;
    header["fps_num"] = fps_num;
    header["fps_den"] = fps_den;
    out_ << header.dump() << "\n";
}

void RoiMetadataJsonlWriter::OnFrame(uint64_t frame_index, const std::vector<RoiBox>& boxes) {
    nlohmann::ordered_json frame = nlohmann::ordered_json::object();
    frame["type"] = "frame";
    frame["i"] = frame_index;
    nlohmann::ordered_json arr = nlohmann::ordered_json::array();
    for (const auto& box : boxes) {
        nlohmann::ordered_json b = nlohmann::ordered_json::object();
        b["id"] = box.id;
        b["h"] = box.h;
        b["w"] = box.w;
        b["x"] = box.x;
        b["y"] = box.y;
        arr.push_back(std::move(b));
    }
    frame["boxes"] = std::move(arr);
    out_ << frame.dump() << "\n";
}

void RoiMetadataJsonlWriter::OnSegmentEnd() {
    out_.flush();
}

}  // namespace secure_save
