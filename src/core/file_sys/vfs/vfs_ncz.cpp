// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/file_sys/vfs/vfs_ncz.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <zstd.h>
#include <openssl/evp.h>

#include "common/assert.h"
#include "common/logging.h"
#include "common/string_util.h"

namespace FileSys {

// ============================================================
// 내부 유틸리티
// ============================================================

namespace {

/// AES-128-CTR 카운터를 NCA 오프셋에 맞게 업데이트
/// C# UpdateCounter 로직과 동일 (Aes128CtrTransformExtension.cs 참조)
void UpdateAesCtrCounter(std::array<u8, 16>& counter, s64 offset) {
    u64 off = static_cast<u64>(offset) >> 4;
    for (u32 j = 0; j < 7; j++) {
        counter[0x10 - j - 1] = static_cast<u8>(off & 0xFF);
        off >>= 8;
    }
    // 바이트 8의 상위 4비트 보존
    counter[8] = static_cast<u8>((counter[8] & 0xF0) | static_cast<int>(off & 0x0F));
}

/// 간단한 AES-128-CTR XOR 변환
/// Eden 내부에 AesCtrStorage가 있으므로 실제 통합 시 그쪽을 사용하는 것을 권장.
/// 여기서는 OpenSSL EVP를 직접 사용하여 의존성을 최소화.
void ApplyAesCtr(u8* data, std::size_t length,
                 const std::array<u8, 16>& key,
                 const std::array<u8, 16>& counter_in) {
    if (length == 0) return;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return;

    // OpenSSL AES-128-CTR 초기화
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key.data(), counter_in.data());

    int out_len = 0;
    EVP_EncryptUpdate(ctx, data, &out_len, data, static_cast<int>(length));

    EVP_CIPHER_CTX_free(ctx);
}

/// NCZ 헤더 파싱
/// C# NczHeader::Read() 대응
std::optional<NczParsedHeader> ParseNczHeader(const VirtualFile& file) {
    if (!file) return std::nullopt;

    const auto file_size = static_cast<s64>(file->GetSize());
    if (file_size < static_cast<s64>(NCZ_NCA_HEADER_SIZE) + 8 + 8) {
        LOG_ERROR(Loader, "NSZ file too small: {} bytes", file_size);
        return std::nullopt;
    }

    NczParsedHeader hdr;

    // 1) NCA 헤더 읽기 (0x4000 바이트)
    const auto nca_hdr_read = file->Read(hdr.nca_header_bytes.data(),
                                          NCZ_NCA_HEADER_SIZE, 0);
    if (nca_hdr_read != NCZ_NCA_HEADER_SIZE) {
        LOG_ERROR(Loader, "Failed to read NCA header from NSZ");
        return std::nullopt;
    }

    s64 pos = static_cast<s64>(NCZ_NCA_HEADER_SIZE);

    // 2) "NCZSECTN" 매직 확인
    {
        char magic[8];
        if (file->Read(reinterpret_cast<u8*>(magic), 8, pos) != 8) return std::nullopt;
        if (std::string_view(magic, 8) != NCZ_SECTION_MAGIC) {
            LOG_ERROR(Loader, "NSZ: NCZSECTN magic not found at offset 0x{:X}", pos);
            return std::nullopt;
        }
        pos += 8;
    }

    // 3) 섹션 카운트 읽기
    s64 section_count = 0;
    if (file->Read(reinterpret_cast<u8*>(&section_count), 8, pos) != 8) return std::nullopt;
    pos += 8;

    if (section_count <= 0 || section_count > 32) {
        LOG_ERROR(Loader, "NSZ: invalid section count {}", section_count);
        return std::nullopt;
    }

    // 4) 섹션 목록 읽기
    hdr.sections.resize(static_cast<std::size_t>(section_count));
    for (s64 i = 0; i < section_count; i++) {
        if (file->Read(reinterpret_cast<u8*>(&hdr.sections[i]),
                       sizeof(NczSectionEntry), pos) != sizeof(NczSectionEntry)) {
            LOG_ERROR(Loader, "NSZ: failed to read section {}", i);
            return std::nullopt;
        }
        pos += static_cast<s64>(sizeof(NczSectionEntry));
    }

    // NCA 총 크기 계산: 마지막 섹션의 끝 오프셋
    if (!hdr.sections.empty()) {
        const auto& last = hdr.sections.back();
        hdr.nca_size = last.offset + last.size;
    } else {
        hdr.nca_size = static_cast<s64>(NCZ_NCA_HEADER_SIZE);
    }

    // 5) 블록 압축 매직 확인 (선택적)
    {
        char magic[8];
        if (file->Read(reinterpret_cast<u8*>(magic), 8, pos) != 8) {
            // 파일 끝 → 블록 없는 스트림 압축
            hdr.compression_start_offset = pos;
            return hdr;
        }

        if (std::string_view(magic, 8) == NCZ_BLOCK_MAGIC) {
            pos += 8;

            // 블록 헤더 읽기
            if (file->Read(reinterpret_cast<u8*>(&hdr.block_header),
                           sizeof(NczBlockHeader), pos) != sizeof(NczBlockHeader)) {
                LOG_ERROR(Loader, "NSZ: failed to read block header");
                return std::nullopt;
            }
            pos += static_cast<s64>(sizeof(NczBlockHeader));

            hdr.has_block_compression = true;

            // 블록별 압축 크기 배열
            const int num_blocks = hdr.block_header.number_of_blocks;
            if (num_blocks <= 0 || num_blocks > 0x100000) {
                LOG_ERROR(Loader, "NSZ: invalid block count {}", num_blocks);
                return std::nullopt;
            }
            hdr.compressed_block_sizes.resize(static_cast<std::size_t>(num_blocks));
            const std::size_t block_sizes_bytes =
                static_cast<std::size_t>(num_blocks) * sizeof(s32);
            if (file->Read(reinterpret_cast<u8*>(hdr.compressed_block_sizes.data()),
                           block_sizes_bytes, pos) != block_sizes_bytes) {
                LOG_ERROR(Loader, "NSZ: failed to read block sizes");
                return std::nullopt;
            }
            pos += static_cast<s64>(block_sizes_bytes);
            hdr.compression_start_offset = pos;
        } else {
            // 매직이 NCZBLOCK이 아님 → 스트림 압축, 현재 위치 되돌리기
            hdr.compression_start_offset = pos; // magic 8바이트는 이미 소비됨
            // 실제로는 magic을 이미 읽었으므로 pos - 8이 압축 시작점
            hdr.compression_start_offset = pos - 8;
        }
    }

    if (!hdr.has_block_compression) {
        LOG_ERROR(Loader, "NSZ: Blockless compression is not supported. File: {}", file->GetName());
        return std::nullopt;
    }

    return hdr;
}

/// 블록 목록 사전 계산
std::vector<NczVfsFile::BlockInfo> BuildBlockList(const NczParsedHeader& hdr) {
    std::vector<NczVfsFile::BlockInfo> blocks;
    if (!hdr.has_block_compression) return blocks;

    const u8 exp = hdr.block_header.block_size_exponent;
    if (exp < 14 || exp > 32) {
        LOG_ERROR(Loader, "NSZ: invalid block_size_exponent {}", exp);
        return blocks;
    }

    const s64 decompressed_block_size = 1LL << exp;
    const s64 total_decompressed = hdr.block_header.decompressed_size;
    const s64 last_decompressed_offset = total_decompressed - 1;

    s64 compressed_offset = hdr.compression_start_offset;
    s64 decompressed_offset = 0;

    const int num_blocks = static_cast<int>(hdr.compressed_block_sizes.size());
    blocks.reserve(static_cast<std::size_t>(num_blocks));

    for (int i = 0; i < num_blocks; i++) {
        const s32 compressed_size = hdr.compressed_block_sizes[i];
        if (compressed_size <= 0) {
            LOG_ERROR(Loader, "NSZ: compressed block size {} at index {}", compressed_size, i);
            break;
        }

        s64 cur_decompressed_block_size = decompressed_block_size;
        s64 decompressed_offset_end = decompressed_offset + decompressed_block_size - 1;

        if (i == num_blocks - 1) {
            // 마지막 블록: 실제 끝 오프셋으로 조정
            decompressed_offset_end = last_decompressed_offset;
            cur_decompressed_block_size = last_decompressed_offset - decompressed_offset + 1;
        }

        NczVfsFile::BlockInfo bi;
        bi.index                      = i;
        bi.decompressed_offset_start  = decompressed_offset;
        bi.decompressed_offset_end    = decompressed_offset_end;
        bi.decompressed_block_size    = cur_decompressed_block_size;
        bi.compressed_offset_start    = compressed_offset;
        bi.is_compressed              = (compressed_size < cur_decompressed_block_size);
        blocks.push_back(bi);

        decompressed_offset += decompressed_block_size;
        compressed_offset   += compressed_size;
    }

    return blocks;
}

} // namespace

// ============================================================
// NczVfsFile 구현
// ============================================================

std::shared_ptr<NczVfsFile> NczVfsFile::Make(VirtualFile nsz_file) {
    if (!nsz_file) return nullptr;

    auto hdr_opt = ParseNczHeader(nsz_file);
    if (!hdr_opt) {
        LOG_ERROR(Loader, "Failed to parse NCZ header: {}", nsz_file->GetName());
        return nullptr;
    }

    return std::shared_ptr<NczVfsFile>(
        new NczVfsFile(std::move(nsz_file), std::move(*hdr_opt)));
}

NczVfsFile::NczVfsFile(VirtualFile nsz_file, NczParsedHeader header)
    : m_nsz_file(std::move(nsz_file)), m_header(std::move(header)) {

    // 고유 ID 발급: 정적 원자 카운터로 각 인스턴스를 구별한다.
    // raw pointer 재사용에 의한 thread_local 캐시 오염(UAF)을 방지한다.
    static std::atomic<uintptr_t> s_id_counter{1};
    m_instance_id = s_id_counter.fetch_add(1, std::memory_order_relaxed);

    // 파일명 .nsz → .nca 변환
    m_name = m_nsz_file->GetName();
    const auto dot = m_name.rfind('.');
    if (dot != std::string::npos) {
        m_name = m_name.substr(0, dot) + ".nca";
    }

    // 블록 목록 사전 계산
    if (m_header.has_block_compression) {
        m_blocks = BuildBlockList(m_header);
        m_block_cache.resize(MAX_CACHE_BLOCKS);
    }
}

NczVfsFile::~NczVfsFile() = default;

std::string NczVfsFile::GetName() const { return m_name; }
std::size_t NczVfsFile::GetSize() const { return static_cast<std::size_t>(m_header.nca_size); }
bool NczVfsFile::Resize(std::size_t) { return false; }
bool NczVfsFile::IsWritable() const { return false; }
bool NczVfsFile::IsReadable() const { return true; }

VirtualDir NczVfsFile::GetContainingDirectory() const {
    return m_nsz_file->GetContainingDirectory();
}

bool NczVfsFile::Rename(std::string_view name) {
    m_name = std::string(name);
    return true;
}

std::vector<u8> NczVfsFile::ReadBytes(std::size_t size, std::size_t offset) const {
    std::vector<u8> buf(size);
    const auto read = Read(buf.data(), size, offset);
    buf.resize(read);
    return buf;
}

std::size_t NczVfsFile::Write(const u8*, std::size_t, std::size_t) { return 0; }

std::size_t NczVfsFile::Read(u8* data, std::size_t length, std::size_t offset) const {
    if (!data || length == 0) return 0;

    const s64 nca_size = m_header.nca_size;
    const s64 read_start = static_cast<s64>(offset);
    const s64 read_end   = read_start + static_cast<s64>(length);

    if (read_start >= nca_size) return 0;

    const s64 clamped_end = std::min(read_end, nca_size);
    std::size_t bytes_written = 0;

    // ── 헤더 영역 (0 ~ 0x4000) ──────────────────────────────────
    if (read_start < static_cast<s64>(NCZ_NCA_HEADER_SIZE)) {
        const s64 hdr_read_start = read_start;
        const s64 hdr_read_end   = std::min(clamped_end,
                                             static_cast<s64>(NCZ_NCA_HEADER_SIZE));
        const std::size_t hdr_len = static_cast<std::size_t>(hdr_read_end - hdr_read_start);

        std::memcpy(data, m_header.nca_header_bytes.data() + hdr_read_start, hdr_len);
        bytes_written += hdr_len;
    }

    // ── 압축 데이터 영역 (0x4000 ~) ────────────────────────────
    if (clamped_end > static_cast<s64>(NCZ_NCA_HEADER_SIZE)) {
        const s64 data_start = std::max(read_start,
                                         static_cast<s64>(NCZ_NCA_HEADER_SIZE));
        const s64 data_end   = clamped_end;
        const std::size_t data_len = static_cast<std::size_t>(data_end - data_start);

        u8* dst = data + (data_start - read_start);
        const s64 decomp_offset = data_start - static_cast<s64>(NCZ_NCA_HEADER_SIZE);

        const std::size_t decomp_read = ReadDecompressed(dst, data_len, decomp_offset);
        if (decomp_read > 0) {
            // AES-CTR 복원 (nca_offset = data_start, 헤더 포함 절대 오프셋)
            ReEncrypt(dst, decomp_read, data_start);
        }
        bytes_written += decomp_read;
    }

    return bytes_written;
}

// ============================================================
// 압축 해제
// ============================================================

std::size_t NczVfsFile::ReadDecompressed(u8* buf, std::size_t length,
                                          s64 decompressed_offset) const {
    if (m_header.has_block_compression) {
        return ReadBlockCompressed(buf, length, decompressed_offset);
    }
    return ReadBlockless(buf, length, decompressed_offset);
}

// ── 블록 압축 모드 ──────────────────────────────────────────

const NczVfsFile::CachedBlock* NczVfsFile::GetCachedBlock(s64 decomp_offset) const {
    for (const auto& cb : m_block_cache) {
        if (cb.block_index < 0) continue;
        const auto& bi = m_blocks[static_cast<std::size_t>(cb.block_index)];
        if (decomp_offset >= bi.decompressed_offset_start &&
            decomp_offset <= bi.decompressed_offset_end) {
            return &cb;
        }
    }
    return nullptr;
}

const NczVfsFile::CachedBlock* NczVfsFile::DecompressAndCacheBlock(
    const BlockInfo& block) const {

    // 압축 데이터 읽기
    const s64 compressed_size_raw = m_header.compressed_block_sizes[
        static_cast<std::size_t>(block.index)];

    std::vector<u8> compressed_data(static_cast<std::size_t>(compressed_size_raw));
    if (m_nsz_file->Read(compressed_data.data(), compressed_data.size(),
                          static_cast<std::size_t>(block.compressed_offset_start))
            != compressed_data.size()) {
        LOG_ERROR(Loader, "NSZ: failed to read compressed block {}", block.index);
        return nullptr;
    }

    std::vector<u8> decompressed_data(static_cast<std::size_t>(block.decompressed_block_size));

    if (block.is_compressed) {
        // zstd 단일 블록 압축 해제
        const std::size_t result = ZSTD_decompress(
            decompressed_data.data(), decompressed_data.size(),
            compressed_data.data(), compressed_data.size());

        if (ZSTD_isError(result)) {
            LOG_ERROR(Loader, "NSZ: zstd decompression failed for block {}: {}",
                      block.index, ZSTD_getErrorName(result));
            return nullptr;
        }
        if (result != static_cast<std::size_t>(block.decompressed_block_size)) {
            LOG_ERROR(Loader, "NSZ: block {} decompressed size mismatch: got {}, expected {}",
                      block.index, result, block.decompressed_block_size);
            return nullptr;
        }
    } else {
        // 비압축 블록: 그대로 복사
        decompressed_data = std::move(compressed_data);
    }

    // 캐시에 추가 (LRU 방식: 가장 오래된 슬롯 교체)
    std::lock_guard lock(m_cache_mutex);

    // 빈 슬롯 찾기
    CachedBlock* target = nullptr;
    for (auto& cb : m_block_cache) {
        if (cb.block_index < 0) { target = &cb; break; }
    }
    if (!target) {
        // 모든 슬롯 사용 중 → FIFO: 가장 오래된 슬롯(front)을 뒤로 밀어 마지막 슬롯에 쓴다.
        // rotate 이후에만 유효한 포인터를 얻어야 하므로 rotate 전 대입은 하지 않는다.
        std::rotate(m_block_cache.begin(), m_block_cache.begin() + 1, m_block_cache.end());
        target = &m_block_cache[MAX_CACHE_BLOCKS - 1];
    }

    target->block_index = block.index;
    target->data        = std::move(decompressed_data);
    return target;
}

std::size_t NczVfsFile::ReadBlockCompressed(u8* buf, std::size_t length,
                                             s64 decompressed_offset) const {
    std::size_t total_written = 0;
    s64 cur_offset = decompressed_offset;

    while (total_written < length) {
        // 현재 offset에 해당하는 블록 탐색
        const BlockInfo* block = nullptr;
        for (const auto& bi : m_blocks) {
            if (cur_offset >= bi.decompressed_offset_start &&
                cur_offset <= bi.decompressed_offset_end) {
                block = &bi;
                break;
            }
        }
        if (!block) break;

        // 블록 내 복사 범위 계산 (캐시 접근 전에 미리 계산)
        const s64 block_local_offset = cur_offset - block->decompressed_offset_start;
        const std::size_t available_in_block =
            static_cast<std::size_t>(block->decompressed_block_size - block_local_offset);
        const std::size_t to_copy = std::min(available_in_block, length - total_written);

        // 캐시 확인 및 복사를 락 보유 상태에서 수행
        // DecompressAndCacheBlock은 내부에서 락을 획득하므로 락 해제 후 호출,
        // 이후 재진입하여 락 보유 상태로 memcpy까지 완료한다.
        {
            std::unique_lock lock(m_cache_mutex);
            const CachedBlock* cached = GetCachedBlock(cur_offset);
            if (cached) {
                // 캐시 히트: 락 보유 상태에서 바로 복사
                std::memcpy(buf + total_written,
                            cached->data.data() + block_local_offset,
                            to_copy);
                total_written += to_copy;
                cur_offset    += static_cast<s64>(to_copy);
                continue;
            }
        }

        // 캐시 미스: 락 없이 압축 해제 수행 (DecompressAndCacheBlock 내부에서 락 획득)
        const CachedBlock* cached = DecompressAndCacheBlock(*block);
        if (!cached) break;

        // 압축 해제 후 재진입: 락 보유 상태에서 복사
        {
            std::lock_guard lock(m_cache_mutex);
            // DecompressAndCacheBlock이 반환한 포인터는 rotate로 인해 무효화될 수 있으므로
            // 오프셋으로 다시 조회하여 안전한 포인터를 얻는다.
            const CachedBlock* safe_cached = GetCachedBlock(cur_offset);
            if (!safe_cached) break;  // 다른 스레드가 해당 슬롯을 교체한 경우

            std::memcpy(buf + total_written,
                        safe_cached->data.data() + block_local_offset,
                        to_copy);
        }

        total_written += to_copy;
        cur_offset    += static_cast<s64>(to_copy);
    }

    return total_written;
}

// ── 스트림(Blockless) 압축 모드 ──────────────────────────────
// zstd 스트림은 순방향 탐색만 가능하므로, 역방향 읽기 시 처음부터 재시작.
// 에뮬레이터 NCA 접근 패턴은 대부분 순방향이므로 실용적으로 문제없음.

std::size_t NczVfsFile::ReadBlockless(u8* buf, std::size_t length,
                                       s64 decompressed_offset) const {
    const s64 compression_start = m_header.compression_start_offset;
    const s64 total_compressed_size =
        static_cast<s64>(m_nsz_file->GetSize()) - compression_start;

    if (total_compressed_size <= 0) return 0;

    // 압축 데이터 전체 읽기 (blockless 모드는 전체 스트림이므로 캐싱 권장)
    // TODO: 대용량 파일의 경우 청크 단위 스트리밍 개선 가능
    // thread_local 캐시로 블록리스 압축 해제 결과를 보관한다.
    // owner를 raw pointer로 비교하면 객체 소멸 후 동일 주소에 새 객체가 생성될 때
    // 잘못된 캐시 히트(use-after-free)가 발생한다.
    // 대신 생성 시 할당한 고유 ID를 비교하여 안전하게 무효화한다.
    static thread_local struct BlocklessCache {
        uintptr_t owner_id = 0;
        std::vector<u8> decompressed;
    } s_cache;

    if (s_cache.owner_id != m_instance_id || s_cache.decompressed.empty()) {
        std::vector<u8> compressed_data(static_cast<std::size_t>(total_compressed_size));
        if (m_nsz_file->Read(compressed_data.data(), compressed_data.size(),
                              static_cast<std::size_t>(compression_start))
                != compressed_data.size()) {
            LOG_ERROR(Loader, "NSZ: blockless read failed for {}", m_nsz_file->GetName());
            return 0;
        }

        // zstd 스트림 압축 해제 (전체 크기 사전에 알 수 없으므로 추정 후 재시도)
        const std::size_t estimated_size =
            static_cast<std::size_t>(m_header.nca_size - static_cast<s64>(NCZ_NCA_HEADER_SIZE));

        s_cache.decompressed.resize(estimated_size);
        const std::size_t result = ZSTD_decompress(
            s_cache.decompressed.data(), s_cache.decompressed.size(),
            compressed_data.data(), compressed_data.size());

        if (ZSTD_isError(result)) {
            LOG_ERROR(Loader, "NSZ: zstd blockless decompress failed: {}",
                      ZSTD_getErrorName(result));
            s_cache.decompressed.clear();
            return 0;
        }

        s_cache.decompressed.resize(result);
        s_cache.owner_id = m_instance_id;
    }

    // 요청 범위 복사
    const s64 decomp_size = static_cast<s64>(s_cache.decompressed.size());
    if (decompressed_offset >= decomp_size) return 0;

    const s64 copy_end = std::min(decompressed_offset + static_cast<s64>(length), decomp_size);
    const std::size_t copy_len = static_cast<std::size_t>(copy_end - decompressed_offset);

    std::memcpy(buf, s_cache.decompressed.data() + decompressed_offset, copy_len);
    return copy_len;
}

// ============================================================
// AES-128-CTR 복원 (C# NczSectionsEncryptionHelper::Recover 대응)
// ============================================================

void NczVfsFile::ReEncrypt(u8* buf, std::size_t length, s64 nca_offset) const {
    if (length == 0) return;

    std::size_t written = 0;
    s64 cur_nca_offset = nca_offset;

    while (written < length) {
        // 현재 오프셋에 해당하는 섹션 탐색
        const NczSectionEntry* section = nullptr;
        for (const auto& s : m_header.sections) {
            if (cur_nca_offset >= s.offset && cur_nca_offset < (s.offset + s.size)) {
                section = &s;
                break;
            }
        }
        if (!section) break;

        const NczCryptoType crypto = static_cast<NczCryptoType>(section->crypto_type);

        // 섹션 내 남은 바이트 수
        const s64 available_in_section = section->offset + section->size - cur_nca_offset;
        const std::size_t to_process = static_cast<std::size_t>(
            std::min(available_in_section, static_cast<s64>(length - written)));

        if (crypto == NczCryptoType::AesCtr || crypto == NczCryptoType::AesCtrEx) {
            // AES-128-CTR 복원
            std::array<u8, 16> counter = section->crypto_counter;
            UpdateAesCtrCounter(counter, cur_nca_offset);
            ApplyAesCtr(buf + written, to_process, section->crypto_key, counter);
        }
        // NczCryptoType::None / Auto → 변환 없음

        written        += to_process;
        cur_nca_offset += static_cast<s64>(to_process);
    }
}

// ============================================================
// 헬퍼 함수
// ============================================================

bool IsNszFile(const VirtualFile& file) {
    if (!file) return false;
    const auto name = file->GetName();
    const auto dot = name.rfind('.');
    if (dot == std::string::npos) return false;
    const auto ext = Common::ToLower(name.substr(dot + 1));
    return ext == "nsz";
}

VirtualFile WrapNszAsNca(VirtualFile nsz_file) {
    return NczVfsFile::Make(std::move(nsz_file));
}

} // namespace FileSys