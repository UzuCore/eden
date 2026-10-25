// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

#include "core/file_sys/vfs/vfs.h"

namespace FileSys {

// ============================================================
// NSZ 포맷 상수
// ============================================================

/// NCA 헤더 크기 (압축되지 않는 영역)
constexpr std::size_t NCZ_NCA_HEADER_SIZE = 0x4000;

/// NCZ 섹션 최대 개수
/// NCA는 최대 4개의 논리 섹션을 가지지만, 업데이트 NCA는 AesCtrEx 암호화를 사용해
/// 패치 entry마다 AES 카운터가 달라진다. nsz 도구는 이 각각의 암호화 구간을
/// 별도 NczSection으로 저장하므로, 큰 업데이트 NCA는 수백 개의 NczSection을 가질 수 있다.
/// 4096으로 충분히 넉넉하게 잡는다.
constexpr s64 NCZ_MAX_SECTION_COUNT = 4096;

/// NCZ 섹션 매직
constexpr std::string_view NCZ_SECTION_MAGIC = "NCZSECTN";

/// NCZ 블록 압축 매직
constexpr std::string_view NCZ_BLOCK_MAGIC = "NCZBLOCK";

// ============================================================
// NCZ 헤더 구조체
// ============================================================

/// NczSection 원시 구조체 (C# NczSectionRaw 대응)
/// 각 섹션은 NCA 내의 특정 오프셋 범위에 대한 암호화 복원 정보를 담는다.
#pragma pack(push, 1)
struct NczSectionEntry {
    s64 offset;       ///< NCA 시작 기준 오프셋 (NCA 헤더 포함)
    s64 size;         ///< 섹션 크기
    s64 crypto_type;  ///< 암호화 타입 (NcaEncryptionType 대응)
    s64 padding;
    std::array<u8, 16> crypto_key;      ///< AES 키
    std::array<u8, 16> crypto_counter;  ///< AES-CTR 초기 카운터
};
static_assert(sizeof(NczSectionEntry) == 0x40, "NczSectionEntry size mismatch");

/// NCZ 블록 압축 헤더 원시 구조체 (C# NczBlockCompressionHeaderRaw 대응)
struct NczBlockHeader {
    u8 version;
    u8 type;
    u8 unused;
    u8 block_size_exponent;  ///< 압축 해제 블록 크기 = 1 << block_size_exponent
    s32 number_of_blocks;
    s64 decompressed_size;   ///< NCA 헤더를 제외한 압축 해제 데이터 전체 크기
};
static_assert(sizeof(NczBlockHeader) == 0x10, "NczBlockHeader size mismatch");
#pragma pack(pop)

/// 암호화 타입 (LibHac NcaEncryptionType 대응)
enum class NczCryptoType : s64 {
    Auto    = 0,
    None    = 1,
    AesXts  = 2,
    AesCtr  = 3,
    AesCtrEx = 4,
};

// ============================================================
// 파싱된 NCZ 헤더
// ============================================================

struct NczParsedHeader {
    /// 원본 NCA 헤더 바이트 (보통 0x4000, BKTR NCA는 더 클 수 있음)
    std::vector<u8> nca_header_bytes{};

    /// 섹션 목록
    std::vector<NczSectionEntry> sections;

    /// 블록 압축 헤더 (블록 압축 미사용 시 has_block_compression == false)
    bool has_block_compression = false;
    NczBlockHeader block_header{};

    /// 블록별 압축 크기 목록 (블록 압축 사용 시)
    std::vector<s32> compressed_block_sizes;

    /// 압축 데이터가 시작되는 NCZ 파일 내 오프셋
    s64 compression_start_offset = 0;

    /// 원본 NCA 총 크기
    s64 nca_size = 0;
};

// ============================================================
// NczVfsFile: NSZ 파일을 NCA VirtualFile로 노출하는 래퍼
// ============================================================

/**
 * NSZ 파일을 NCA 파일인 것처럼 읽을 수 있게 하는 VirtualFile 구현체.
 *
 * 내부 동작:
 *   Read(offset, size) 호출 시:
 *     - offset < 0x4000 → 원본 NCA 헤더 바이트 반환
 *     - offset >= 0x4000 → zstd 압축 해제 후 AES-128-CTR 재암호화 복원
 *
 * 블록 압축 모드(NCZBLOCK)와 스트림 압축 모드(NCZSECTN only) 모두 지원.
 * 블록 압축 모드에서는 블록 단위로 캐시하여 랜덤 읽기 성능을 확보.
 */
class NczVfsFile final : public VfsFile {
public:
    // --------------------------------------------------------
    // 블록 캐시 (블록 압축 모드 전용)
    // --------------------------------------------------------

    struct BlockInfo {
        int  index;
        s64  decompressed_offset_start;
        s64  decompressed_offset_end;
        s64  decompressed_block_size;
        s64  compressed_offset_start;  ///< NCZ 파일 내 절대 오프셋
        bool is_compressed;
    };
    /**
     * NSZ VirtualFile로부터 NczVfsFile을 생성한다.
     * @param nsz_file  실제 .nsz 파일 VirtualFile
     * @return 성공 시 NczVfsFile shared_ptr, 실패 시 nullptr
     */
    static std::shared_ptr<NczVfsFile> Make(VirtualFile nsz_file);

    ~NczVfsFile() override;

    // VfsFile 인터페이스
    std::string GetName() const override;
    std::size_t GetSize() const override;
    bool Resize(std::size_t new_size) override;
    VirtualDir GetContainingDirectory() const override;
    bool IsWritable() const override;
    bool IsReadable() const override;
    std::vector<u8> ReadBytes(std::size_t size, std::size_t offset = 0) const override;
    std::size_t Read(u8* data, std::size_t length, std::size_t offset) const override;
    std::size_t Write(const u8* data, std::size_t length, std::size_t offset) override;
    bool Rename(std::string_view name) override;

private:
    explicit NczVfsFile(VirtualFile nsz_file, NczParsedHeader header);

    // --------------------------------------------------------
    // 압축 해제
    // --------------------------------------------------------

    /**
     * NCZ 압축 영역에서 decompressed_offset 위치의 바이트를 읽어 buf에 저장한다.
     * decompressed_offset은 NCA 헤더(0x4000)를 뺀 압축 해제 스트림 내 오프셋.
     */
    std::size_t ReadDecompressed(u8* buf, std::size_t length, s64 decompressed_offset) const;

    /// 블록 압축 모드 읽기
    std::size_t ReadBlockCompressed(u8* buf, std::size_t length, s64 decompressed_offset) const;

    /// 스트림 압축 모드 읽기 (blockless)
    std::size_t ReadBlockless(u8* buf, std::size_t length, s64 decompressed_offset) const;

    // --------------------------------------------------------
    // AES-128-CTR 복원
    // --------------------------------------------------------

    /**
     * 압축 해제된 buf의 내용을, nca_offset 위치에 해당하는 섹션의 암호화로 복원한다.
     * nca_offset: NCA 파일 시작 기준 오프셋 (헤더 포함).
     */
    void ReEncrypt(u8* buf, std::size_t length, s64 nca_offset) const;

    /// 블록 인덱스 목록 (파싱 시 사전 계산)
    std::vector<BlockInfo> m_blocks;

    struct CachedBlock {
        int         block_index = -1;
        std::vector<u8> data;
    };

    /// 최근 사용 블록 캐시 (최대 4블록)
    mutable std::mutex            m_cache_mutex;
    mutable std::vector<CachedBlock> m_block_cache;
    static constexpr int MAX_CACHE_BLOCKS = 4;

    /// 지정 decompressed offset이 속하는 블록을 반환, 없으면 nullptr
    const CachedBlock* GetCachedBlock(s64 decompressed_offset) const;

    /// 블록을 디컴프레스하여 캐시에 추가 후 반환
    const CachedBlock* DecompressAndCacheBlock(const BlockInfo& block) const;

    // --------------------------------------------------------
    // 멤버
    // --------------------------------------------------------

    VirtualFile        m_nsz_file;
    NczParsedHeader    m_header;
    std::string        m_name;  ///< .nsz → .nca로 바뀐 파일명

    /// thread_local 블록리스 캐시의 소유권 검증용 고유 ID.
    /// raw pointer 비교 대신 사용하여 UAF를 방지한다.
    uintptr_t          m_instance_id;
};

// ============================================================
// 헬퍼 함수
// ============================================================

/**
 * 주어진 VirtualFile이 NSZ 파일인지 확인한다.
 * (확장자 체크 + 매직 바이트 확인)
 */
bool IsNszFile(const VirtualFile& file);

/**
 * NSZ VirtualFile을 NCA처럼 읽히는 VirtualFile로 변환한다.
 * 실패 시 nullptr 반환.
 */
VirtualFile WrapNszAsNca(VirtualFile nsz_file);

} // namespace FileSys