#pragma once

#include "streams.h"

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rng.h>
#include <cryptopp/secblock.h>

namespace securefs
{
namespace lite
{
    class CorruptedStreamException final : public ExceptionBase
    {
    public:
        std::string message() const override;
    };

    class AESGCMCryptStream final : public BlockBasedStream
    {
    private:
        key_type m_master_key;
        CryptoPP::GCM<CryptoPP::AES>::Encryption m_encryptor;
        CryptoPP::GCM<CryptoPP::AES>::Decryption m_decryptor;
        std::shared_ptr<StreamBase> m_stream;
        std::unique_ptr<byte[]> m_buffer;
        unsigned m_iv_size;
        bool m_check;

    public:
        length_type get_block_size() const noexcept { return m_block_size; }

        length_type get_iv_size() const noexcept { return m_iv_size; }

        static constexpr unsigned get_mac_size() noexcept { return 16; }

        static constexpr length_type get_header_size() noexcept { return 16; }

        length_type get_underlying_block_size() const noexcept
        {
            return get_block_size() + get_iv_size() + get_mac_size();
        }

        void resize(length_type new_size) override;

    protected:
        length_type read_block(offset_type block_number, void* output) override;

        void write_block(offset_type block_number, const void* input, length_type size) override;

        void adjust_logical_size(length_type length) override;

        void initialize_header_key(bool force_regenerate);

    public:
        explicit AESGCMCryptStream(std::shared_ptr<StreamBase> stream,
                                   const key_type& master_key,
                                   unsigned block_size = 4096,
                                   unsigned iv_size = 12,
                                   bool check = true);

        ~AESGCMCryptStream();

        virtual length_type size() const override;

        virtual void flush() override;

        virtual bool is_sparse() const noexcept override;

        static length_type calculate_real_size(length_type underlying_size,
                                               length_type block_size,
                                               length_type iv_size) noexcept;
    };
}    // namespace lite
}    // namespace securefs
