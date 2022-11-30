#include "crypto.h"
#include "exceptions.h"
#include "lock_guard.h"

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/rng.h>
#include <cryptopp/sha.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <cerrno>
#include <limits>

// Some of the following codes are copied from https://github.com/arktronic/aes-siv.
// The licence follows:

// This project is licensed under the OSI-approved ISC License:
//
// Copyright (c) 2015 ARKconcepts / Sasha Kotlyar
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
// REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
// INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
// LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
// OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
// PERFORMANCE OF THIS SOFTWARE.

namespace securefs
{

static int safe_cast(size_t size)
{
    if (size < std::numeric_limits<int>::max())
    {
        return static_cast<int>(size);
    }
    throwVFSException(E2BIG);
}

class OpenSSLException : public ExceptionBase
{
private:
    unsigned long m_openssl_error;
    const char* m_file;
    int m_line;

public:
    explicit OpenSSLException(unsigned openssl_error, const char* file, int line)
        : m_openssl_error(openssl_error), m_file(file), m_line(line)
    {
    }
    std::string message() const override
    {
        char buffer[4095];
        ERR_error_string_n(m_openssl_error, buffer, sizeof(buffer));
        return absl::StrCat("OpenSSL error at ", m_file, " line ", m_line, ": ", buffer);
    }
};

#define CALL_OPENSSL_CHECKED(value)                                                                \
    do                                                                                             \
    {                                                                                              \
        if ((value) != 1)                                                                          \
            throw ::securefs::OpenSSLException(::ERR_get_error(), __FILE__, __LINE__);             \
    } while (0)

static const byte aes256_siv_zero_block[AES_SIV::IV_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static const byte aes256_cmac_Rb[AES_SIV::IV_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87};

static const byte aes256_iso_pad = 0x80;    // 0b10000000

static void aes256_bitshift_left(byte* buf, const size_t len)
{
    if (!len)
        return;
    for (size_t i = 0; i < len - 1; ++i)
    {
        buf[i] = static_cast<byte>((static_cast<unsigned>(buf[i]) << 1u)
                                   | ((static_cast<unsigned>(buf[i + 1]) >> 7u) & 1u));
    }
    buf[len - 1] = buf[len - 1] << 1u;
}

static void aes256_siv_dbl(byte* block)
{
    bool need_xor = (block[0] >> 7u) == 1u;
    aes256_bitshift_left(block, 16);
    if (need_xor)
        CryptoPP::xorbuf(block, aes256_cmac_Rb, 16);
}

AES_SIV::AES_SIV(const void* key, size_t size)
{
    const ::EVP_CIPHER* cmac_cipher = nullptr;
    const ::EVP_CIPHER* ctr_cipher = nullptr;
    if (size == 32)
    {
        cmac_cipher = EVP_aes_128_cbc();
        ctr_cipher = EVP_aes_128_ctr();
    }
    else if (size == 64)
    {
        cmac_cipher = EVP_aes_256_cbc();
        ctr_cipher = EVP_aes_256_ctr();
    }
    else
    {
        throwInvalidArgumentException("Invalid key size for AES-SIV");
    }
    m_cmac.reset(::CMAC_CTX_new());
    if (!m_cmac)
    {
        CALL_OPENSSL_CHECKED(0);
    }
    CALL_OPENSSL_CHECKED(::CMAC_Init(m_cmac.get(), key, size / 2, cmac_cipher, nullptr));
    m_ctr.reset(::EVP_CIPHER_CTX_new());
    if (!m_ctr)
    {
        CALL_OPENSSL_CHECKED(0);
    }
    CALL_OPENSSL_CHECKED(::EVP_CipherInit_ex(m_ctr.get(),
                                             ctr_cipher,
                                             nullptr,
                                             static_cast<const byte*>(key) + size / 2,
                                             aes256_siv_zero_block,
                                             1));
}

AES_SIV::~AES_SIV() = default;

void AES_SIV::s2v(const void* plaintext,
                  size_t text_len,
                  const void* additional_data,
                  size_t additional_len,
                  void* iv)
{
    byte D[AES_SIV::IV_SIZE];
    calculate_cmac(D, aes256_siv_zero_block, array_length(aes256_siv_zero_block));

    if (additional_data && additional_len)
    {
        aes256_siv_dbl(D);
        byte add_mac[AES_SIV::IV_SIZE];
        calculate_cmac(add_mac, static_cast<const byte*>(additional_data), additional_len);
        CryptoPP::xorbuf(D, add_mac, AES_SIV::IV_SIZE);
    }

    if (text_len >= AES_SIV::IV_SIZE)
    {
        SecByteBlock T(static_cast<const byte*>(plaintext), text_len);
        CryptoPP::xorbuf(T.data() + text_len - array_length(D), D, array_length(D));
        calculate_cmac(static_cast<byte*>(iv), T.data(), T.size());
    }
    else
    {
        aes256_siv_dbl(D);
        byte padded[AES_SIV::IV_SIZE];
        memcpy(padded, plaintext, text_len);
        padded[text_len] = aes256_iso_pad;
        for (size_t i = text_len + 1; i < array_length(padded); ++i)
        {
            padded[i] = 0;
        }
        CryptoPP::xorbuf(D, padded, AES_SIV::IV_SIZE);
        calculate_cmac(static_cast<byte*>(iv), D, array_length(D));
    }
}

void AES_SIV::calculate_cmac(byte* output, const byte* input, size_t size)
{
    CALL_OPENSSL_CHECKED(::CMAC_Update(m_cmac.get(), input, size));
    CALL_OPENSSL_CHECKED(::CMAC_Final(m_cmac.get(), output, nullptr));
    CALL_OPENSSL_CHECKED(::CMAC_Init(m_cmac.get(), nullptr, 0, nullptr, nullptr));
}

void AES_SIV::encrypt_and_authenticate(const void* plaintext,
                                       size_t text_len,
                                       const void* additional_data,
                                       size_t additional_len,
                                       void* ciphertext,
                                       void* siv)
{
    LockGuard<Mutex> lg(m_mutex);

    s2v(plaintext, text_len, additional_data, additional_len, siv);
    byte modded_iv[AES_SIV::IV_SIZE];
    memcpy(modded_iv, siv, AES_SIV::IV_SIZE);

    // Clear the 31st and 63rd bits in the IV.
    modded_iv[8] &= 0x7fu;
    modded_iv[12] &= 0x7fu;

    int out_len = safe_cast(text_len);
    CALL_OPENSSL_CHECKED(::EVP_CipherInit_ex(m_ctr.get(), nullptr, nullptr, nullptr, modded_iv, 1));
    CALL_OPENSSL_CHECKED(::EVP_CipherUpdate(m_ctr.get(),
                                            static_cast<byte*>(ciphertext),
                                            &out_len,
                                            static_cast<const byte*>(plaintext),
                                            out_len));
}

bool AES_SIV::decrypt_and_verify(const void* ciphertext,
                                 size_t text_len,
                                 const void* additional_data,
                                 size_t additional_len,
                                 void* plaintext,
                                 const void* siv)
{
    LockGuard<Mutex> lg(m_mutex);

    byte temp_iv[AES_SIV::IV_SIZE];
    memcpy(temp_iv, siv, AES_SIV::IV_SIZE);
    // Clear the 31st and 63rd bits in the IV.
    temp_iv[8] &= 0x7fu;
    temp_iv[12] &= 0x7fu;

    int out_len = safe_cast(text_len);
    CALL_OPENSSL_CHECKED(::EVP_CipherInit_ex(m_ctr.get(), nullptr, nullptr, nullptr, temp_iv, 1));
    CALL_OPENSSL_CHECKED(::EVP_CipherUpdate(m_ctr.get(),
                                            static_cast<byte*>(plaintext),
                                            &out_len,
                                            static_cast<const byte*>(ciphertext),
                                            out_len));

    s2v(plaintext, text_len, additional_data, additional_len, temp_iv);
    return CryptoPP::VerifyBufsEqual(static_cast<const byte*>(siv), temp_iv, AES_SIV::IV_SIZE);
}

void generate_random(void* buffer, size_t size)
{
    static thread_local SecureRandom rng;
    rng.generate(buffer, size);
}

void hmac_sha256_calculate(
    const void* message, size_t msg_len, const void* key, size_t key_len, void* mac, size_t mac_len)
{
    HMAC_SHA256 hmac(key, key_len);
    hmac.update(message, msg_len);
    hmac.digest(mac, mac_len);
}

bool hmac_sha256_verify(const void* message,
                        size_t msg_len,
                        const void* key,
                        size_t key_len,
                        const void* mac,
                        size_t mac_len)
{
    unsigned char computed_mac[16];
    HMAC_SHA256 hmac(key, key_len);
    hmac.update(message, msg_len);
    hmac.digest(computed_mac, sizeof(computed_mac));
    return CRYPTO_memcmp(mac, computed_mac, std::min(sizeof(computed_mac), mac_len));
}

unsigned int pbkdf_hmac_sha256(const void* password,
                               size_t pass_len,
                               const void* salt,
                               size_t salt_len,
                               unsigned int min_iterations,
                               double min_seconds,
                               void* derived,
                               size_t derive_len)
{
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> kdf;
    return kdf.DeriveKey(static_cast<byte*>(derived),
                         derive_len,
                         0,
                         static_cast<const byte*>(password),
                         pass_len,
                         static_cast<const byte*>(salt),
                         salt_len,
                         min_iterations,
                         min_seconds);
}

static ::EVP_KDF* get_hkdf_kdf()
{
    static auto kdf = ::EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf)
    {
        CALL_OPENSSL_CHECKED(0);
    }
    return kdf;
}

void hkdf(const void* key,
          size_t key_len,
          const void* salt,
          size_t salt_len,
          const void* info,
          size_t info_len,
          void* output,
          size_t out_len)
{
    ::EVP_KDF_CTX* kctx = ::EVP_KDF_CTX_new(get_hkdf_kdf());
    if (!kctx)
    {
        CALL_OPENSSL_CHECKED(0);
    }
    DEFER(if (kctx) { ::EVP_KDF_CTX_free(kctx); });
    OSSL_PARAM params[]
        = {OSSL_PARAM_construct_utf8_string("digest", "sha256", (size_t)7),
           OSSL_PARAM_construct_octet_string("salt", const_cast<void*>(salt), salt_len),
           OSSL_PARAM_construct_octet_string("key", const_cast<void*>(key), key_len),
           OSSL_PARAM_construct_octet_string("info", const_cast<void*>(info), info_len),
           OSSL_PARAM_construct_end()};
    CALL_OPENSSL_CHECKED(::EVP_KDF_CTX_set_params(kctx, params));
    CALL_OPENSSL_CHECKED(::EVP_KDF_derive(kctx, static_cast<byte*>(output), out_len, params));
}

HMAC_SHA256::HMAC_SHA256(const void* key, size_t size)
{
    m_ctx.reset(::HMAC_CTX_new());
    if (!m_ctx)
    {
        CALL_OPENSSL_CHECKED(0);
    }
    CALL_OPENSSL_CHECKED(::HMAC_Init_ex(m_ctx.get(), key, safe_cast(size), EVP_sha256(), nullptr));
}

void HMAC_SHA256::update(const void* input, size_t size)
{
    CALL_OPENSSL_CHECKED(
        ::HMAC_Update(m_ctx.get(), static_cast<const byte*>(input), safe_cast(size)));
}

void HMAC_SHA256::digest(void* digest, size_t size)
{
    unsigned int len = safe_cast(size);
    CALL_OPENSSL_CHECKED(::HMAC_Final(m_ctx.get(), static_cast<byte*>(digest), &len));
}

void HMAC_SHA256::reset()
{
    CALL_OPENSSL_CHECKED(::HMAC_Init_ex(m_ctx.get(), nullptr, 0, nullptr, nullptr));
}

static ::EVP_RAND* get_default_rand_algorithm()
{
    static auto result = ::EVP_RAND_fetch(nullptr, "CTR-DRBG", nullptr);
    if (!result)
    {
        CALL_OPENSSL_CHECKED(0);
    }
    return result;
}

SecureRandom::SecureRandom()
{
    m_ctx.reset(::EVP_RAND_CTX_new(get_default_rand_algorithm(), nullptr));
    if (!m_ctx)
    {
        CALL_OPENSSL_CHECKED(0);
    }
    OSSL_PARAM params[]
        = {OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, SN_aes_256_ctr, 0),
           OSSL_PARAM_construct_end()};
    CALL_OPENSSL_CHECKED(::EVP_RAND_instantiate(m_ctx.get(), 128, 1, nullptr, 0, params));
}

void SecureRandom::generate(void* buffer, size_t size)
{
    CALL_OPENSSL_CHECKED(
        ::EVP_RAND_generate(m_ctx.get(), static_cast<byte*>(buffer), size, 128, 1, nullptr, 0));
}
}    // namespace securefs
