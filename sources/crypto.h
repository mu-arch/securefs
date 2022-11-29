#pragma once

#include "platform.h"

#include <cryptopp/aes.h>
#include <cryptopp/cmac.h>
#include <cryptopp/modes.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <stddef.h>
#include <stdint.h>

namespace securefs
{
struct CMACCloser
{
    void operator()(::CMAC_CTX* ctx) const
    {
        if (ctx)
        {
            ::CMAC_CTX_free(ctx);
        }
    }
};

struct EVPCipherCTXFreer
{
    void operator()(::EVP_CIPHER_CTX* ctx) const
    {
        if (ctx)
        {
            ::EVP_CIPHER_CTX_free(ctx);
        }
    }
};

struct HMACFreer
{
    void operator()(::HMAC_CTX* ctx) const
    {
        if (ctx)
        {
            ::HMAC_CTX_free(ctx);
        }
    }
};

// Implementation of AES-SIV according to https://tools.ietf.org/html/rfc5297
class AES_SIV
{
private:
    Mutex m_mutex;
    std::unique_ptr<::CMAC_CTX, CMACCloser> m_cmac THREAD_ANNOTATION_GUARDED_BY(m_mutex);
    std::unique_ptr<::EVP_CIPHER_CTX, EVPCipherCTXFreer>
        m_ctr THREAD_ANNOTATION_GUARDED_BY(m_mutex);

private:
    void s2v(const void* plaintext,
             size_t text_len,
             const void* additional_data,
             size_t additional_len,
             void* iv) THREAD_ANNOTATION_REQUIRES(m_mutex);

    void calculate_cmac(byte* output, const byte* input, size_t size)
        THREAD_ANNOTATION_REQUIRES(m_mutex);

public:
    static constexpr size_t IV_SIZE = 16;

public:
    explicit AES_SIV(const void* key, size_t size);
    ~AES_SIV();

    void encrypt_and_authenticate(const void* plaintext,
                                  size_t text_len,
                                  const void* additional_data,
                                  size_t additional_len,
                                  void* ciphertext,
                                  void* siv);

    bool decrypt_and_verify(const void* ciphertext,
                            size_t text_len,
                            const void* additional_data,
                            size_t additional_len,
                            void* plaintext,
                            const void* siv);
};

class HMAC_SHA256
{
private:
    std::unique_ptr<::HMAC_CTX, HMACFreer> m_ctx;

public:
    explicit HMAC_SHA256(const void* key, size_t size);
    void update(const void* input, size_t size);
    void digest(void* digest, size_t size);
    void reset();
};

void hmac_sha256_calculate(const void* message,
                           size_t msg_len,
                           const void* key,
                           size_t key_len,
                           void* mac,
                           size_t mac_len);

bool hmac_sha256_verify(const void* message,
                        size_t msg_len,
                        const void* key,
                        size_t key_len,
                        const void* mac,
                        size_t mac_len);

// HMAC based key derivation function (https://tools.ietf.org/html/rfc5869)
// This one is not implemented by Crypto++, so we implement it ourselves
void hkdf(const void* key,
          size_t key_len,
          const void* salt,
          size_t salt_len,
          const void* info,
          size_t info_len,
          void* output,
          size_t out_len);

unsigned int pbkdf_hmac_sha256(const void* password,
                               size_t pass_len,
                               const void* salt,
                               size_t salt_len,
                               unsigned int min_iterations,
                               double min_seconds,
                               void* derived,
                               size_t derive_len);

void generate_random(void* buffer, size_t size);
}    // namespace securefs
