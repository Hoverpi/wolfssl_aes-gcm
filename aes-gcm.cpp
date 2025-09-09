#ifndef HAVE_AESGCM
#define HAVE_AESGCM
#endif

#include <iostream>
#include <string>
#include <vector>
#include <print>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <expected>

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/ssl.h>

using std::vector;
using std::string;
using std::string_view;
using std::println;
using std::size_t;
using std::expected;
using std::optional;
using std::unexpected;
using std::move;

#ifndef AES_128_KEY_SIZE
# define AES_128_KEY_SIZE 16
#endif
#ifndef GCM_NONCE_MID_SZ
# define GCM_NONCE_MID_SZ 12
#endif
#ifndef AES_BLOCK_SIZE
# define AES_BLOCK_SIZE 16
#endif

enum class GcmErrCode {
    WolfInitFail,
    RngInitFail,
    AesInitFail,
    NotInitialized,
    EncryptFail,
    DecryptFail,
    BadInput
};

struct GcmError {
    GcmErrCode code;
    string message;
};

template<typename T>
using Expected = expected<T, GcmError>;

// A small helper: return unexpected easily
inline auto make_error(GcmErrCode c, string msg) {
    return unexpected(GcmError{c, msg});
}

class GcmWrapper {
private:
    vector<uint8_t>  key{};
    size_t key_size;

    vector<uint8_t>  iv{};
    size_t iv_size;

    vector<uint8_t>  aad{};
    size_t aad_size;

    RNG  rng{};
    Aes  aes{};
    bool key_init = false;
    bool initialized = false;

    explicit GcmWrapper(size_t ks) : key(ks), key_size(ks), iv(GCM_NONCE_MID_SZ), iv_size(GCM_NONCE_MID_SZ), aad(), aad_size(0) {}

    Expected<void> initAll() {
        // initialize wolfSSL
        if (wolfSSL_Init() != SSL_SUCCESS) {
            return make_error(GcmErrCode::WolfInitFail, "wolfSSL_Init failed");
        }

        // initialize RNG
        if (wc_InitRng(&rng) != 0) {
            // clean wolfssl
            wolfSSL_Cleanup();
            return make_error(GcmErrCode::RngInitFail, "RNG init failed");
        }

        // generate key and IV using RNG
        if (wc_RNG_GenerateBlock(&rng, this->key.data(), this->key_size) != 0) {
            wc_FreeRng(&rng);
            wolfSSL_Cleanup();
            return make_error(GcmErrCode::RngInitFail, "RNG failed to produce key");
        }
        if (wc_RNG_GenerateBlock(&rng, this->iv.data(), this->iv_size) != 0) {
            wc_FreeRng(&rng);
            wolfSSL_Cleanup();
            return make_error(GcmErrCode::RngInitFail, "RNG failed to produce IV");
        }

        // initialize AES/GCM context
        if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
            wc_AesFree(&aes);  
            wc_FreeRng(&rng);
            wolfSSL_Cleanup();
            return make_error(GcmErrCode::AesInitFail, "AES init failed");
        }

        // set flag
        this->key_init =  true;
        this->initialized = true;
        return{};
    }

public:
    // Factory to make a Gcm or an error
    static Expected<GcmWrapper> create(size_t ks = AES_128_KEY_SIZE) {
      auto ptr = make_unique<GcmWrapper>(ks);
      auto ret = g->initAll();
      if (!ret) return unexpected(ret.error());
      return ptr;
    }

    Expected<string> getKey() const {
        if (this->key.empty()) { 
            return make_error(GcmErrCode::BadInput, "Key is empty");
        } else {
            return string(this->key.begin(), this->key.end());
        }
    }

    // Clean resources
    void Cleanup() noexcept {
        if (this->initialized) {
            wc_AesFree(&aes);  
            wc_FreeRng(&rng);
            wolfSSL_Cleanup();
            this->initialized = false;
        }
    }

    ~GcmWrapper() noexcept {
        Cleanup();
    }
};

int main() {
  auto g = GcmWrapper::create(AES_128_KEY_SIZE);
  string plain = "texto plano";
  string aad = "auth_header";
  auto key = g->getKey();
  println("key string = {}, key vector = {}", key);
//   string iv = g.getkey();
//   string encrypted = g.encrypt(plain, aad);
//   println("Key = {}, Iv = {}, Encrypted = {}", key, iv, encrypted);
//   string decrypted = g.decrypt(encrypted, aad);
//   println("Decrypted = {}", decrypted);
  return 0;
}