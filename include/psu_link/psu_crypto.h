#pragma once
// psu_crypto.h — 配對與連線驗證需要的密碼學函式，由呼叫端注入
//
// PSU-Link 維持零相依：這裡只定義介面，實作由使用的平台提供。
//   ESP-IDF：port/esp_idf/psu_crypto_mbedtls.c（mbedTLS 的 X25519 與 HMAC-SHA256）
//   主機測試：test/ 裡的假實作 —— 只驗流程，不提供任何安全性
//
// 協定只用到兩種密碼學原語：X25519 金鑰交換與 HMAC-SHA256。
// 其餘推導（承諾值、配對碼、長期金鑰、連線金鑰、訊框驗證碼）全部是
// HMAC-SHA256 加上不同的標籤字串，見 psu_pair.h 與 psu_sess.h。

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *ctx;   // 原樣傳回給下面每個函式

    // 密碼學等級的亂數（ESP32：esp_fill_random，RF 開著時是真亂數）
    void (*random)(void *ctx, uint8_t *out, size_t n);

    // 產生 X25519 金鑰對。sk、pk 皆 32 位元組，pk 為 RFC 7748 的 u 座標（小端序）
    bool (*x25519_keygen)(void *ctx, uint8_t sk[32], uint8_t pk[32]);

    // 共享秘密 = X25519(sk, peer_pk)。對方公鑰不合法時回傳 false
    bool (*x25519_shared)(void *ctx, const uint8_t sk[32], const uint8_t peer_pk[32],
                          uint8_t shared[32]);

    // HMAC-SHA256
    void (*hmac_sha256)(void *ctx, const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len, uint8_t out[32]);
} psu_crypto_t;

// 常數時間比較（驗證碼比對一律用這個，不用 memcmp）
bool psu_ct_equal(const uint8_t *a, const uint8_t *b, size_t n);

#ifdef __cplusplus
}
#endif
