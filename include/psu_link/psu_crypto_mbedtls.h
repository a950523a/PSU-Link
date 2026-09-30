#pragma once
// psu_crypto_mbedtls.h — psu_crypto_t 的 ESP-IDF 實作（mbedTLS + esp_fill_random）
//
// 只在 ESP-IDF 下編譯（port/esp_idf/psu_crypto_mbedtls.c）。需要 sdkconfig 開啟
// CONFIG_MBEDTLS_ECP_C、CONFIG_MBEDTLS_ECDH_C、CONFIG_MBEDTLS_ECP_DP_CURVE25519_ENABLED
// （ESP-IDF 預設就是開的）。

#include "psu_link/psu_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

const psu_crypto_t *psu_crypto_mbedtls(void);

#ifdef __cplusplus
}
#endif
