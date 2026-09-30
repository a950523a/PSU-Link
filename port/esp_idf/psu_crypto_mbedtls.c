// psu_crypto_mbedtls.c — psu_crypto_t 的 ESP-IDF 實作
//
// X25519 用 mbedTLS 的 ECP（Curve25519 是 Montgomery 曲線：公鑰只有 X 座標，
// 以小端序 32 位元組表示，與 RFC 7748 相同）；HMAC-SHA256 用 mbedtls_md_hmac；
// 亂數用 esp_fill_random（RF 開著時是硬體真亂數，ESP-NOW 需要 WiFi，所以一定開著）。

#include "psu_link/psu_crypto_mbedtls.h"

#include "esp_random.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"

static void rnd(void *ctx, uint8_t *out, size_t n)
{
    (void)ctx;
    esp_fill_random(out, n);
}

static int f_rng(void *ctx, unsigned char *out, size_t n)
{
    (void)ctx;
    esp_fill_random(out, n);
    return 0;
}

static bool keygen(void *ctx, uint8_t sk[32], uint8_t pk[32])
{
    (void)ctx;
    mbedtls_ecp_group grp;
    mbedtls_mpi       d;
    mbedtls_ecp_point q;
    size_t            olen = 0;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);

    bool ok = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) == 0 &&
              mbedtls_ecp_gen_keypair(&grp, &d, &q, f_rng, NULL) == 0 &&
              mbedtls_mpi_write_binary_le(&d, sk, 32) == 0 &&
              mbedtls_ecp_point_write_binary(&grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                             &olen, pk, 32) == 0 &&
              olen == 32;

    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

static bool shared(void *ctx, const uint8_t sk[32], const uint8_t peer_pk[32], uint8_t out[32])
{
    (void)ctx;
    mbedtls_ecp_group grp;
    mbedtls_mpi       d, z;
    mbedtls_ecp_point q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&q);

    bool ok = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) == 0 &&
              mbedtls_ecp_point_read_binary(&grp, &q, peer_pk, 32) == 0 &&
              mbedtls_ecp_check_pubkey(&grp, &q) == 0 &&
              mbedtls_mpi_read_binary_le(&d, sk, 32) == 0 &&
              mbedtls_ecdh_compute_shared(&grp, &z, &q, &d, f_rng, NULL) == 0 &&
              mbedtls_mpi_cmp_int(&z, 0) != 0 &&          // RFC 7748：低階點會得到全 0，拒絕
              mbedtls_mpi_write_binary_le(&z, out, 32) == 0;

    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&z);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

static void hmac(void *ctx, const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    (void)ctx;
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, key_len, msg, msg_len, out);
}

static const psu_crypto_t s_crypto = {
    .ctx           = NULL,
    .random        = rnd,
    .x25519_keygen = keygen,
    .x25519_shared = shared,
    .hmac_sha256   = hmac,
};

const psu_crypto_t *psu_crypto_mbedtls(void) { return &s_crypto; }
