// test_psu_pair.c — 配對（psu_pair）與連線驗證（psu_sess）的主機端測試
//
//   gcc -std=c99 -Wall -Wextra -Werror -Iinclude psu_link.c psu_pair.c psu_sess.c
//       test/test_psu_pair.c -o test_psu_pair && ./test_psu_pair      （上面是同一行）
//
// 密碼學：SHA-256 / HMAC 是真的實作（用 FIPS 180-2 與 RFC 4231 的向量驗過），
// X25519 則換成一個可交換的假實作 —— pk = H(sk)，shared = H(min(pk_a,pk_b) ‖ max(...))。
// 它讓雙方算出同一個共享秘密、中間人也能各自跟兩邊算出，足以測流程與攻擊情境，
// 但**沒有任何安全性**。真正的 X25519 在韌體裡由 mbedTLS 提供。
//
// 訊息在模擬的無線電上傳送前都會經過 psu_link_encode / decode，連編解碼一起測。

#include "psu_link/psu_pair.h"
#include "psu_link/psu_sess.h"
#include <stdio.h>
#include <string.h>

static int s_fail = 0, s_pass = 0;
#define CHECK(c) do { if (c) s_pass++; else { s_fail++; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

// ─── SHA-256 / HMAC-SHA256（測試用的參考實作）─────────────────────────────────

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(uint32_t h[8], const uint8_t b[64])
{
    uint32_t w[64], a, bb, c, d, e, f, g, hh;
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)b[4*i] << 24 | (uint32_t)b[4*i+1] << 16 | (uint32_t)b[4*i+2] << 8 | b[4*i+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i-15], 7) ^ ROR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR(w[i-2], 17) ^ ROR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = h[0]; bb = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = hh + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & bb) ^ (a & c) ^ (bb & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = bb; bb = a; a = t1 + t2;
    }
    h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void sha256(const uint8_t *m, size_t n, uint8_t out[32])
{
    uint32_t h[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
    uint8_t blk[64];
    size_t i = 0;
    for (; i + 64 <= n; i += 64) sha256_block(h, m + i);
    size_t r = n - i;
    memset(blk, 0, 64);
    memcpy(blk, m + i, r);
    blk[r] = 0x80;
    if (r >= 56) { sha256_block(h, blk); memset(blk, 0, 64); }
    uint64_t bits = (uint64_t)n * 8;
    for (int k = 0; k < 8; k++) blk[63 - k] = (uint8_t)(bits >> (8 * k));
    sha256_block(h, blk);
    for (int k = 0; k < 8; k++) {
        out[4*k] = (uint8_t)(h[k] >> 24); out[4*k+1] = (uint8_t)(h[k] >> 16);
        out[4*k+2] = (uint8_t)(h[k] >> 8); out[4*k+3] = (uint8_t)h[k];
    }
}

static void hmac(void *ctx, const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen, uint8_t out[32])
{
    (void)ctx;
    uint8_t k[64] = {0}, buf[64 + 512], ih[32];
    if (klen > 64) sha256(key, klen, k); else memcpy(k, key, klen);
    for (int i = 0; i < 64; i++) buf[i] = k[i] ^ 0x36;
    memcpy(buf + 64, msg, mlen);
    sha256(buf, 64 + mlen, ih);
    for (int i = 0; i < 64; i++) buf[i] = k[i] ^ 0x5c;
    memcpy(buf + 64, ih, 32);
    sha256(buf, 96, out);
}

// ─── 假 X25519 與亂數 ────────────────────────────────────────────────────────

static uint64_t s_rng = 0x9E3779B97F4A7C15ull;
static void rnd(void *ctx, uint8_t *out, size_t n)
{
    (void)ctx;
    for (size_t i = 0; i < n; i++) {
        s_rng ^= s_rng << 13; s_rng ^= s_rng >> 7; s_rng ^= s_rng << 17;
        out[i] = (uint8_t)(s_rng >> 24);
    }
}
static bool keygen(void *ctx, uint8_t sk[32], uint8_t pk[32])
{
    rnd(ctx, sk, 32);
    sha256(sk, 32, pk);
    return true;
}
static bool shared(void *ctx, const uint8_t sk[32], const uint8_t peer[32], uint8_t out[32])
{
    (void)ctx;
    uint8_t mine[32], buf[64];
    sha256(sk, 32, mine);
    bool lo = memcmp(mine, peer, 32) < 0;
    memcpy(buf,      lo ? mine : peer, 32);
    memcpy(buf + 32, lo ? peer : mine, 32);
    sha256(buf, 64, out);
    return true;
}
static const psu_crypto_t CR = { NULL, rnd, keygen, shared, hmac };

// ─── 模擬無線電 ──────────────────────────────────────────────────────────────

#define MAX_EP 4
typedef struct {
    psu_pair_t p;
    uint8_t    mac[6];
    uint8_t    role;
    bool       present;
} ep_t;

static ep_t     s_ep[MAX_EP];
static int      s_nep;
static uint32_t s_now;
static int      s_loss_pct;        // 隨機丟包率（%）
static int      s_sent;
static uint32_t s_loss_rng = 12345u;

static void ep_add(uint8_t role, uint8_t id)
{
    ep_t *e = &s_ep[s_nep++];
    memset(e, 0, sizeof *e);
    e->role = role;
    e->present = true;
    for (int i = 0; i < 6; i++) e->mac[i] = (uint8_t)(0x10 * id + i);
    psu_pair_start(&e->p, role, e->mac, &CR, s_now);
}

static void deliver(int from, const psu_msg_t *m, bool bc)
{
    char line[PSU_LINK_MAX_LINE];
    psu_msg_t d;
    size_t n = psu_link_encode(m, line, sizeof line);
    CHECK(n > 0);
    CHECK(psu_link_decode(line, n, &d) == PSU_LINK_OK);
    CHECK(d.type == m->type);
    s_sent++;
    // 隨機丟包。不能用「每 N 則丟一則」：兩端交替重送時，同一則訊息會每次都
    // 剛好落在被丟的位置，永遠送不到 —— 那是測試手法的假象，不是協定的問題。
    s_loss_rng = s_loss_rng * 1103515245u + 12345u;
    if ((int)((s_loss_rng >> 16) % 100u) < s_loss_pct) return;
    for (int i = 0; i < s_nep; i++) {
        if (i == from || !s_ep[i].present) continue;
        if (!bc && memcmp(s_ep[from].p.peer_mac, s_ep[i].mac, 6) != 0) continue;
        psu_pair_rx(&s_ep[i].p, &d, s_ep[from].mac, s_now);
    }
}

static void run(uint32_t ms)
{
    for (uint32_t t = 0; t < ms; t += 10) {
        s_now += 10;
        for (int i = 0; i < s_nep; i++) {
            psu_msg_t m; bool bc;
            while (psu_pair_poll(&s_ep[i].p, s_now, &m, &bc)) deliver(i, &m, bc);
        }
    }
}

static void reset(void) { s_nep = 0; s_loss_pct = 0; s_sent = 0; }

// ─── 測試：編解碼 ────────────────────────────────────────────────────────────

static void test_codec(void)
{
    char line[PSU_LINK_MAX_LINE];
    psu_msg_t m = { .type = PSU_MSG_PAIR_KEY }, d;
    m.u.pair_key.proto_ver = PSU_LINK_PROTO_VER;
    m.u.pair_key.role = PSU_ROLE_NODE;
    for (int i = 0; i < 32; i++) m.u.pair_key.pk[i] = (uint8_t)(i * 7 + 1);
    size_t n = psu_link_encode(&m, line, sizeof line);
    CHECK(n > 70 && n < PSU_LINK_MAX_LINE);
    CHECK(psu_link_decode(line, n, &d) == PSU_LINK_OK);
    CHECK(d.u.pair_key.role == PSU_ROLE_NODE && memcmp(d.u.pair_key.pk, m.u.pair_key.pk, 32) == 0);
    printf("  PKH: %s", line);

    m.type = PSU_MSG_SESS_REPLY;
    for (int i = 0; i < 16; i++) { m.u.sess_reply.n[i] = (uint8_t)i; m.u.sess_reply.tag[i] = (uint8_t)(255 - i); }
    n = psu_link_encode(&m, line, sizeof line);
    CHECK(psu_link_decode(line, n, &d) == PSU_LINK_OK && d.type == PSU_MSG_SESS_REPLY);
    CHECK(memcmp(&d.u.sess_reply, &m.u.sess_reply, sizeof m.u.sess_reply) == 0);

    m.type = PSU_MSG_SESS_REQUEST;
    n = psu_link_encode(&m, line, sizeof line);
    CHECK(psu_link_decode(line, n, &d) == PSU_LINK_OK && d.type == PSU_MSG_SESS_REQUEST);

    // 位元組欄位長度不對、角色超出範圍
    CHECK(psu_link_decode("$PCM,ABCD*0000", 14, &d) != PSU_LINK_OK);
    char bad[PSU_LINK_MAX_LINE];
    const char *body = "PNC,2,00112233445566778899AABBCCDDEEFF";
    snprintf(bad, sizeof bad, "$%s*%04X\n", body, psu_link_crc16((const uint8_t *)body, strlen(body)));
    CHECK(psu_link_decode(bad, strlen(bad), &d) == PSU_LINK_BAD_FIELDS);
}

static void test_crypto_vectors(void)
{
    uint8_t h[32];
    sha256((const uint8_t *)"abc", 3, h);
    CHECK(h[0] == 0xba && h[1] == 0x78 && h[31] == 0xad);          // FIPS 180-2
    uint8_t key[20];
    memset(key, 0x0b, 20);
    hmac(NULL, key, 20, (const uint8_t *)"Hi There", 8, h);
    CHECK(h[0] == 0xb0 && h[1] == 0x34 && h[31] == 0xf7);          // RFC 4231 case 1
}

// ─── 測試：配對 ──────────────────────────────────────────────────────────────

static void confirm_both(ep_t *a, ep_t *b)
{
    psu_pair_user(&a->p, true, s_now);
    run(300);
    psu_pair_user(&b->p, true, s_now);
    run(2000);
}

static void test_pair_ok(int loss_pct)
{
    reset();
    s_loss_pct = loss_pct;
    ep_add(PSU_ROLE_CONTROLLER, 1);
    ep_add(PSU_ROLE_NODE, 2);
    ep_t *c = &s_ep[0], *n = &s_ep[1];
    run(10000);
    CHECK(c->p.state == PSU_PAIR_CONFIRM && n->p.state == PSU_PAIR_CONFIRM);
    CHECK(c->p.code == n->p.code && c->p.code < 1000000u);
    printf("  配對碼（丟包 %d%%）：%06u / %06u，共送 %d 則\n", loss_pct,
           (unsigned)c->p.code, (unsigned)n->p.code, s_sent);
    confirm_both(c, n);
    CHECK(c->p.state == PSU_PAIR_DONE && n->p.state == PSU_PAIR_DONE);
    CHECK(memcmp(c->p.ltk, n->p.ltk, 32) == 0);
    CHECK(memcmp(c->p.peer_mac, n->mac, 6) == 0 && memcmp(n->p.peer_mac, c->mac, 6) == 0);
}

static void test_pair_reject_and_timeout(void)
{
    reset();
    ep_add(PSU_ROLE_CONTROLLER, 1);
    ep_add(PSU_ROLE_NODE, 2);
    run(3000);
    psu_pair_user(&s_ep[0].p, true, s_now);
    psu_pair_user(&s_ep[1].p, false, s_now);         // 節點端按取消
    run(2000);
    CHECK(s_ep[1].p.state == PSU_PAIR_FAILED && s_ep[1].p.fail == PSU_PAIR_FAIL_USER_REJECT);
    CHECK(s_ep[0].p.state == PSU_PAIR_FAILED && s_ep[0].p.fail == PSU_PAIR_FAIL_PEER_REJECT);

    reset();
    ep_add(PSU_ROLE_CONTROLLER, 1);
    ep_add(PSU_ROLE_NODE, 2);
    run(3000);
    psu_pair_user(&s_ep[0].p, true, s_now);          // 只有控制板確認
    run(PSU_PAIR_CONFIRM_MS + 1000);
    CHECK(s_ep[0].p.state == PSU_PAIR_FAILED && s_ep[1].p.state == PSU_PAIR_FAILED);

    reset();
    ep_add(PSU_ROLE_CONTROLLER, 1);                  // 沒有節點
    run(PSU_PAIR_SEARCH_MS + 1000);
    CHECK(s_ep[0].p.state == PSU_PAIR_FAILED && s_ep[0].p.fail == PSU_PAIR_FAIL_TIMEOUT);
}

// 確認前按確認沒有作用；DONE 之後一則偽造的 PCF 推翻不了結果
static void test_pair_misc(void)
{
    reset();
    ep_add(PSU_ROLE_CONTROLLER, 1);
    ep_add(PSU_ROLE_NODE, 2);
    psu_pair_user(&s_ep[0].p, true, s_now);
    CHECK(!s_ep[0].p.local_ok);
    run(3000);
    confirm_both(&s_ep[0], &s_ep[1]);
    CHECK(s_ep[0].p.state == PSU_PAIR_DONE);
    psu_msg_t f = { .type = PSU_MSG_PAIR_CONFIRM };
    f.u.pair_confirm.role = PSU_ROLE_NODE;
    memset(f.u.pair_confirm.tag, 0xAA, 16);
    psu_pair_rx(&s_ep[0].p, &f, s_ep[1].mac, s_now);
    CHECK(s_ep[0].p.state == PSU_PAIR_DONE);
}

// 附近還有第二台節點在配對：控制板只跟選定的那台往下走，另一台的訊息被忽略
static void test_pair_two_nodes(void)
{
    reset();
    ep_add(PSU_ROLE_CONTROLLER, 1);
    ep_add(PSU_ROLE_NODE, 2);
    ep_add(PSU_ROLE_NODE, 3);
    run(5000);
    ep_t *c = &s_ep[0];
    int chosen = memcmp(c->p.peer_mac, s_ep[1].mac, 6) == 0 ? 1 : 2;
    int other  = 3 - chosen;
    CHECK(c->p.state == PSU_PAIR_CONFIRM);
    CHECK(s_ep[chosen].p.state == PSU_PAIR_CONFIRM && s_ep[chosen].p.code == c->p.code);
    CHECK(s_ep[other].p.state == PSU_PAIR_SEARCHING);   // 沒被選到的那台看不到配對碼
    confirm_both(c, &s_ep[chosen]);
    CHECK(c->p.state == PSU_PAIR_DONE);
}

// 節點公開的亂數跟承諾的不一樣 → 控制板判定失敗（中間人想事後改亂數就是這樣）
static void test_pair_commit_mismatch(void)
{
    reset();
    ep_add(PSU_ROLE_CONTROLLER, 1);
    ep_add(PSU_ROLE_NODE, 2);
    ep_t *c = &s_ep[0], *n = &s_ep[1];
    // 讓節點送出公鑰、控制板送出公鑰、節點送出承諾值，但擋住之後的亂數交換
    for (int i = 0; i < 200 && !c->p.have_commit; i++) run(10);
    CHECK(c->p.have_commit);
    psu_msg_t fake = { .type = PSU_MSG_PAIR_NONCE };
    fake.u.pair_nonce.role = PSU_ROLE_NODE;
    memset(fake.u.pair_nonce.n, 0x5A, 16);
    psu_pair_rx(&c->p, &fake, n->mac, s_now);
    CHECK(c->p.state == PSU_PAIR_FAILED && c->p.fail == PSU_PAIR_FAIL_COMMIT);
}

// 中間人：分別跟兩邊配對。兩邊的配對碼幾乎必然不同 —— 使用者比對時就會發現
static void test_pair_mitm(void)
{
    int differ = 0;
    for (int round = 0; round < 50; round++) {
        psu_pair_t c, n, mc, mn;
        uint8_t mac_c[6] = {1,1,1,1,1,1}, mac_n[6] = {2,2,2,2,2,2};
        psu_pair_start(&c,  PSU_ROLE_CONTROLLER, mac_c, &CR, 0);
        psu_pair_start(&n,  PSU_ROLE_NODE,       mac_n, &CR, 0);
        psu_pair_start(&mc, PSU_ROLE_NODE,       mac_n, &CR, 0);        // 對控制板冒充節點
        psu_pair_start(&mn, PSU_ROLE_CONTROLLER, mac_c, &CR, 0);        // 對節點冒充控制板
        for (uint32_t t = 10; t < 5000; t += 10) {
            psu_msg_t m; bool bc;
            while (psu_pair_poll(&c,  t, &m, &bc)) psu_pair_rx(&mc, &m, mac_c, t);
            while (psu_pair_poll(&mc, t, &m, &bc)) psu_pair_rx(&c,  &m, mac_n, t);
            while (psu_pair_poll(&n,  t, &m, &bc)) psu_pair_rx(&mn, &m, mac_n, t);
            while (psu_pair_poll(&mn, t, &m, &bc)) psu_pair_rx(&n,  &m, mac_c, t);
        }
        CHECK(c.state == PSU_PAIR_CONFIRM && n.state == PSU_PAIR_CONFIRM);
        if (c.code != n.code) differ++;
    }
    CHECK(differ == 50);
}

// ─── 測試：連線驗證 ──────────────────────────────────────────────────────────

static psu_sess_t s_c, s_n;
static bool s_n_alive;

static void sess_pump(uint32_t ms)
{
    for (uint32_t t = 0; t < ms; t += 10) {
        s_now += 10;
        psu_msg_t m;
        while (psu_sess_poll(&s_c, s_now, &m)) if (s_n_alive) psu_sess_rx(&s_n, &m, s_now);
        while (s_n_alive && psu_sess_poll(&s_n, s_now, &m)) psu_sess_rx(&s_c, &m, s_now);
    }
}

// 送一則 $SET（控制板 → 節點），回傳節點的驗證結果
static psu_sess_result_t send_set(psu_sess_t *from, psu_sess_t *to, char *wire, size_t *wlen)
{
    char line[PSU_LINK_MAX_LINE];
    psu_msg_t m = { .type = PSU_MSG_SET };
    m.u.set = (psu_msg_set_t){ .seq = 1, .has_v = true, .v_cv = 6720 };
    size_t n = psu_link_encode(&m, line, sizeof line);
    *wlen = psu_sess_wrap(from, line, n, wire, PSU_LINK_MAX_AUTH_LINE);
    if (*wlen == 0) return PSU_SESS_NO_SESSION;
    size_t inner;
    psu_sess_result_t r = psu_sess_unwrap(to, wire, *wlen, &inner, s_now);
    if (r == PSU_SESS_OK) {
        psu_msg_t d;
        CHECK(psu_link_decode(wire, inner, &d) == PSU_LINK_OK && d.type == PSU_MSG_SET && d.u.set.v_cv == 6720);
    }
    return r;
}

static void test_session(void)
{
    uint8_t ltk[32];
    rnd(NULL, ltk, 32);
    s_now = 1000;
    s_n_alive = true;
    psu_sess_init(&s_c, PSU_ROLE_CONTROLLER, ltk, &CR, s_now);
    psu_sess_init(&s_n, PSU_ROLE_NODE,       ltk, &CR, s_now);
    sess_pump(200);
    CHECK(psu_sess_ready(&s_c) && psu_sess_ready(&s_n));

    char wire[PSU_LINK_MAX_AUTH_LINE];
    size_t wl;
    CHECK(send_set(&s_c, &s_n, wire, &wl) == PSU_SESS_OK);
    printf("  帶驗證的 SET：%s", wire);

    // 重送同一則 → 擋下
    size_t inner;
    CHECK(psu_sess_unwrap(&s_n, wire, wl, &inner, s_now) == PSU_SESS_REPLAY);

    // 竄改內容（電壓 6720 → 9720）→ 擋下
    CHECK(send_set(&s_c, &s_n, wire, &wl) == PSU_SESS_OK);
    char *v = strstr(wire, "6720");
    v[0] = '9';
    CHECK(psu_sess_unwrap(&s_n, wire, wl, &inner, s_now) == PSU_SESS_BAD_TAG);

    // 反射：把控制板自己送出的訊框丟回控制板 → 方向不同，驗不過
    CHECK(send_set(&s_c, &s_n, wire, &wl) == PSU_SESS_OK);
    CHECK(psu_sess_unwrap(&s_c, wire, wl, &inner, s_now) == PSU_SESS_BAD_TAG);

    // 沒有尾碼的 $SET（冒用 MAC 的偽造）→ PLAIN，呼叫端必須丟掉
    CHECK(psu_sess_unwrap(&s_n, "$SET,1,6720,*1234\n", 18, &inner, s_now) == PSU_SESS_PLAIN);

    // 另一把長期金鑰（沒配對過的裝置）→ 驗不過
    psu_sess_t other;
    uint8_t ltk2[32];
    rnd(NULL, ltk2, 32);
    psu_sess_init(&other, PSU_ROLE_CONTROLLER, ltk2, &CR, s_now);
    memcpy(other.sk, ltk2, 32);
    other.established = true;
    CHECK(send_set(&other, &s_n, wire, &wl) == PSU_SESS_BAD_TAG);

    // 偽造的 SH1：節點回 SH2 但保留現有連線，控制板的訊框照常通過
    psu_msg_t sh1 = { .type = PSU_MSG_SESS_INIT };
    memset(sh1.u.sess_init.n, 0x33, 16);
    psu_sess_rx(&s_n, &sh1, s_now);
    CHECK(psu_sess_ready(&s_n));
    CHECK(send_set(&s_c, &s_n, wire, &wl) == PSU_SESS_OK);

    // 節點重開機：沒有連線金鑰 → 送 SHR → 控制板重新握手 → 恢復
    psu_sess_init(&s_n, PSU_ROLE_NODE, ltk, &CR, s_now);
    CHECK(send_set(&s_c, &s_n, wire, &wl) == PSU_SESS_NO_SESSION);
    sess_pump(3000);
    CHECK(psu_sess_ready(&s_n));
    CHECK(send_set(&s_c, &s_n, wire, &wl) == PSU_SESS_OK);
    // 重開機前錄下的訊框在新連線裡無效
    CHECK(psu_sess_unwrap(&s_n, wire, wl, &inner, s_now) == PSU_SESS_REPLAY);

    // 控制板重開機：節點還拿著舊金鑰；新握手完成後舊訊框全部無效
    char old[PSU_LINK_MAX_AUTH_LINE];
    size_t oldl;
    CHECK(send_set(&s_c, &s_n, old, &oldl) == PSU_SESS_OK);
    psu_sess_init(&s_c, PSU_ROLE_CONTROLLER, ltk, &CR, s_now);
    sess_pump(3000);
    CHECK(psu_sess_ready(&s_c) && psu_sess_ready(&s_n));
    CHECK(send_set(&s_c, &s_n, wire, &wl) == PSU_SESS_OK);
    CHECK(psu_sess_unwrap(&s_n, old, oldl, &inner, s_now) == PSU_SESS_BAD_TAG);

    // SH3 遺失：節點收到第一則用新金鑰的訊框就完成切換
    s_n_alive = true;
    psu_sess_rekey(&s_c, s_now + 5000);
    s_now += 5000;
    psu_msg_t m;
    CHECK(psu_sess_poll(&s_c, s_now, &m) && m.type == PSU_MSG_SESS_INIT);
    psu_sess_rx(&s_n, &m, s_now);
    CHECK(psu_sess_poll(&s_n, s_now, &m) && m.type == PSU_MSG_SESS_REPLY);
    psu_sess_rx(&s_c, &m, s_now);
    CHECK(psu_sess_poll(&s_c, s_now, &m) && m.type == PSU_MSG_SESS_FINISH);   // 故意不送出
    CHECK(send_set(&s_c, &s_n, wire, &wl) == PSU_SESS_OK);
    CHECK(send_set(&s_c, &s_n, wire, &wl) == PSU_SESS_OK);

    // 節點 → 控制板方向也驗
    char line[PSU_LINK_MAX_LINE];
    psu_msg_t st = { .type = PSU_MSG_STATUS };
    st.u.status = (psu_msg_status_t){ .seq = 9, .v_cv = 6700, .i_ca = 500, .mode = PSU_MODE_CV, .flags = 7 };
    size_t n = psu_link_encode(&st, line, sizeof line);
    wl = psu_sess_wrap(&s_n, line, n, wire, sizeof wire);
    CHECK(wl > 0 && psu_sess_unwrap(&s_c, wire, wl, &inner, s_now) == PSU_SESS_OK);
}

int main(void)
{
    test_crypto_vectors();
    test_codec();
    test_pair_ok(0);
    test_pair_ok(30);
    test_pair_ok(50);
    test_pair_reject_and_timeout();
    test_pair_misc();
    test_pair_two_nodes();
    test_pair_commit_mismatch();
    test_pair_mitm();
    test_session();
    printf("%d passed, %d failed\n", s_pass, s_fail);
    return s_fail ? 1 : 0;
}
