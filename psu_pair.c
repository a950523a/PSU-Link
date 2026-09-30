// psu_pair.c — ESP-NOW 配對狀態機。流程與推導見 include/psu_link/psu_pair.h

#include "psu_link/psu_pair.h"

// ─── 共用小工具 ──────────────────────────────────────────────────────────────

bool psu_ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

static void copy(uint8_t *dst, const uint8_t *src, size_t n)
{
    for (size_t i = 0; i < n; i++) dst[i] = src[i];
}

static void wipe(uint8_t *p, size_t n)
{
    volatile uint8_t *v = p;
    for (size_t i = 0; i < n; i++) v[i] = 0;
}

static bool mac_eq(const uint8_t a[6], const uint8_t b[6])
{
    for (int i = 0; i < 6; i++) if (a[i] != b[i]) return false;
    return true;
}

// HMAC 的訊息是「標籤字串 + 數個位元組欄位」接起來
typedef struct {
    uint8_t buf[160];
    size_t  len;
} cat_t;

static void cat_add(cat_t *c, const void *p, size_t n)
{
    const uint8_t *b = (const uint8_t *)p;
    for (size_t i = 0; i < n && c->len < sizeof c->buf; i++) c->buf[c->len++] = b[i];
}

static void cat_label(cat_t *c, const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    cat_add(c, s, n);
}

// ─── 角色換算：C = 控制板、N = 節點 ─────────────────────────────────────────

static const uint8_t *pk_c(const psu_pair_t *p) { return p->role == PSU_ROLE_CONTROLLER ? p->pk : p->peer_pk; }
static const uint8_t *pk_n(const psu_pair_t *p) { return p->role == PSU_ROLE_NODE ? p->pk : p->peer_pk; }
static const uint8_t *n_c (const psu_pair_t *p) { return p->role == PSU_ROLE_CONTROLLER ? p->n_mine : p->n_peer; }
static const uint8_t *n_n (const psu_pair_t *p) { return p->role == PSU_ROLE_NODE ? p->n_mine : p->n_peer; }
static const uint8_t *mac_c(const psu_pair_t *p) { return p->role == PSU_ROLE_CONTROLLER ? p->my_mac : p->peer_mac; }
static const uint8_t *mac_n(const psu_pair_t *p) { return p->role == PSU_ROLE_NODE ? p->my_mac : p->peer_mac; }
static uint8_t peer_role(const psu_pair_t *p) { return p->role == PSU_ROLE_CONTROLLER ? PSU_ROLE_NODE : PSU_ROLE_CONTROLLER; }

// ─── 推導 ────────────────────────────────────────────────────────────────────

// Cn = HMAC(Nn, "PSU-PAIR-C" ‖ PKn ‖ PKc)[0:16]
static void commitment(const psu_pair_t *p, const uint8_t nn[PSU_NONCE_LEN], uint8_t out[PSU_TAG_LEN])
{
    cat_t c = { .len = 0 };
    uint8_t h[32];
    cat_label(&c, "PSU-PAIR-C");
    cat_add(&c, pk_n(p), PSU_KEY_LEN);
    cat_add(&c, pk_c(p), PSU_KEY_LEN);
    p->cr->hmac_sha256(p->cr->ctx, nn, PSU_NONCE_LEN, c.buf, c.len, h);
    copy(out, h, PSU_TAG_LEN);
}

// 金鑰確認值：HMAC(LTK, "PSU-PAIR-F" ‖ role ‖ PKc ‖ PKn)[0:16]
static void confirm_tag(const psu_pair_t *p, uint8_t role, uint8_t out[PSU_TAG_LEN])
{
    cat_t c = { .len = 0 };
    uint8_t h[32];
    cat_label(&c, "PSU-PAIR-F");
    cat_add(&c, &role, 1);
    cat_add(&c, pk_c(p), PSU_KEY_LEN);
    cat_add(&c, pk_n(p), PSU_KEY_LEN);
    p->cr->hmac_sha256(p->cr->ctx, p->ltk, PSU_KEY_LEN, c.buf, c.len, h);
    copy(out, h, PSU_TAG_LEN);
}

// 兩邊亂數都到手之後：配對碼與長期金鑰
static bool derive(psu_pair_t *p)
{
    static const uint8_t LBL_V[] = "PSU-PAIR-V";
    cat_t c = { .len = 0 };
    uint8_t h[32];

    cat_add(&c, pk_c(p), PSU_KEY_LEN);
    cat_add(&c, pk_n(p), PSU_KEY_LEN);
    cat_add(&c, n_c(p), PSU_NONCE_LEN);
    cat_add(&c, n_n(p), PSU_NONCE_LEN);
    p->cr->hmac_sha256(p->cr->ctx, LBL_V, sizeof LBL_V - 1, c.buf, c.len, h);
    uint32_t v = ((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) | ((uint32_t)h[2] << 8) | h[3];
    p->code = v % 1000000u;

    uint8_t shared[32];
    if (!p->cr->x25519_shared(p->cr->ctx, p->sk, p->peer_pk, shared)) return false;
    c.len = 0;
    cat_label(&c, "PSU-PAIR-K");
    cat_add(&c, n_c(p), PSU_NONCE_LEN);
    cat_add(&c, n_n(p), PSU_NONCE_LEN);
    cat_add(&c, mac_c(p), 6);
    cat_add(&c, mac_n(p), 6);
    p->cr->hmac_sha256(p->cr->ctx, shared, sizeof shared, c.buf, c.len, p->ltk);
    wipe(shared, sizeof shared);
    wipe(p->sk, sizeof p->sk);   // 私鑰用完即丟：每次配對都是新的一對
    return true;
}

// ─── 狀態轉換 ────────────────────────────────────────────────────────────────

static void fail(psu_pair_t *p, psu_pair_fail_t why, bool tell_peer, uint32_t now_ms)
{
    p->state         = PSU_PAIR_FAILED;
    p->fail          = why;
    p->reject_left   = tell_peer ? 3 : 0;
    p->reject_reason = (uint8_t)why;
    p->next_tx_ms    = now_ms;
    p->local_ok      = false;
    p->peer_ok       = false;
    wipe(p->sk, sizeof p->sk);
    wipe(p->ltk, sizeof p->ltk);
}

static void enter_confirm(psu_pair_t *p, uint32_t now_ms)
{
    p->state       = PSU_PAIR_CONFIRM;
    p->deadline_ms = now_ms + PSU_PAIR_CONFIRM_MS;
    p->next_tx_ms  = now_ms;
}

static void maybe_done(psu_pair_t *p)
{
    if (p->state == PSU_PAIR_CONFIRM && p->local_ok && p->peer_ok) p->state = PSU_PAIR_DONE;
}

void psu_pair_start(psu_pair_t *p, uint8_t role, const uint8_t my_mac[6],
                    const psu_crypto_t *cr, uint32_t now_ms)
{
    uint8_t *raw = (uint8_t *)p;
    for (size_t i = 0; i < sizeof *p; i++) raw[i] = 0;
    p->role = role;
    p->cr   = cr;
    copy(p->my_mac, my_mac, 6);

    if (!cr->x25519_keygen(cr->ctx, p->sk, p->pk)) {
        fail(p, PSU_PAIR_FAIL_CRYPTO, false, now_ms);
        return;
    }
    cr->random(cr->ctx, p->n_mine, PSU_NONCE_LEN);
    p->state       = PSU_PAIR_SEARCHING;
    p->deadline_ms = now_ms + PSU_PAIR_SEARCH_MS;
    p->next_tx_ms  = now_ms;
}

bool psu_pair_busy(const psu_pair_t *p)
{
    return p->state == PSU_PAIR_SEARCHING || p->state == PSU_PAIR_EXCHANGING ||
           p->state == PSU_PAIR_CONFIRM;
}

void psu_pair_rx(psu_pair_t *p, const psu_msg_t *m, const uint8_t src[6], uint32_t now_ms)
{
    if (p->state == PSU_PAIR_IDLE || p->state == PSU_PAIR_FAILED) return;
    bool selected = p->state != PSU_PAIR_SEARCHING;
    if (selected && !mac_eq(src, p->peer_mac)) return;   // 只聽選定的那一台

    switch (m->type) {
    case PSU_MSG_PAIR_KEY: {
        const psu_msg_pair_key_t *k = &m->u.pair_key;
        if (k->role != peer_role(p) || k->proto_ver != PSU_LINK_PROTO_VER) return;
        if (p->state == PSU_PAIR_SEARCHING) {
            copy(p->peer_mac, src, 6);
            copy(p->peer_pk, k->pk, PSU_KEY_LEN);
            p->state      = PSU_PAIR_EXCHANGING;
            p->next_tx_ms = now_ms;          // 控制板：回自己的公鑰；節點：送承諾值
        } else if (p->role == PSU_ROLE_NODE && p->state == PSU_PAIR_EXCHANGING &&
                   psu_ct_equal(k->pk, p->peer_pk, PSU_KEY_LEN)) {
            p->next_tx_ms = now_ms;          // 控制板沒收到承諾值，重送
        }
        break;
    }
    case PSU_MSG_PAIR_COMMIT:
        if (p->role == PSU_ROLE_CONTROLLER && p->state == PSU_PAIR_EXCHANGING && !p->have_commit) {
            copy(p->commit, m->u.pair_commit.c, PSU_TAG_LEN);
            p->have_commit = true;
            p->next_tx_ms  = now_ms;         // 公開自己的亂數
        }
        break;

    case PSU_MSG_PAIR_NONCE: {
        const psu_msg_pair_nonce_t *n = &m->u.pair_nonce;
        if (n->role != peer_role(p)) return;
        if (p->role == PSU_ROLE_NODE) {
            if (p->state == PSU_PAIR_EXCHANGING) {
                copy(p->n_peer, n->n, PSU_NONCE_LEN);
                p->have_peer_nonce = true;
                if (!derive(p)) { fail(p, PSU_PAIR_FAIL_CRYPTO, true, now_ms); return; }
                enter_confirm(p, now_ms);
                p->reply_nonce = true;
            } else if (p->have_peer_nonce && psu_ct_equal(n->n, p->n_peer, PSU_NONCE_LEN)) {
                p->reply_nonce = true;       // 控制板沒收到我的亂數，再回一次
            }
        } else if (p->state == PSU_PAIR_EXCHANGING && p->have_commit && !p->have_peer_nonce) {
            uint8_t expect[PSU_TAG_LEN];
            commitment(p, n->n, expect);
            if (!psu_ct_equal(expect, p->commit, PSU_TAG_LEN)) {
                fail(p, PSU_PAIR_FAIL_COMMIT, true, now_ms);
                return;
            }
            copy(p->n_peer, n->n, PSU_NONCE_LEN);
            p->have_peer_nonce = true;
            if (!derive(p)) { fail(p, PSU_PAIR_FAIL_CRYPTO, true, now_ms); return; }
            enter_confirm(p, now_ms);
        }
        break;
    }
    case PSU_MSG_PAIR_CONFIRM: {
        const psu_msg_pair_confirm_t *c = &m->u.pair_confirm;
        if (c->role != peer_role(p)) return;
        if (p->state != PSU_PAIR_CONFIRM && p->state != PSU_PAIR_DONE) return;   // 還沒算出金鑰，對方會重送
        uint8_t expect[PSU_TAG_LEN];
        confirm_tag(p, peer_role(p), expect);
        if (!psu_ct_equal(expect, c->tag, PSU_TAG_LEN)) {
            // 已完成的配對不能被一個偽造的封包推翻；確認階段才算失敗
            if (p->state == PSU_PAIR_CONFIRM) fail(p, PSU_PAIR_FAIL_CONFIRM, true, now_ms);
            return;
        }
        p->peer_ok = true;
        if (p->local_ok) p->reply_confirm = true;   // 對方還在重送，表示可能沒收到我的
        maybe_done(p);
        break;
    }
    case PSU_MSG_PAIR_REJECT:
        if (selected && m->u.pair_reject.role == peer_role(p) && psu_pair_busy(p))
            fail(p, PSU_PAIR_FAIL_PEER_REJECT, false, now_ms);
        break;

    default:
        break;
    }
}

void psu_pair_user(psu_pair_t *p, bool accept, uint32_t now_ms)
{
    if (!psu_pair_busy(p)) return;
    if (!accept) {
        fail(p, PSU_PAIR_FAIL_USER_REJECT, p->state != PSU_PAIR_SEARCHING, now_ms);
        return;
    }
    if (p->state != PSU_PAIR_CONFIRM) return;   // 配對碼還沒出來，沒有東西可以確認
    p->local_ok   = true;
    p->next_tx_ms = now_ms;
    maybe_done(p);
    if (p->state == PSU_PAIR_DONE) p->reply_confirm = true;   // 對方先按的：回一次讓它也完成
}

bool psu_pair_poll(psu_pair_t *p, uint32_t now_ms, psu_msg_t *out, bool *broadcast)
{
    *broadcast = false;

    if (psu_pair_busy(p) && (int32_t)(now_ms - p->deadline_ms) >= 0) {
        fail(p, PSU_PAIR_FAIL_TIMEOUT, p->state != PSU_PAIR_SEARCHING, now_ms);
    }

    // 反應式的回覆優先，不受重送節奏限制
    if (p->reply_nonce) {
        p->reply_nonce = false;
        out->type = PSU_MSG_PAIR_NONCE;
        out->u.pair_nonce.role = p->role;
        copy(out->u.pair_nonce.n, p->n_mine, PSU_NONCE_LEN);
        return true;
    }
    if (p->reply_confirm) {
        p->reply_confirm = false;
        if (p->local_ok) {
            out->type = PSU_MSG_PAIR_CONFIRM;
            out->u.pair_confirm.role = p->role;
            confirm_tag(p, p->role, out->u.pair_confirm.tag);
            return true;
        }
    }

    if ((int32_t)(now_ms - p->next_tx_ms) < 0) return false;

    if (p->state == PSU_PAIR_FAILED) {
        if (!p->reject_left) return false;
        p->reject_left--;
        p->next_tx_ms = now_ms + 200u;
        out->type = PSU_MSG_PAIR_REJECT;
        out->u.pair_reject.role   = p->role;
        out->u.pair_reject.reason = p->reject_reason;
        return true;
    }

    p->next_tx_ms = now_ms + PSU_PAIR_RESEND_MS;

    switch (p->state) {
    case PSU_PAIR_SEARCHING:
        if (p->role != PSU_ROLE_NODE) return false;   // 控制板只聽
        out->type = PSU_MSG_PAIR_KEY;
        out->u.pair_key.proto_ver = PSU_LINK_PROTO_VER;
        out->u.pair_key.role      = p->role;
        copy(out->u.pair_key.pk, p->pk, PSU_KEY_LEN);
        *broadcast = true;
        return true;

    case PSU_PAIR_EXCHANGING:
        if (p->role == PSU_ROLE_NODE) {
            out->type = PSU_MSG_PAIR_COMMIT;
            commitment(p, p->n_mine, out->u.pair_commit.c);
        } else if (!p->have_commit) {
            out->type = PSU_MSG_PAIR_KEY;
            out->u.pair_key.proto_ver = PSU_LINK_PROTO_VER;
            out->u.pair_key.role      = p->role;
            copy(out->u.pair_key.pk, p->pk, PSU_KEY_LEN);
        } else {
            out->type = PSU_MSG_PAIR_NONCE;
            out->u.pair_nonce.role = p->role;
            copy(out->u.pair_nonce.n, p->n_mine, PSU_NONCE_LEN);
        }
        return true;

    case PSU_PAIR_CONFIRM:
        if (!p->local_ok || p->peer_ok) return false;
        out->type = PSU_MSG_PAIR_CONFIRM;
        out->u.pair_confirm.role = p->role;
        confirm_tag(p, p->role, out->u.pair_confirm.tag);
        return true;

    default:
        return false;
    }
}
