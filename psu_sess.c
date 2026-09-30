// psu_sess.c — 連線握手與逐封包驗證。設計見 include/psu_link/psu_sess.h

#include "psu_link/psu_sess.h"

static void copy(uint8_t *dst, const uint8_t *src, size_t n)
{
    for (size_t i = 0; i < n; i++) dst[i] = src[i];
}

static void wipe(uint8_t *p, size_t n)
{
    volatile uint8_t *v = p;
    for (size_t i = 0; i < n; i++) v[i] = 0;
}

// HMAC(key, label ‖ a ‖ b)
static void kdf(const psu_sess_t *s, const uint8_t *key, const char *label,
                const uint8_t *a, const uint8_t *b, uint8_t out[32])
{
    uint8_t msg[3 + 2 * PSU_NONCE_LEN];
    size_t  n = 0;
    while (label[n]) { msg[n] = (uint8_t)label[n]; n++; }
    copy(msg + n, a, PSU_NONCE_LEN); n += PSU_NONCE_LEN;
    copy(msg + n, b, PSU_NONCE_LEN); n += PSU_NONCE_LEN;
    s->cr->hmac_sha256(s->cr->ctx, key, PSU_KEY_LEN, msg, n, out);
}

static void hs_tag(const psu_sess_t *s, const char *label, const uint8_t *a, const uint8_t *b,
                   uint8_t out[PSU_TAG_LEN])
{
    uint8_t h[32];
    kdf(s, s->ltk, label, a, b, h);
    copy(out, h, PSU_TAG_LEN);
}

static char dir_char(uint8_t role) { return role == PSU_ROLE_CONTROLLER ? 'C' : 'N'; }
static uint8_t peer_role(const psu_sess_t *s)
{
    return s->role == PSU_ROLE_CONTROLLER ? PSU_ROLE_NODE : PSU_ROLE_CONTROLLER;
}

// 驗證碼 = HMAC(SK, 方向 ‖ 計數器(大端) ‖ 原本的一行)[0:8]
static void frame_tag(const psu_sess_t *s, const uint8_t *key, uint8_t role, uint32_t ctr,
                      const char *inner, size_t len, uint8_t out[PSU_SESS_TAG_LEN])
{
    uint8_t msg[5 + PSU_LINK_MAX_LINE];
    uint8_t h[32];
    if (len > PSU_LINK_MAX_LINE) len = PSU_LINK_MAX_LINE;
    msg[0] = (uint8_t)dir_char(role);
    msg[1] = (uint8_t)(ctr >> 24); msg[2] = (uint8_t)(ctr >> 16);
    msg[3] = (uint8_t)(ctr >> 8);  msg[4] = (uint8_t)ctr;
    copy(msg + 5, (const uint8_t *)inner, len);
    s->cr->hmac_sha256(s->cr->ctx, key, PSU_KEY_LEN, msg, 5 + len, h);
    copy(out, h, PSU_SESS_TAG_LEN);
}

static void establish(psu_sess_t *s, const uint8_t sk[PSU_KEY_LEN])
{
    copy(s->sk, sk, PSU_KEY_LEN);
    s->established = true;
    s->tx_ctr      = 0;
    s->rx_ctr      = 0;
    s->bad_streak  = 0;
    s->n_handshakes++;
}

// ─── API ─────────────────────────────────────────────────────────────────────

void psu_sess_init(psu_sess_t *s, uint8_t role, const uint8_t ltk[PSU_KEY_LEN],
                   const psu_crypto_t *cr, uint32_t now_ms)
{
    uint8_t *raw = (uint8_t *)s;
    for (size_t i = 0; i < sizeof *s; i++) raw[i] = 0;
    s->role = role;
    s->cr   = cr;
    copy(s->ltk, ltk, PSU_KEY_LEN);
    s->next_tx_ms    = now_ms;
    s->last_rekey_ms = now_ms - PSU_SESS_RESEND_MS;   // 第一次重新握手不受頻率限制
    if (role == PSU_ROLE_CONTROLLER) psu_sess_rekey(s, now_ms);
}

bool psu_sess_ready(const psu_sess_t *s) { return s->established; }

void psu_sess_rekey(psu_sess_t *s, uint32_t now_ms)
{
    if (s->role != PSU_ROLE_CONTROLLER) return;
    if ((int32_t)(now_ms - s->last_rekey_ms) < (int32_t)PSU_SESS_RESEND_MS) return;
    s->cr->random(s->cr->ctx, s->nc, PSU_NONCE_LEN);
    s->hs_active     = true;
    s->next_tx_ms    = now_ms;
    s->last_rekey_ms = now_ms;
    s->bad_streak    = 0;
}

bool psu_sess_rx(psu_sess_t *s, const psu_msg_t *m, uint32_t now_ms)
{
    uint8_t expect[PSU_TAG_LEN];

    switch (m->type) {
    case PSU_MSG_SESS_REPLY:
        if (s->role != PSU_ROLE_CONTROLLER) return true;
        if (s->hs_active) {
            hs_tag(s, "SH2", s->nc, m->u.sess_reply.n, expect);
            if (!psu_ct_equal(expect, m->u.sess_reply.tag, PSU_TAG_LEN)) return true;
            uint8_t sk[32];
            kdf(s, s->ltk, "SES", s->nc, m->u.sess_reply.n, sk);
            establish(s, sk);
            wipe(sk, sizeof sk);
            s->hs_active = false;
            hs_tag(s, "SH3", m->u.sess_reply.n, s->nc, s->finish_tag);
            copy(s->last_nn, m->u.sess_reply.n, PSU_NONCE_LEN);
            s->send_finish = true;
        } else if (s->established && psu_ct_equal(m->u.sess_reply.n, s->last_nn, PSU_NONCE_LEN)) {
            s->send_finish = true;       // 節點沒收到 SH3，又回了一次 SH2
        }
        return true;

    case PSU_MSG_SESS_REQUEST:
        if (s->role == PSU_ROLE_CONTROLLER) psu_sess_rekey(s, now_ms);
        return true;

    case PSU_MSG_SESS_INIT:
        if (s->role != PSU_ROLE_NODE) return true;
        if (!(s->pend && psu_ct_equal(m->u.sess_init.n, s->pend_nc, PSU_NONCE_LEN))) {
            copy(s->pend_nc, m->u.sess_init.n, PSU_NONCE_LEN);
            s->cr->random(s->cr->ctx, s->pend_nn, PSU_NONCE_LEN);
            kdf(s, s->ltk, "SES", s->pend_nc, s->pend_nn, s->pend_sk);
            s->pend = true;
        }
        s->send_reply = true;
        s->next_tx_ms = now_ms + 2u * PSU_SESS_RESEND_MS;   // 握手進行中，先別送 SHR
        return true;

    case PSU_MSG_SESS_FINISH:
        if (s->role != PSU_ROLE_NODE || !s->pend) return true;
        hs_tag(s, "SH3", s->pend_nn, s->pend_nc, expect);
        if (psu_ct_equal(expect, m->u.sess_finish.tag, PSU_TAG_LEN)) {
            establish(s, s->pend_sk);
            wipe(s->pend_sk, sizeof s->pend_sk);
            s->pend = false;
        }
        return true;

    default:
        return false;
    }
}

bool psu_sess_poll(psu_sess_t *s, uint32_t now_ms, psu_msg_t *out)
{
    if (s->role == PSU_ROLE_CONTROLLER) {
        if (s->send_finish) {
            s->send_finish = false;
            out->type = PSU_MSG_SESS_FINISH;
            copy(out->u.sess_finish.tag, s->finish_tag, PSU_TAG_LEN);
            return true;
        }
        if (s->hs_active && (int32_t)(now_ms - s->next_tx_ms) >= 0) {
            s->next_tx_ms = now_ms + PSU_SESS_RESEND_MS;
            out->type = PSU_MSG_SESS_INIT;
            copy(out->u.sess_init.n, s->nc, PSU_NONCE_LEN);
            return true;
        }
        return false;
    }

    if (s->send_reply) {
        s->send_reply = false;
        out->type = PSU_MSG_SESS_REPLY;
        copy(out->u.sess_reply.n, s->pend_nn, PSU_NONCE_LEN);
        hs_tag(s, "SH2", s->pend_nc, s->pend_nn, out->u.sess_reply.tag);
        return true;
    }
    // 沒有連線金鑰，或一直驗不過：請控制板重新握手
    bool want = !s->established || s->bad_streak >= PSU_SESS_BAD_REKEY;
    if (want && (int32_t)(now_ms - s->next_tx_ms) >= 0) {
        s->next_tx_ms = now_ms + PSU_SESS_RESEND_MS;
        s->bad_streak = 0;
        out->type = PSU_MSG_SESS_REQUEST;
        return true;
    }
    return false;
}

size_t psu_sess_wrap(psu_sess_t *s, const char *line, size_t len, char *out, size_t cap)
{
    static const char HEX[] = "0123456789ABCDEF";
    if (!s->established || s->tx_ctr == 0xFFFFFFFFu) return 0;
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) len--;
    if (len == 0 || len > PSU_LINK_MAX_LINE || len + 27u > cap) return 0;

    uint32_t ctr = ++s->tx_ctr;
    uint8_t  tag[PSU_SESS_TAG_LEN];
    frame_tag(s, s->sk, s->role, ctr, line, len, tag);

    size_t n = 0;
    for (size_t i = 0; i < len; i++) out[n++] = line[i];
    out[n++] = '~';
    for (int i = 7; i >= 0; i--) out[n++] = HEX[(ctr >> (i * 4)) & 0xFu];
    for (size_t i = 0; i < PSU_SESS_TAG_LEN; i++) {
        out[n++] = HEX[tag[i] >> 4];
        out[n++] = HEX[tag[i] & 0xFu];
    }
    out[n++] = '\n';
    out[n]   = '\0';
    return n;
}

static int hexv(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static bool check(psu_sess_t *s, const uint8_t *key, uint32_t ctr, const char *inner, size_t len,
                  const uint8_t tag[PSU_SESS_TAG_LEN])
{
    uint8_t expect[PSU_SESS_TAG_LEN];
    frame_tag(s, key, peer_role(s), ctr, inner, len, expect);
    return psu_ct_equal(expect, tag, PSU_SESS_TAG_LEN);
}

static psu_sess_result_t bad(psu_sess_t *s, uint32_t now_ms)
{
    s->n_bad_tag++;
    if (++s->bad_streak >= PSU_SESS_BAD_REKEY && s->role == PSU_ROLE_CONTROLLER)
        psu_sess_rekey(s, now_ms);
    return PSU_SESS_BAD_TAG;
}

psu_sess_result_t psu_sess_unwrap(psu_sess_t *s, const char *line, size_t len,
                                  size_t *inner_len, uint32_t now_ms)
{
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) len--;
    size_t tilde = len;
    for (size_t i = len; i > 0; i--) {
        if (line[i - 1] == '~') { tilde = i - 1; break; }
    }
    if (tilde == len) return PSU_SESS_PLAIN;
    if (len - tilde - 1 != 8u + 2u * PSU_SESS_TAG_LEN || tilde > PSU_LINK_MAX_LINE)
        return PSU_SESS_MALFORMED;

    const char *sfx = line + tilde + 1;
    uint32_t ctr = 0;
    for (int i = 0; i < 8; i++) {
        int h = hexv(sfx[i]);
        if (h < 0) return PSU_SESS_MALFORMED;
        ctr = (ctr << 4) | (uint32_t)h;
    }
    uint8_t tag[PSU_SESS_TAG_LEN];
    for (size_t i = 0; i < PSU_SESS_TAG_LEN; i++) {
        int hi = hexv(sfx[8 + 2 * i]), lo = hexv(sfx[9 + 2 * i]);
        if (hi < 0 || lo < 0) return PSU_SESS_MALFORMED;
        tag[i] = (uint8_t)((hi << 4) | lo);
    }

    if (s->established && check(s, s->sk, ctr, line, tilde, tag)) {
        if (ctr <= s->rx_ctr) { s->n_replay++; return PSU_SESS_REPLAY; }
        s->rx_ctr     = ctr;
        s->bad_streak = 0;
        s->n_ok++;
        *inner_len = tilde;
        return PSU_SESS_OK;
    }
    // 節點：SH3 可能遺失 —— 第一則用新金鑰驗過的訊框就等於握手完成
    if (s->role == PSU_ROLE_NODE && s->pend && ctr > 0 && check(s, s->pend_sk, ctr, line, tilde, tag)) {
        establish(s, s->pend_sk);
        wipe(s->pend_sk, sizeof s->pend_sk);
        s->pend   = false;
        s->rx_ctr = ctr;
        s->n_ok++;
        *inner_len = tilde;
        return PSU_SESS_OK;
    }
    if (!s->established && !s->pend) {
        s->bad_streak++;
        return PSU_SESS_NO_SESSION;
    }
    return bad(s, now_ms);
}
