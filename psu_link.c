// psu_link.c — 充電控制板 ↔ 電源節點 連線協定的編解碼
// 格式與訊息定義見 include/psu_link/psu_link.h
//
// 不用 snprintf / sscanf：只依賴 <stdint.h> <stdbool.h> <stddef.h>，
// 而且 sscanf("%f") 正是舊協定的問題之一 —— 浮點字串解析在不同 libc 上
// 行為不一，這裡全部是整數。

#include "psu_link/psu_link.h"

// ─── CRC ─────────────────────────────────────────────────────────────────────

uint16_t psu_link_crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)((uint16_t)data[i] << 8);
        for (int b = 0; b < 8; b++) {
            crc = (crc & 0x8000u) ? (uint16_t)((crc << 1) ^ 0x1021u) : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

// ─── 編碼 ────────────────────────────────────────────────────────────────────

typedef struct {
    char   *buf;
    size_t  cap;      // 可寫入的位元組數（保留 1 給 NUL）
    size_t  len;
    bool    overflow;
} writer_t;

static void put_char(writer_t *w, char c)
{
    if (w->len >= w->cap) { w->overflow = true; return; }
    w->buf[w->len++] = c;
}

static void put_str(writer_t *w, const char *s)
{
    while (*s) put_char(w, *s++);
}

static void put_uint(writer_t *w, uint32_t v)
{
    char tmp[10];
    int  n = 0;
    do { tmp[n++] = (char)('0' + (v % 10u)); v /= 10u; } while (v && n < 10);
    while (n) put_char(w, tmp[--n]);
}

static void put_int(writer_t *w, int32_t v)
{
    if (v < 0) { put_char(w, '-'); put_uint(w, (uint32_t)(-(v + 1)) + 1u); }
    else       { put_uint(w, (uint32_t)v); }
}

static void put_hex(writer_t *w, uint32_t v, int digits)
{
    static const char HEX[] = "0123456789ABCDEF";
    for (int i = digits - 1; i >= 0; i--) put_char(w, HEX[(v >> (i * 4)) & 0xFu]);
}

static void put_bytes(writer_t *w, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) put_hex(w, b[i], 2);
}

size_t psu_link_encode(const psu_msg_t *msg, char *buf, size_t buf_size)
{
    if (!msg || !buf || buf_size < 2) return 0;

    writer_t w = { buf, buf_size - 1, 0, false };
    put_char(&w, '$');

    switch (msg->type) {
    case PSU_MSG_HELLO:
        put_str(&w, "HELO,");
        put_uint(&w, msg->u.hello.proto_ver);
        break;
    case PSU_MSG_CAP:
        put_str(&w, "CAP,");
        put_uint(&w, msg->u.cap.proto_ver);  put_char(&w, ',');
        put_uint(&w, msg->u.cap.node_type);  put_char(&w, ',');
        put_hex (&w, msg->u.cap.caps, 4);    put_char(&w, ',');
        put_uint(&w, msg->u.cap.v_max_cv);   put_char(&w, ',');
        put_uint(&w, msg->u.cap.i_max_ca);   put_char(&w, ',');
        put_uint(&w, msg->u.cap.fw_ver);
        break;
    case PSU_MSG_STATUS:
        put_str(&w, "ST,");
        put_uint(&w, msg->u.status.seq);     put_char(&w, ',');
        put_uint(&w, msg->u.status.v_cv);    put_char(&w, ',');
        put_int (&w, msg->u.status.i_ca);    put_char(&w, ',');
        put_uint(&w, msg->u.status.mode);    put_char(&w, ',');
        put_hex (&w, msg->u.status.flags, 2);
        break;
    case PSU_MSG_SET:
        if (!msg->u.set.has_v && !msg->u.set.has_i) return 0;   // 空的 SET 沒有意義
        put_str(&w, "SET,");
        put_uint(&w, msg->u.set.seq);        put_char(&w, ',');
        if (msg->u.set.has_v) put_uint(&w, msg->u.set.v_cv);
        put_char(&w, ',');
        if (msg->u.set.has_i) put_uint(&w, msg->u.set.i_ca);
        break;
    case PSU_MSG_ACK:
        put_str(&w, "ACK,");
        put_uint(&w, msg->u.ack.seq);        put_char(&w, ',');
        put_uint(&w, msg->u.ack.result);
        break;
    case PSU_MSG_PAIR_KEY:
        put_str(&w, "PKH,");
        put_uint(&w, msg->u.pair_key.proto_ver); put_char(&w, ',');
        put_uint(&w, msg->u.pair_key.role);      put_char(&w, ',');
        put_bytes(&w, msg->u.pair_key.pk, PSU_KEY_LEN);
        break;
    case PSU_MSG_PAIR_COMMIT:
        put_str(&w, "PCM,");
        put_bytes(&w, msg->u.pair_commit.c, PSU_TAG_LEN);
        break;
    case PSU_MSG_PAIR_NONCE:
        put_str(&w, "PNC,");
        put_uint(&w, msg->u.pair_nonce.role);    put_char(&w, ',');
        put_bytes(&w, msg->u.pair_nonce.n, PSU_NONCE_LEN);
        break;
    case PSU_MSG_PAIR_CONFIRM:
        put_str(&w, "PCF,");
        put_uint(&w, msg->u.pair_confirm.role);  put_char(&w, ',');
        put_bytes(&w, msg->u.pair_confirm.tag, PSU_TAG_LEN);
        break;
    case PSU_MSG_PAIR_REJECT:
        put_str(&w, "PRJ,");
        put_uint(&w, msg->u.pair_reject.role);   put_char(&w, ',');
        put_uint(&w, msg->u.pair_reject.reason);
        break;
    case PSU_MSG_SESS_INIT:
        put_str(&w, "SH1,");
        put_bytes(&w, msg->u.sess_init.n, PSU_NONCE_LEN);
        break;
    case PSU_MSG_SESS_REPLY:
        put_str(&w, "SH2,");
        put_bytes(&w, msg->u.sess_reply.n, PSU_NONCE_LEN);   put_char(&w, ',');
        put_bytes(&w, msg->u.sess_reply.tag, PSU_TAG_LEN);
        break;
    case PSU_MSG_SESS_FINISH:
        put_str(&w, "SH3,");
        put_bytes(&w, msg->u.sess_finish.tag, PSU_TAG_LEN);
        break;
    case PSU_MSG_SESS_REQUEST:
        put_str(&w, "SHR");
        break;
    default:
        return 0;
    }

    uint16_t crc = psu_link_crc16((const uint8_t *)buf + 1, w.len - 1);
    put_char(&w, '*');
    put_hex (&w, crc, 4);
    put_char(&w, '\n');

    if (w.overflow) return 0;
    buf[w.len] = '\0';
    return w.len;
}

// ─── 解碼 ────────────────────────────────────────────────────────────────────

#define MAX_FIELDS 8

typedef struct {
    const char *p;
    size_t      n;
} field_t;

static bool tok_eq(const field_t *f, const char *s)
{
    size_t i = 0;
    for (; i < f->n; i++) {
        if (s[i] == '\0' || s[i] != f->p[i]) return false;
    }
    return s[i] == '\0';
}

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

// 十進位無號整數；空欄位或非數字字元都算錯
static bool parse_uint(const field_t *f, uint32_t max, uint32_t *out)
{
    if (f->n == 0 || f->n > 10) return false;
    uint32_t v = 0;
    for (size_t i = 0; i < f->n; i++) {
        char c = f->p[i];
        if (c < '0' || c > '9') return false;
        uint32_t d = (uint32_t)(c - '0');
        // 超過 max。先比 d：max 小於 9 時 (max - d) 會無號下溢，讓任何值都通過
        if (d > max || v > (max - d) / 10u) return false;
        v = v * 10u + d;
    }
    *out = v;
    return true;
}

static bool parse_int16(const field_t *f, int16_t *out)
{
    if (f->n > 0 && f->p[0] == '-') {
        field_t rest = { f->p + 1, f->n - 1 };
        uint32_t v;
        if (!parse_uint(&rest, 32768u, &v)) return false;
        *out = (int16_t)(-(int32_t)v);
        return true;
    }
    uint32_t v;
    if (!parse_uint(f, 32767u, &v)) return false;
    *out = (int16_t)v;
    return true;
}

static bool parse_hex_field(const field_t *f, size_t max_digits, uint32_t *out)
{
    if (f->n == 0 || f->n > max_digits) return false;
    uint32_t v = 0;
    for (size_t i = 0; i < f->n; i++) {
        int h = hex_val(f->p[i]);
        if (h < 0) return false;
        v = (v << 4) | (uint32_t)h;
    }
    *out = v;
    return true;
}

// 固定長度的位元組欄位（2n 個十六進位字元，大小寫皆可）
static bool parse_bytes(const field_t *f, uint8_t *out, size_t n)
{
    if (f->n != 2 * n) return false;
    for (size_t i = 0; i < n; i++) {
        int hi = hex_val(f->p[2 * i]), lo = hex_val(f->p[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static bool parse_role(const field_t *f, uint8_t *role)
{
    uint32_t r;
    if (!parse_uint(f, 1u, &r)) return false;
    *role = (uint8_t)r;
    return true;
}

psu_link_result_t psu_link_decode(const char *line, size_t len, psu_msg_t *out)
{
    if (!line || !out) return PSU_LINK_BAD_FIELDS;

    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) len--;
    if (len == 0 || line[0] != '$') return PSU_LINK_NOT_FRAME;
    if (len > PSU_LINK_MAX_LINE - 2) return PSU_LINK_TOO_LONG;

    // "...*XXXX" —— '*' 必須剛好在倒數第 5 個位置
    if (len < 6 || line[len - 5] != '*') return PSU_LINK_BAD_CRC;
    field_t crc_f = { line + len - 4, 4 };
    uint32_t crc_rx;
    if (!parse_hex_field(&crc_f, 4, &crc_rx)) return PSU_LINK_BAD_CRC;
    size_t body_len = len - 6;   // 去掉 '$' 與 "*XXXX"
    if (psu_link_crc16((const uint8_t *)line + 1, body_len) != (uint16_t)crc_rx)
        return PSU_LINK_BAD_CRC;

    // 以 ',' 切欄位
    field_t f[MAX_FIELDS];
    size_t  nf = 0;
    const char *body = line + 1;
    size_t start = 0;
    for (size_t i = 0; i <= body_len; i++) {
        if (i == body_len || body[i] == ',') {
            if (nf == MAX_FIELDS) return PSU_LINK_BAD_FIELDS;
            f[nf].p = body + start;
            f[nf].n = i - start;
            nf++;
            start = i + 1;
        }
    }

    uint32_t a, b, c, d, e;
    out->type = PSU_MSG_NONE;

    if (tok_eq(&f[0], "HELO")) {
        if (nf != 2 || !parse_uint(&f[1], 255u, &a)) return PSU_LINK_BAD_FIELDS;
        out->type = PSU_MSG_HELLO;
        out->u.hello.proto_ver = (uint8_t)a;

    } else if (tok_eq(&f[0], "CAP")) {
        uint32_t caps;
        if (nf != 7 ||
            !parse_uint(&f[1], 255u, &a) || !parse_uint(&f[2], 255u, &b) ||
            !parse_hex_field(&f[3], 4, &caps) ||
            !parse_uint(&f[4], 65535u, &c) || !parse_uint(&f[5], 65535u, &d) ||
            !parse_uint(&f[6], 65535u, &e))
            return PSU_LINK_BAD_FIELDS;
        out->type = PSU_MSG_CAP;
        out->u.cap.proto_ver = (uint8_t)a;
        out->u.cap.node_type = (uint8_t)b;
        out->u.cap.caps      = (uint16_t)caps;
        out->u.cap.v_max_cv  = (uint16_t)c;
        out->u.cap.i_max_ca  = (uint16_t)d;
        out->u.cap.fw_ver    = (uint16_t)e;

    } else if (tok_eq(&f[0], "ST")) {
        int16_t  i_ca;
        uint32_t flags;
        if (nf != 6 ||
            !parse_uint(&f[1], 65535u, &a) || !parse_uint(&f[2], 65535u, &b) ||
            !parse_int16(&f[3], &i_ca) || !parse_uint(&f[4], 255u, &c) ||
            !parse_hex_field(&f[5], 2, &flags))
            return PSU_LINK_BAD_FIELDS;
        out->type = PSU_MSG_STATUS;
        out->u.status.seq   = (uint16_t)a;
        out->u.status.v_cv  = (uint16_t)b;
        out->u.status.i_ca  = i_ca;
        out->u.status.mode  = (uint8_t)c;
        out->u.status.flags = (uint8_t)flags;

    } else if (tok_eq(&f[0], "SET")) {
        if (nf != 4 || !parse_uint(&f[1], 65535u, &a)) return PSU_LINK_BAD_FIELDS;
        out->u.set.seq   = (uint16_t)a;
        out->u.set.has_v = f[2].n > 0;
        out->u.set.has_i = f[3].n > 0;
        out->u.set.v_cv  = 0;
        out->u.set.i_ca  = 0;
        if (!out->u.set.has_v && !out->u.set.has_i) return PSU_LINK_BAD_FIELDS;
        if (out->u.set.has_v) {
            if (!parse_uint(&f[2], 65535u, &b)) return PSU_LINK_BAD_FIELDS;
            out->u.set.v_cv = (uint16_t)b;
        }
        if (out->u.set.has_i) {
            if (!parse_uint(&f[3], 65535u, &c)) return PSU_LINK_BAD_FIELDS;
            out->u.set.i_ca = (uint16_t)c;
        }
        out->type = PSU_MSG_SET;

    } else if (tok_eq(&f[0], "ACK")) {
        if (nf != 3 || !parse_uint(&f[1], 65535u, &a) || !parse_uint(&f[2], 255u, &b))
            return PSU_LINK_BAD_FIELDS;
        out->type = PSU_MSG_ACK;
        out->u.ack.seq    = (uint16_t)a;
        out->u.ack.result = (uint8_t)b;

    } else if (tok_eq(&f[0], "PKH")) {
        if (nf != 4 || !parse_uint(&f[1], 255u, &a) ||
            !parse_role(&f[2], &out->u.pair_key.role) ||
            !parse_bytes(&f[3], out->u.pair_key.pk, PSU_KEY_LEN))
            return PSU_LINK_BAD_FIELDS;
        out->u.pair_key.proto_ver = (uint8_t)a;
        out->type = PSU_MSG_PAIR_KEY;

    } else if (tok_eq(&f[0], "PCM")) {
        if (nf != 2 || !parse_bytes(&f[1], out->u.pair_commit.c, PSU_TAG_LEN))
            return PSU_LINK_BAD_FIELDS;
        out->type = PSU_MSG_PAIR_COMMIT;

    } else if (tok_eq(&f[0], "PNC")) {
        if (nf != 3 || !parse_role(&f[1], &out->u.pair_nonce.role) ||
            !parse_bytes(&f[2], out->u.pair_nonce.n, PSU_NONCE_LEN))
            return PSU_LINK_BAD_FIELDS;
        out->type = PSU_MSG_PAIR_NONCE;

    } else if (tok_eq(&f[0], "PCF")) {
        if (nf != 3 || !parse_role(&f[1], &out->u.pair_confirm.role) ||
            !parse_bytes(&f[2], out->u.pair_confirm.tag, PSU_TAG_LEN))
            return PSU_LINK_BAD_FIELDS;
        out->type = PSU_MSG_PAIR_CONFIRM;

    } else if (tok_eq(&f[0], "PRJ")) {
        if (nf != 3 || !parse_role(&f[1], &out->u.pair_reject.role) ||
            !parse_uint(&f[2], 255u, &a))
            return PSU_LINK_BAD_FIELDS;
        out->u.pair_reject.reason = (uint8_t)a;
        out->type = PSU_MSG_PAIR_REJECT;

    } else if (tok_eq(&f[0], "SH1")) {
        if (nf != 2 || !parse_bytes(&f[1], out->u.sess_init.n, PSU_NONCE_LEN))
            return PSU_LINK_BAD_FIELDS;
        out->type = PSU_MSG_SESS_INIT;

    } else if (tok_eq(&f[0], "SH2")) {
        if (nf != 3 || !parse_bytes(&f[1], out->u.sess_reply.n, PSU_NONCE_LEN) ||
            !parse_bytes(&f[2], out->u.sess_reply.tag, PSU_TAG_LEN))
            return PSU_LINK_BAD_FIELDS;
        out->type = PSU_MSG_SESS_REPLY;

    } else if (tok_eq(&f[0], "SH3")) {
        if (nf != 2 || !parse_bytes(&f[1], out->u.sess_finish.tag, PSU_TAG_LEN))
            return PSU_LINK_BAD_FIELDS;
        out->type = PSU_MSG_SESS_FINISH;

    } else if (tok_eq(&f[0], "SHR")) {
        if (nf != 1) return PSU_LINK_BAD_FIELDS;
        out->type = PSU_MSG_SESS_REQUEST;

    } else {
        return PSU_LINK_BAD_TYPE;
    }

    return PSU_LINK_OK;
}
