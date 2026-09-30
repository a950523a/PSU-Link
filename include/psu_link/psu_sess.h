#pragma once
// psu_sess.h — 配對後的連線握手與逐封包驗證（ESP-NOW 用）
//
// 為什麼需要：ESP-NOW 的 LMK 加密擋不住偽造。裝置永遠會收廣播與未加密的單播
// 封包，而接收回呼分不出封包有沒有加密過 —— 冒用控制板的 MAC 送一則未加密的
// $SET，節點照樣收到。所以驗證放在協定這一層：每則訊息帶計數器與驗證碼，
// 驗不過或計數器沒有往前的一律丟掉，偽造與重送（錄下舊封包再播）都擋得住。
//
// ── 握手（每次連線：任一邊開機、失去同步時）───────────────────────────────
//
//   C → N   SH1(Nc)
//   N → C   SH2(Nn, HMAC(LTK, "SH2" ‖ Nc ‖ Nn)[0:16])
//   C → N   SH3(HMAC(LTK, "SH3" ‖ Nn ‖ Nc)[0:16])
//   連線金鑰 SK = HMAC(LTK, "SES" ‖ Nc ‖ Nn)，雙方計數器歸零
//
//   LTK 是配對時算出的長期金鑰。亂數每次都新產生，所以錄下的舊握手與舊訊框
//   在新連線裡全部無效。節點開機後沒有 SK，會每秒送 SHR 請控制板重新握手；
//   任一邊連續 3 則驗不過，也會重新握手。
//
//   節點收到 SH1 時不會丟掉現有的 SK —— 要等 SH3（或第一則用新 SK 驗過的訊框）
//   才切換。偽造的 SH1 因此只能讓節點多算一次，打斷不了現有連線。
//
// ── 訊框 ──────────────────────────────────────────────────────────────────────
//
//   <原本的一行，不含 \n>~<計數器 8 hex><驗證碼 16 hex>\n
//   驗證碼 = HMAC(SK, 方向 ‖ 計數器(大端 4 B) ‖ 原本的一行)[0:8]
//   方向為送出方的角色：'C' 控制板、'N' 節點 —— 反射回去的訊框驗不過
//
//   握手訊息（SH1/SH2/SH3/SHR）與配對訊息本身不帶尾碼。
//   呼叫端規則：在 ESP-NOW 上，psu_sess_unwrap() 回傳 PSU_SESS_PLAIN 的行，只有
//   解碼出來是配對或握手訊息才處理，其他一律丟掉。
//
// 資料進、資料出：不做 I/O、不讀時間，時間由參數傳入。

#include "psu_link/psu_link.h"
#include "psu_link/psu_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PSU_SESS_RESEND_MS     1000u   // SH1 / SHR 重送間隔（也是重新握手的最短間隔）
#define PSU_SESS_BAD_REKEY        3u   // 連續幾則驗不過就重新握手
#define PSU_SESS_TAG_LEN          8u

typedef enum {
    PSU_SESS_OK = 0,        // 驗證通過；原本的一行是 line[0 .. *inner_len)
    PSU_SESS_PLAIN,         // 沒有驗證尾碼（配對或握手訊息才可以這樣）
    PSU_SESS_NO_SESSION,    // 帶了尾碼，但還沒有連線金鑰
    PSU_SESS_BAD_TAG,       // 驗證碼不符：偽造、或雙方金鑰不同步
    PSU_SESS_REPLAY,        // 計數器沒有往前：重送的舊訊框
    PSU_SESS_MALFORMED,     // 尾碼格式不對
} psu_sess_result_t;

typedef struct {
    // ── 呼叫端可讀：統計 ──
    uint32_t n_ok, n_bad_tag, n_replay, n_plain_dropped, n_handshakes;

    // ── 內部 ──
    uint8_t  role;
    const psu_crypto_t *cr;
    uint8_t  ltk[PSU_KEY_LEN];
    bool     established;
    uint8_t  sk[PSU_KEY_LEN];
    uint32_t tx_ctr, rx_ctr;
    uint8_t  bad_streak;
    uint32_t next_tx_ms;

    // 控制板
    bool     hs_active;
    uint8_t  nc[PSU_NONCE_LEN];
    bool     send_finish;
    uint8_t  finish_tag[PSU_TAG_LEN];
    uint8_t  last_nn[PSU_NONCE_LEN];
    uint32_t last_rekey_ms;

    // 節點
    bool     pend;
    uint8_t  pend_sk[PSU_KEY_LEN];
    uint8_t  pend_nc[PSU_NONCE_LEN], pend_nn[PSU_NONCE_LEN];
    bool     send_reply;
} psu_sess_t;

// ltk 為配對存下的長期金鑰。控制板初始化後立刻開始握手；節點開始送 SHR。
void psu_sess_init(psu_sess_t *s, uint8_t role, const uint8_t ltk[PSU_KEY_LEN],
                   const psu_crypto_t *cr, uint32_t now_ms);

// 連線金鑰已建立，可以送收一般訊息
bool psu_sess_ready(const psu_sess_t *s);

// 控制板：重新握手（有頻率限制）。節點呼叫無作用。
void psu_sess_rekey(psu_sess_t *s, uint32_t now_ms);

// 餵進解碼後的 PSU_SESS_PLAIN 訊息。是握手訊息就處理並回傳 true。
bool psu_sess_rx(psu_sess_t *s, const psu_msg_t *m, uint32_t now_ms);

// 每次輪詢呼叫；回傳 true 表示要送 *out（一律單播給配對的對方，不加尾碼）
bool psu_sess_poll(psu_sess_t *s, uint32_t now_ms, psu_msg_t *out);

// 幫一行（psu_link_encode 的輸出）加上驗證尾碼。沒有連線金鑰時回傳 0。
// out 取 PSU_LINK_MAX_AUTH_LINE 一定夠用。
size_t psu_sess_wrap(psu_sess_t *s, const char *line, size_t len, char *out, size_t cap);

// 驗證並拆掉尾碼。回傳 PSU_SESS_OK 時，*inner_len 是原本那一行的長度（不含 '~' 以後）。
psu_sess_result_t psu_sess_unwrap(psu_sess_t *s, const char *line, size_t len,
                                  size_t *inner_len, uint32_t now_ms);

#ifdef __cplusplus
}
#endif
