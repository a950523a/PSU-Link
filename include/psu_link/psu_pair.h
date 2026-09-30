#pragma once
// psu_pair.h — ESP-NOW 配對：X25519 金鑰交換 + 6 位數配對碼人工比對
//
// 跟藍牙的「數字比對」（Secure Simple Pairing, Numeric Comparison）同一個想法：
// 雙方交換公鑰，節點先承諾自己的亂數、控制板再公開亂數，最後兩邊各自算出同一組
// 6 位數，顯示在兩邊的螢幕上。使用者看兩個數字一樣，在兩邊都按確認，才存下對方。
//
// 為什麼要承諾值：配對碼只有 6 位數（約 20 位元）。如果中間人能在看到雙方亂數
// 之後才決定自己的，就能暴力試到兩邊的數字剛好相同。節點先送 C = 承諾(Nn)，
// 看到控制板的 Nc 之後才公開 Nn，中間人就沒有試的機會 —— 成功率固定是 10⁻⁶。
//
// 流程（→ 為送出方向；控制板 = C，節點 = N）
//
//   N  → 廣播   PKH(PKn)                 節點進入配對後每 0.5 s 廣播
//   C  → N      PKH(PKc)                 控制板收到第一個節點公鑰就選定它
//   N  → C      PCM(Cn)                  Cn = HMAC(Nn, "PSU-PAIR-C" ‖ PKn ‖ PKc)[0:16]
//   C  → N      PNC(Nc)
//   N  → C      PNC(Nn)                  控制板驗證 Cn；不符 → 失敗（可能有中間人）
//   兩邊        配對碼 = be32(HMAC("PSU-PAIR-V", PKc ‖ PKn ‖ Nc ‖ Nn)[0:4]) mod 10⁶
//               長期金鑰 LTK = HMAC(X25519(sk, PK對方), "PSU-PAIR-K" ‖ Nc ‖ Nn ‖ MACc ‖ MACn)
//   使用者在兩邊按確認
//   各自   →    PCF(tag_role)            tag = HMAC(LTK, "PSU-PAIR-F" ‖ role ‖ PKc ‖ PKn)[0:16]
//   兩邊都確認、且對方的 tag 驗證通過 → DONE，呼叫端存下 peer_mac 與 ltk
//
// PCF 的 tag 同時證明雙方算出了同一把 LTK（金鑰確認），配對碼一樣但金鑰不同
// 的情況不會被接受。任一邊按取消、或逾時，送 PRJ 並失敗，什麼都不存。
//
// 資料進、資料出：本檔不做 I/O、不讀時間。呼叫端把收到的訊息餵給
// psu_pair_rx()，每次輪詢呼叫 psu_pair_poll() 取得要送出的訊息，時間由參數傳入。
// 遺失的封包靠 poll 每 0.5 s 重送當下階段的訊息，重複收到的訊息會被忽略或重答。

#include "psu_link/psu_link.h"
#include "psu_link/psu_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PSU_PAIR_SEARCH_MS    30000u   // 從開始到交換完亂數的時限
#define PSU_PAIR_CONFIRM_MS   60000u   // 顯示配對碼後等使用者確認的時限
#define PSU_PAIR_RESEND_MS      500u

typedef enum {
    PSU_PAIR_IDLE = 0,
    PSU_PAIR_SEARCHING,     // 節點：廣播公鑰中；控制板：等節點的公鑰
    PSU_PAIR_EXCHANGING,    // 已選定對方，交換承諾值與亂數中
    PSU_PAIR_CONFIRM,       // 配對碼已算出，等使用者（本地）與對方確認
    PSU_PAIR_DONE,          // 雙方都確認 —— peer_mac、ltk 可以存了
    PSU_PAIR_FAILED,
} psu_pair_state_t;

typedef enum {
    PSU_PAIR_FAIL_NONE = 0,
    PSU_PAIR_FAIL_TIMEOUT,        // 找不到對方，或使用者太久沒確認
    PSU_PAIR_FAIL_USER_REJECT,    // 本地使用者按了取消
    PSU_PAIR_FAIL_PEER_REJECT,    // 對方按了取消（或對方逾時）
    PSU_PAIR_FAIL_COMMIT,         // 承諾值不符 —— 可能有中間人
    PSU_PAIR_FAIL_CONFIRM,        // 金鑰確認值不符 —— 可能有中間人
    PSU_PAIR_FAIL_CRYPTO,         // 產生金鑰失敗、對方公鑰不合法
} psu_pair_fail_t;

typedef struct {
    // ── 呼叫端可讀 ──
    psu_pair_state_t state;
    psu_pair_fail_t  fail;
    uint32_t         code;        // CONFIRM / DONE 時有效，0 … 999999（顯示時補零到 6 位）
    bool             local_ok;    // 本地使用者已確認
    bool             peer_ok;     // 對方已確認且金鑰確認值正確
    uint8_t          peer_mac[6]; // EXCHANGING 起有效
    uint8_t          ltk[PSU_KEY_LEN];   // DONE 時有效：存進 NVS，給 psu_sess 用

    // ── 內部 ──
    uint8_t  role;
    const psu_crypto_t *cr;
    uint8_t  my_mac[6];
    uint8_t  sk[PSU_KEY_LEN], pk[PSU_KEY_LEN], peer_pk[PSU_KEY_LEN];
    uint8_t  n_mine[PSU_NONCE_LEN], n_peer[PSU_NONCE_LEN];
    uint8_t  commit[PSU_TAG_LEN];      // 控制板：收到的節點承諾值
    bool     have_commit, have_peer_nonce;
    bool     reply_nonce;              // 節點：重複收到 Nc 時再回一次 Nn
    bool     reply_confirm;            // 對方又送 PCF 時再回一次自己的（對方可能沒收到）
    uint8_t  reject_left;              // 失敗後還要送幾次 PRJ
    uint8_t  reject_reason;
    uint32_t deadline_ms, next_tx_ms;
} psu_pair_t;

void psu_pair_start(psu_pair_t *p, uint8_t role, const uint8_t my_mac[6],
                    const psu_crypto_t *cr, uint32_t now_ms);

// 收到的配對訊息（PKH / PCM / PNC / PCF / PRJ）。src_mac 為 ESP-NOW 來源位址。
// 不是配對訊息、或不是選定的對方送的，一律忽略。
void psu_pair_rx(psu_pair_t *p, const psu_msg_t *m, const uint8_t src_mac[6], uint32_t now_ms);

// 使用者在本地按了確認（accept = true）或取消
void psu_pair_user(psu_pair_t *p, bool accept, uint32_t now_ms);

// 每次輪詢呼叫。回傳 true 表示現在要送 *out；*broadcast = true 送廣播，
// 否則單播給 peer_mac。一次呼叫最多一則，呼叫端可在同一次輪詢內重複呼叫直到 false。
bool psu_pair_poll(psu_pair_t *p, uint32_t now_ms, psu_msg_t *out, bool *broadcast);

// 仍在進行中（還沒 DONE / FAILED / IDLE）
bool psu_pair_busy(const psu_pair_t *p);

#ifdef __cplusplus
}
#endif
