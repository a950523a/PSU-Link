#pragma once
// psu_fw.h — 節點韌體更新的兩端狀態機（2026-10-28）：控制板送（psu_fw_tx）、節點收（psu_fw_rx）。
//
// 訊息格式在 psu_link.h（FWB／FWD／FWE／FWA／FWX）。這裡只管順序、位置、重送與逾時：
//   * 一次一塊，等到 FWA 才送下一塊；FWA 帶「節點下一個要的位置」
//   * 送的人逾時就重送同一則；節點收到重複或跳號的 FWD 不寫，回 FWA 說它要哪裡
//   * 節點寫 flash、算 SHA-256、驗證映像都在呼叫端的 ops 裡做 —— 這份程式不依賴平台，
//     控制板（ESP32）、電源節點（ESP32）、之後的量測節點（小 MCU）共用
//
// 純資料轉換，無 OS 依賴；時間由呼叫端傳入（毫秒，可回繞）。

#include <stdbool.h>
#include <stdint.h>
#include "psu_link/psu_link.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PSU_FW_TX_RETRY_MS     1000u    // 等 FWA 多久就重送
#define PSU_FW_TX_BEGIN_MS     5000u    // FWB 等比較久：節點可能要先準備分區
#define PSU_FW_TX_MAX_TRIES    10u      // 同一則送幾次都沒回應就放棄
#define PSU_FW_RX_IDLE_MS      30000u   // 節點：開始之後這麼久沒收到東西就放棄這次更新

// ─── 節點（收）───────────────────────────────────────────────────────────────

typedef struct {
    // 收到 FWB：檢查名稱是不是自己的、大小放不放得下，準備寫入。回傳 psu_fw_result_t
    uint8_t (*begin)(void *ctx, const psu_msg_fw_begin_t *b);
    // 依序寫入（offset 一定是接著上一塊）。回傳 PSU_FW_OK 或 PSU_FW_FLASH
    uint8_t (*write)(void *ctx, uint32_t offset, const uint8_t *data, uint8_t len);
    // 全部收完：比對 SHA-256、驗證映像、設定下次開機。回傳 PSU_FW_OK／PSU_FW_HASH／PSU_FW_FLASH。
    // 成功後由呼叫端在送出 FWA 之後重新開機（這裡不重開）
    uint8_t (*finish)(void *ctx);
    // 放棄這次更新（中止、逾時、出錯）：丟掉寫到一半的東西，原本的韌體照常
    void    (*abort)(void *ctx);
    void *ctx;
} psu_fw_rx_ops_t;

typedef struct {
    const psu_fw_rx_ops_t *ops;
    bool     active;
    uint32_t size;
    uint32_t next;          // 下一個要的位置
    uint8_t  sha256[32];    // 這次的 FWB：重複收到同一個 FWB 時從原位置接著傳，不重來
    uint32_t last_ms;
} psu_fw_rx_t;

void psu_fw_rx_init(psu_fw_rx_t *rx, const psu_fw_rx_ops_t *ops);
// 處理一則 FWB／FWD／FWE／FWX（其他類型回傳 false）。要回覆時寫進 reply、回傳 true
bool psu_fw_rx_handle(psu_fw_rx_t *rx, const psu_msg_t *m, uint32_t now_ms, psu_msg_t *reply);
// 定期呼叫：太久沒收到資料就放棄
void psu_fw_rx_tick(psu_fw_rx_t *rx, uint32_t now_ms);

// ─── 控制板（送）─────────────────────────────────────────────────────────────

typedef enum {
    PSU_FW_TX_IDLE = 0,
    PSU_FW_TX_BEGIN,        // 送了 FWB，等 FWA
    PSU_FW_TX_DATA,         // 送 FWD 中
    PSU_FW_TX_END,          // 送了 FWE，等節點驗證、切換
    PSU_FW_TX_DONE,         // 節點說成功，接著會重開機。result = NOT_BEGUN：成功的回應掉了、沒親眼看到
                            // （重送 FWE 時節點已經重開），呼叫端用節點重新連上後的 INF 版本確認
    PSU_FW_TX_FAILED,       // result 是原因
} psu_fw_tx_state_t;

typedef struct {
    psu_fw_tx_state_t state;
    uint8_t           result;    // 失敗原因（psu_fw_result_t）
    const uint8_t    *img;
    uint32_t          size;
    psu_msg_fw_begin_t begin;
    uint32_t          next;      // 送出中那一塊的位置
    uint8_t           len;       // 送出中那一塊的長度
    uint32_t          sent_ms;
    uint8_t           tries;
} psu_fw_tx_t;

// 開始：寫好 FWB 到 out。img 要在整個傳輸期間都有效（呼叫端的緩衝區）
void psu_fw_tx_start(psu_fw_tx_t *tx, const uint8_t *img, uint32_t size, const uint8_t sha256[32],
                     const char *name, const char *ver, uint32_t now_ms, psu_msg_t *out);
// 收到 FWA／FWX（其他類型回傳 false）。要送下一則時寫進 out、回傳 true
bool psu_fw_tx_on_msg(psu_fw_tx_t *tx, const psu_msg_t *in, uint32_t now_ms, psu_msg_t *out);
// 定期呼叫：逾時就重送（out，回傳 true）；重送太多次就失敗，並送 FWX 告訴節點
bool psu_fw_tx_tick(psu_fw_tx_t *tx, uint32_t now_ms, psu_msg_t *out);
// 放棄（例如連線斷了、使用者取消）：寫 FWX 到 out
void psu_fw_tx_abort(psu_fw_tx_t *tx, uint8_t reason, psu_msg_t *out);
bool psu_fw_tx_running(const psu_fw_tx_t *tx);   // BEGIN／DATA／END
int  psu_fw_tx_percent(const psu_fw_tx_t *tx);   // 0–100

#ifdef __cplusplus
}
#endif
