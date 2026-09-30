#pragma once
// psu_link.h — 充電控制板 ↔ 電源節點 連線協定（UART / ESP-NOW 共用）
//
// 純資料轉換，無 OS 依賴，無副作用；只用 <stdint.h> <stdbool.h> <stddef.h>。
// 控制板（TES charger）與電源節點（LianMing PSU Controller、電流量測模組…）
// 兩端共用這一份定義，改一邊就不會漏改另一邊。
//
// ── 線上格式 ────────────────────────────────────────────────────────────────
//
//   $<TYPE>,<field>,<field>,...*<CRC16>\n
//
//   - 一行一則訊息，ASCII，行尾 '\n'（前面可有 '\r'，解碼時忽略）
//   - CRC-16/CCITT-FALSE（poly 0x1021, init 0xFFFF），涵蓋 '$' 之後、'*' 之前
//     的所有位元組，以 4 位大寫十六進位寫在 '*' 之後
//   - 數值一律是十進位整數；電壓電流以 0.01 為單位（4820 = 48.20 V）
//   - 不以 '$' 開頭的行不屬於本協定。電源節點可以繼續把它們當成人下的
//     文字指令（PAIR、ON、OFF…），控制板則直接忽略
//
// ── 訊息 ─────────────────────────────────────────────────────────────────────
//
//   方向            訊息                                        用途
//   控制板 → 節點   $HELO,<ver>                                 詢問能力；節點回 CAP
//   節點 → 控制板   $CAP,<ver>,<type>,<caps>,<vmax>,<imax>,<fw> 節點類型與能力（開機時與收到 HELO 時送）
//   節點 → 控制板   $ST,<seq>,<v>,<i>,<mode>,<flags>            狀態；輸出中每 100 ms、待機每 1 s
//   控制板 → 節點   $SET,<seq>,<v>,<i>                          設定值；<v> 或 <i> 可留空表示不變
//   節點 → 控制板   $ACK,<seq>,<result>                         回應 SET
//
//   <caps> 與 <flags> 以十六進位寫（caps 4 位、flags 2 位），其餘欄位十進位。
//   ST 在待機時照樣送 —— 它同時是心跳，沒有另外的 HB 訊息。
//
// ── 配對與連線驗證（ESP-NOW 用；UART 是實體線，不需要）──────────────────────
//
//   位元組欄位一律寫成大寫十六進位、長度固定（32 位元組 = 64 字元）。
//   <role>：0 = 控制板、1 = 電源節點。流程與金鑰推導見 psu_pair.h、psu_sess.h。
//
//   $PKH,<ver>,<role>,<pk>      公鑰（X25519，32 B）。節點廣播，控制板單播回覆
//   $PCM,<c>                    節點對自己亂數的承諾值（16 B）
//   $PNC,<role>,<n>             亂數（16 B）。控制板先送，節點收到後才送自己的
//   $PCF,<role>,<tag>           使用者按了確認 + 金鑰確認值（16 B）
//   $PRJ,<role>,<reason>        取消配對（psu_pair_fail_t）
//   $SH1,<n>                    控制板 → 節點：開始連線握手
//   $SH2,<n>,<tag>              節點 → 控制板：握手回應
//   $SH3,<tag>                  控制板 → 節點：握手完成
//   $SHR                        節點 → 控制板：請重新握手（節點重開機、失去連線金鑰）
//
//   握手完成後，其餘訊息在 ESP-NOW 上都必須帶驗證尾碼（見 psu_sess.h）：
//     $ST,...*<CRC16>~<計數器 8 hex><驗證碼 16 hex>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PSU_LINK_PROTO_VER   2u     // 1 = 舊的 "V=..,I=.." / "HB" / "SET:V=" 文字協定
#define PSU_LINK_MAX_LINE    96u    // 含 '\n' 與結尾 NUL 的緩衝區大小上限
#define PSU_LINK_MAX_AUTH_LINE (PSU_LINK_MAX_LINE + 26u)   // 加上 "~<8 hex><16 hex>" 驗證尾碼

#define PSU_KEY_LEN    32u   // X25519 公鑰、長期金鑰
#define PSU_NONCE_LEN  16u
#define PSU_TAG_LEN    16u

#define PSU_ROLE_CONTROLLER  0u
#define PSU_ROLE_NODE        1u

// ─── 節點類型 ────────────────────────────────────────────────────────────────
typedef enum {
    PSU_NODE_UNKNOWN   = 0,
    PSU_NODE_RECTIFIER = 1,   // 可控整流模組（例：LianMing PSU Controller）
    PSU_NODE_METER     = 2,   // 只量測不控制（搭配沒有數位通訊的旋鈕電源）
} psu_node_type_t;

// ─── 能力位元（CAP.caps）────────────────────────────────────────────────────
#define PSU_CAP_REPORT_V     (1u << 0)   // ST 的電壓欄位有意義
#define PSU_CAP_REPORT_I     (1u << 1)   // ST 的電流欄位有意義
#define PSU_CAP_SET_V        (1u << 2)   // 接受 SET 的電壓欄位
#define PSU_CAP_SET_I        (1u << 3)   // 接受 SET 的電流欄位
#define PSU_CAP_REPORT_MODE  (1u << 4)   // ST 的 mode 欄位（CV/CC）有意義

// ─── 輸出模式（ST.mode）─────────────────────────────────────────────────────
typedef enum {
    PSU_MODE_UNKNOWN = 0,
    PSU_MODE_OFF     = 1,
    PSU_MODE_CV      = 2,   // 定電壓
    PSU_MODE_CC      = 3,   // 定電流（被電流上限限住）
} psu_mode_t;

// ─── 狀態旗標（ST.flags）────────────────────────────────────────────────────
#define PSU_ST_V_VALID       (1u << 0)   // 本筆電壓是有效量測
#define PSU_ST_I_VALID       (1u << 1)   // 本筆電流是有效量測
#define PSU_ST_OUTPUT_ON     (1u << 2)   // 輸出開啟中
#define PSU_ST_SOFT_START    (1u << 3)   // 軟啟動爬升中
#define PSU_ST_FAULT         (1u << 4)   // 節點回報異常（細節看節點自己的介面）

// ─── ACK 結果碼 ──────────────────────────────────────────────────────────────
typedef enum {
    PSU_ACK_OK          = 0,
    PSU_ACK_RANGE       = 1,   // 數值超出節點範圍，未套用
    PSU_ACK_UNSUPPORTED = 2,   // 節點沒有對應能力（例：量測模組收到 SET）
} psu_ack_result_t;

// ─── 訊息結構 ────────────────────────────────────────────────────────────────
typedef enum {
    PSU_MSG_NONE   = 0,
    PSU_MSG_HELLO  = 1,
    PSU_MSG_CAP    = 2,
    PSU_MSG_STATUS = 3,
    PSU_MSG_SET    = 4,
    PSU_MSG_ACK    = 5,
    PSU_MSG_PAIR_KEY     = 6,    // PKH
    PSU_MSG_PAIR_COMMIT  = 7,    // PCM
    PSU_MSG_PAIR_NONCE   = 8,    // PNC
    PSU_MSG_PAIR_CONFIRM = 9,    // PCF
    PSU_MSG_PAIR_REJECT  = 10,   // PRJ
    PSU_MSG_SESS_INIT    = 11,   // SH1
    PSU_MSG_SESS_REPLY   = 12,   // SH2
    PSU_MSG_SESS_FINISH  = 13,   // SH3
    PSU_MSG_SESS_REQUEST = 14,   // SHR
} psu_msg_type_t;

typedef struct {
    uint8_t  proto_ver;
} psu_msg_hello_t;

typedef struct {
    uint8_t  proto_ver;
    uint8_t  node_type;     // psu_node_type_t
    uint16_t caps;          // PSU_CAP_*
    uint16_t v_max_cv;      // 0.01 V；0 = 未知
    uint16_t i_max_ca;      // 0.01 A；0 = 未知
    uint16_t fw_ver;        // 節點韌體版本，格式由節點自訂（例：130 = v1.3.0）
} psu_msg_cap_t;

typedef struct {
    uint16_t seq;           // 節點遞增，溢位後回繞
    uint16_t v_cv;          // 0.01 V
    int16_t  i_ca;          // 0.01 A，量測模組可能出現負值
    uint8_t  mode;          // psu_mode_t
    uint8_t  flags;         // PSU_ST_*
} psu_msg_status_t;

typedef struct {
    uint16_t seq;           // 控制板遞增，ACK 會帶回同一個值
    bool     has_v;
    uint16_t v_cv;          // 0.01 V，has_v 為 false 時不送
    bool     has_i;
    uint16_t i_ca;          // 0.01 A，has_i 為 false 時不送
} psu_msg_set_t;

typedef struct {
    uint16_t seq;
    uint8_t  result;        // psu_ack_result_t
} psu_msg_ack_t;

typedef struct { uint8_t proto_ver; uint8_t role; uint8_t pk[PSU_KEY_LEN]; } psu_msg_pair_key_t;
typedef struct { uint8_t c[PSU_TAG_LEN]; }                                 psu_msg_pair_commit_t;
typedef struct { uint8_t role; uint8_t n[PSU_NONCE_LEN]; }                 psu_msg_pair_nonce_t;
typedef struct { uint8_t role; uint8_t tag[PSU_TAG_LEN]; }                 psu_msg_pair_confirm_t;
typedef struct { uint8_t role; uint8_t reason; }                           psu_msg_pair_reject_t;
typedef struct { uint8_t n[PSU_NONCE_LEN]; }                               psu_msg_sess_init_t;
typedef struct { uint8_t n[PSU_NONCE_LEN]; uint8_t tag[PSU_TAG_LEN]; }     psu_msg_sess_reply_t;
typedef struct { uint8_t tag[PSU_TAG_LEN]; }                               psu_msg_sess_finish_t;

typedef struct {
    psu_msg_type_t type;
    union {
        psu_msg_hello_t  hello;
        psu_msg_cap_t    cap;
        psu_msg_status_t status;
        psu_msg_set_t    set;
        psu_msg_ack_t    ack;
        psu_msg_pair_key_t     pair_key;
        psu_msg_pair_commit_t  pair_commit;
        psu_msg_pair_nonce_t   pair_nonce;
        psu_msg_pair_confirm_t pair_confirm;
        psu_msg_pair_reject_t  pair_reject;
        psu_msg_sess_init_t    sess_init;
        psu_msg_sess_reply_t   sess_reply;
        psu_msg_sess_finish_t  sess_finish;
    } u;
} psu_msg_t;

typedef enum {
    PSU_LINK_OK          = 0,
    PSU_LINK_NOT_FRAME   = 1,   // 不是 '$' 開頭 —— 不屬於本協定，呼叫端自行決定怎麼處理
    PSU_LINK_TOO_LONG    = 2,
    PSU_LINK_BAD_CRC     = 3,   // 含找不到 '*' 或 CRC 格式錯誤
    PSU_LINK_BAD_TYPE    = 4,   // CRC 正確但類型不認得（對方版本較新）
    PSU_LINK_BAD_FIELDS  = 5,   // 欄位數量或數值格式／範圍不對
} psu_link_result_t;

// ─── API ─────────────────────────────────────────────────────────────────────

// 編碼成一行（含 '\n' 並以 NUL 結尾）。回傳不含 NUL 的長度；緩衝區不夠或
// 訊息類型不合法時回傳 0。buf_size 取 PSU_LINK_MAX_LINE 一定夠用。
size_t psu_link_encode(const psu_msg_t *msg, char *buf, size_t buf_size);

// 解碼一行。len 不含結尾 NUL；行尾的 '\n' / '\r' 可有可無。
psu_link_result_t psu_link_decode(const char *line, size_t len, psu_msg_t *out);

// CRC-16/CCITT-FALSE。對 "123456789" 應得 0x29B1。
uint16_t psu_link_crc16(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif
