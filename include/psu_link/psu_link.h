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
//   節點 → 控制板   $PWR,<vac>,<pmax>,<ilim>,<src>              AC 輸入與可用功率（2026-10-17）；有變化時、
//                                                               回 HELO 時、以及每 30 s 送一次
//
//   控制板 → 節點   $CHN,<ch>                                   控制板目前的 WiFi 頻道（2026-10-18，ESP-NOW 用）；
//                                                               連線後與每 5 s 送一次，節點不在這個頻道就切過去
//   控制板 → 節點   $NET,<bssid>,<ssid>                         控制板目前所在的網路（2026-10-26，ESP-NOW 用）：
//                                                               連著路由器時是那台基地台，只開熱點時是自己的熱點。
//                                                               bssid 6 B、ssid 1–32 B，都寫成大寫十六進位。
//                                                               有變化時與每 30 s 送一次
//
//   節點 → 控制板   $INF,<hw>,<fw>,<boot>,<uid>                 節點身分（2026-10-28）：緊接在 CAP 之後送。
//                                                               硬體版本（十進位，節點類型自己編）、完整韌體版本
//                                                               字串、開機程式版本（沒有獨立開機程式就留空）、
//                                                               識別碼（MAC 或晶片 ID，1–8 B 十六進位）
//
//   INF：CAP 只說節點「能做什麼」，<fw> 也只是節點自訂的 16 位元整數，裝不下 v1.4.0-8-g9b60735
//   這種版本。控制板要顯示接了什麼、判斷更新檔是不是這台的，就看 INF。CAP 格式不變：
//   不送 INF 的舊節點照常運作，控制板顯示「版本未知」。版本字串只允許 A–Z a–z 0–9 . _ + -
//   （不會撞到 , * $ ~），最長 PSU_VER_STR_MAX。
//
//   ── 節點韌體更新（2026-10-28；控制板轉傳，UART 與 ESP-NOW 同一套）──
//   控制板 → 節點   $FWB,<size>,<sha256>,<name>,<ver>            開始：映像大小、SHA-256（32 B hex）、
//                                                               映像名稱（ESP-IDF 的 project_name）與版本
//   控制板 → 節點   $FWD,<offset>,<data>                        一塊資料（1–PSU_FW_CHUNK B，hex）
//   控制板 → 節點   $FWE                                        傳完了：節點驗證、切換、回 FWA 後重開機
//   節點 → 控制板   $FWA,<offset>,<result>                      回應 FWB／FWD／FWE：<offset> = 節點下一個要的
//                                                               位置（psu_fw_result_t）
//   雙向            $FWX,<reason>                               中止（psu_fw_result_t）
//
//   一次一塊、等 FWA 才送下一塊。FWD 的 offset 不是節點要的，節點不寫、回 FWA 說它要哪裡（重送或斷線後
//   從那裡接著傳）。節點只在 CAP 宣告 PSU_CAP_FW_UPDATE 時才收；名稱不是自己的、太大、正在忙就回
//   REFUSED／BUSY。**電源節點更新時輸出不關**（控制板可能正吃它的電）。
//
//   NET：節點記下來，下次斷線或開機時先掃描一次 WiFi，看那個網路在哪個頻道就直接切過去，
//   不必一個頻道一個頻道試、等握手碰運氣。先比 BSSID（mesh 網路同名的基地台可能在不同頻道），
//   找不到再比 SSID。SSID 本來就是公開廣播的；這則訊息跟其他一般訊息一樣帶驗證尾碼。
//
//   CHN：ESP-NOW 只收得到同一個頻道的封包，但隔壁頻道會漏過來一部分 —— 節點停在 8、控制板在 9 時，
//   握手照樣成功、之後時通時斷，節點的「連續送不出去才重找」也一直被偶爾的成功歸零。
//   由控制板直接說它在哪個頻道，節點就不用猜。跟其他一般訊息一樣帶驗證尾碼，偽造不了。
//
//   PWR 的單位：<vac> 0.1 V、<pmax> W（DC 輸出）、<ilim> 0.1 A（AC 端電流上限）。0 = 不知道 / 不限。
//   <pmax> 由節點自己算：它最清楚自己的模組在這個 AC 電壓下能出多少，也知道 AC 端
//   （插座、AC 充電樁）能給多少電流。控制板只照 <pmax> 收電流，不必認得節點的型號。
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
// 含 '\n' 與結尾 NUL 的緩衝區大小上限。2026-10-28 從 96 加大：FWD 一行帶 PSU_FW_CHUNK B 韌體；
// 加上驗證尾碼剛好是 ESP-NOW 一個封包的 250 B
#define PSU_LINK_MAX_LINE    224u
#define PSU_FW_CHUNK         96u    // FWD 一塊的位元組數上限（hex 192 字）
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
#define PSU_CAP_REPORT_PWR   (1u << 5)   // 節點會送 PWR（AC 輸入電壓、可用功率）
#define PSU_CAP_FW_UPDATE    (1u << 6)   // 節點收 FWB／FWD／FWE：可以由控制板轉傳更新（2026-10-28）

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

// ─── AC 電流上限的來源（PWR.src）───────────────────────────────────────────
typedef enum {
    PSU_AC_SRC_UNKNOWN = 0,   // 不知道 AC 端能給多少（只看模組本身）
    PSU_AC_SRC_OUTLET  = 1,   // 插在一般插座：上限是使用者在節點上的設定
    PSU_AC_SRC_EVSE    = 2,   // 接在 AC 充電樁（J1772 / Type-2）：上限來自 pilot 訊號
} psu_ac_src_t;

// ─── 韌體更新結果碼（FWA.result、FWX.reason）─────────────────────────────────
typedef enum {
    PSU_FW_OK        = 0,
    PSU_FW_BUSY      = 1,   // 節點現在不能更新（例如另一個傳輸進行中）
    PSU_FW_REFUSED   = 2,   // 不收：不是自己的映像、太大、沒有這個能力
    PSU_FW_OFFSET    = 3,   // FWD 的位置不是要的那裡：照 FWA 的 offset 從那裡傳
    PSU_FW_FLASH     = 4,   // 寫入或切換失敗
    PSU_FW_HASH      = 5,   // SHA-256 不符或映像驗證失敗
    PSU_FW_ABORTED   = 6,   // 對方中止、逾時
    PSU_FW_NOT_BEGUN = 7,   // 沒收到 FWB 就收到 FWD／FWE
} psu_fw_result_t;

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
    PSU_MSG_POWER        = 15,   // PWR
    PSU_MSG_CHANNEL      = 16,   // CHN
    PSU_MSG_NETWORK      = 17,   // NET
    PSU_MSG_INFO         = 18,   // INF
    PSU_MSG_FW_BEGIN     = 19,   // FWB
    PSU_MSG_FW_DATA      = 20,   // FWD
    PSU_MSG_FW_END       = 21,   // FWE
    PSU_MSG_FW_ACK       = 22,   // FWA
    PSU_MSG_FW_ABORT     = 23,   // FWX
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

typedef struct {
    uint8_t  channel;       // 1–14
} psu_msg_channel_t;

#define PSU_SSID_MAX 32u
typedef struct {
    uint8_t  bssid[6];
    uint8_t  ssid_len;      // 1–PSU_SSID_MAX
    uint8_t  ssid[PSU_SSID_MAX];   // 不一定是可印字元，也不以 NUL 結尾
} psu_msg_network_t;

#define PSU_VER_STR_MAX  31u   // INF 的版本字串最長字元數（不含 NUL）
#define PSU_BOOT_STR_MAX 15u
#define PSU_UID_MAX       8u
typedef struct {
    uint16_t hw_rev;                         // 硬體版本，0–65535，各節點類型自己編號
    char     fw[PSU_VER_STR_MAX + 1];        // 完整韌體版本，NUL 結尾；空字串 = 不知道
    char     boot[PSU_BOOT_STR_MAX + 1];     // 開機程式版本，NUL 結尾；空字串 = 沒有獨立開機程式
    uint8_t  uid_len;                        // 1–PSU_UID_MAX
    uint8_t  uid[PSU_UID_MAX];
} psu_msg_info_t;

typedef struct {
    uint32_t size;                          // 映像位元組數
    uint8_t  sha256[32];
    char     name[PSU_VER_STR_MAX + 1];     // 映像名稱（ESP-IDF project_name），節點比對是不是自己的
    char     ver[PSU_VER_STR_MAX + 1];      // 版本，給節點記 log 與顯示
} psu_msg_fw_begin_t;

typedef struct {
    uint32_t offset;
    uint8_t  len;                           // 1–PSU_FW_CHUNK
    uint8_t  data[PSU_FW_CHUNK];
} psu_msg_fw_data_t;

typedef struct {
    uint32_t offset;                        // 節點下一個要的位置（全部收完 = size）
    uint8_t  result;                        // psu_fw_result_t
} psu_msg_fw_ack_t;

typedef struct {
    uint8_t  reason;                        // psu_fw_result_t
} psu_msg_fw_abort_t;

typedef struct {
    uint16_t vac_dv;        // AC 輸入電壓，0.1 V；0 = 還沒讀到
    uint16_t pmax_w;        // 節點現在能給的最大 DC 輸出功率，W；0 = 不知道（控制板照舊不限）
    uint16_t ilim_da;       // AC 端的電流上限，0.1 A；0 = 不知道
    uint8_t  src;           // psu_ac_src_t：ilim 從哪裡來
} psu_msg_power_t;

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
        psu_msg_power_t  power;
        psu_msg_channel_t channel;
        psu_msg_network_t network;
        psu_msg_info_t   info;
        psu_msg_fw_begin_t fw_begin;
        psu_msg_fw_data_t  fw_data;
        psu_msg_fw_ack_t   fw_ack;
        psu_msg_fw_abort_t fw_abort;
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
