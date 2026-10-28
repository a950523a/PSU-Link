// test_psu_link.c — psu_link 編解碼的主機端測試
//
// 在電腦上跑，不需要 ESP-IDF：
//   gcc -std=c99 -Wall -Wextra -Werror -Iinclude psu_link.c test/test_psu_link.c -o test_psu_link
//   ./test_psu_link
//
// ESP-IDF 只編 CMakeLists 列出的 SRCS，這個目錄不會進韌體。

#include "psu_link/psu_link.h"
#include <stdio.h>
#include <string.h>

static int s_fail = 0;
static int s_pass = 0;

#define CHECK(cond) do { \
    if (cond) { s_pass++; } \
    else { s_fail++; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); } \
} while (0)

// 用正確的 CRC 包出任意內容的訊框，用來測「CRC 對但欄位錯」的情況
static void frame(const char *body, char *out, size_t cap)
{
    uint16_t crc = psu_link_crc16((const uint8_t *)body, strlen(body));
    snprintf(out, cap, "$%s*%04X\n", body, (unsigned)crc);
}

static psu_link_result_t dec(const char *s, psu_msg_t *m)
{
    return psu_link_decode(s, strlen(s), m);
}

static void test_crc(void)
{
    CHECK(psu_link_crc16((const uint8_t *)"123456789", 9) == 0x29B1);
    CHECK(psu_link_crc16((const uint8_t *)"", 0) == 0xFFFF);
}

static void test_golden(void)
{
    // 固定一組實際位元組，當作協定文件的範例；改了編碼方式這裡會先壞
    char buf[PSU_LINK_MAX_LINE];
    psu_msg_t m = { .type = PSU_MSG_STATUS };
    m.u.status = (psu_msg_status_t){ .seq = 7, .v_cv = 4820, .i_ca = 1050,
                                     .mode = PSU_MODE_CC,
                                     .flags = PSU_ST_V_VALID | PSU_ST_I_VALID | PSU_ST_OUTPUT_ON };
    size_t n = psu_link_encode(&m, buf, sizeof buf);
    char expect[64];
    frame("ST,7,4820,1050,3,07", expect, sizeof expect);
    CHECK(n == strlen(expect));
    CHECK(strcmp(buf, expect) == 0);
    printf("  golden ST: %s", buf);
}

static void test_info(void)
{
    char buf[PSU_LINK_MAX_LINE], expect[PSU_LINK_MAX_LINE];
    psu_msg_t in = { .type = PSU_MSG_INFO }, out;
    const uint8_t mac[6] = { 0x24, 0x6F, 0x28, 0xAB, 0xCD, 0xEF };
    in.u.info.hw_rev = 1;
    strcpy(in.u.info.fw, "v1.4.0-8-g9b60735");
    in.u.info.boot[0] = '\0';                        // 沒有獨立開機程式
    memcpy(in.u.info.uid, mac, 6);
    in.u.info.uid_len = 6;
    size_t n = psu_link_encode(&in, buf, sizeof buf);
    frame("INF,1,v1.4.0-8-g9b60735,,246F28ABCDEF", expect, sizeof expect);
    CHECK(n == strlen(expect) && strcmp(buf, expect) == 0);
    CHECK(dec(buf, &out) == PSU_LINK_OK && out.type == PSU_MSG_INFO && out.u.info.hw_rev == 1 &&
          strcmp(out.u.info.fw, "v1.4.0-8-g9b60735") == 0 && out.u.info.boot[0] == '\0' &&
          out.u.info.uid_len == 6 && memcmp(out.u.info.uid, mac, 6) == 0);
    // 最長的版本字串＋開機程式＋8 B 識別碼，加上驗證尾碼也放得下
    in.u.info.hw_rev = 65535;
    memset(in.u.info.fw, 'a', PSU_VER_STR_MAX);   in.u.info.fw[PSU_VER_STR_MAX] = '\0';
    memset(in.u.info.boot, 'b', PSU_BOOT_STR_MAX); in.u.info.boot[PSU_BOOT_STR_MAX] = '\0';
    in.u.info.uid_len = PSU_UID_MAX;
    n = psu_link_encode(&in, buf, sizeof buf);
    CHECK(n > 0 && n + 26u < PSU_LINK_MAX_AUTH_LINE);
    CHECK(dec(buf, &out) == PSU_LINK_OK && strlen(out.u.info.fw) == PSU_VER_STR_MAX &&
          strlen(out.u.info.boot) == PSU_BOOT_STR_MAX && out.u.info.uid_len == PSU_UID_MAX);
    // 版本字串太長、有不允許的字元（會撞到分隔符號）、識別碼長度不對 → 不編碼
    strcpy(in.u.info.boot, "");
    memset(in.u.info.fw, 'a', PSU_VER_STR_MAX + 1); in.u.info.fw[PSU_VER_STR_MAX + 1] = '\0';
    CHECK(psu_link_encode(&in, buf, sizeof buf) == 0);
    strcpy(in.u.info.fw, "v1.0,x");
    CHECK(psu_link_encode(&in, buf, sizeof buf) == 0);
    strcpy(in.u.info.fw, "v1.0 beta");
    CHECK(psu_link_encode(&in, buf, sizeof buf) == 0);
    strcpy(in.u.info.fw, "v1.0");
    in.u.info.uid_len = 0;
    CHECK(psu_link_encode(&in, buf, sizeof buf) == 0);
    in.u.info.uid_len = PSU_UID_MAX + 1;
    CHECK(psu_link_encode(&in, buf, sizeof buf) == 0);
    // 解碼端一樣擋
    frame("INF,1,v1.0,,", expect, sizeof expect);                 // 沒有識別碼
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
    frame("INF,1,v1.0,,ABC", expect, sizeof expect);              // 奇數個十六進位字
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
    frame("INF,65536,v1.0,,AB", expect, sizeof expect);           // 硬體版本超過 16 位元
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
    frame("INF,1,v1.0 x,,AB", expect, sizeof expect);             // 空白不允許
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
    frame("INF,1,v1.0,,AB,9", expect, sizeof expect);             // 多一個欄位
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
    frame("INF,0,,,AB", expect, sizeof expect);                   // 全部都不知道也合法
    CHECK(dec(expect, &out) == PSU_LINK_OK && out.u.info.fw[0] == '\0' && out.u.info.uid_len == 1);
}

static void test_fw(void)
{
    char buf[PSU_LINK_MAX_LINE], expect[PSU_LINK_MAX_LINE];
    psu_msg_t in, out;
    size_t n;

    // FWB：最長的名稱與版本，加上驗證尾碼也放得進一個 ESP-NOW 封包
    memset(&in, 0, sizeof in);
    in.type = PSU_MSG_FW_BEGIN;
    in.u.fw_begin.size = 789024;
    for (int i = 0; i < 32; i++) in.u.fw_begin.sha256[i] = (uint8_t)(0xA0 + i);
    strcpy(in.u.fw_begin.name, "LianMing-PSU-Controller");
    strcpy(in.u.fw_begin.ver, "v1.4.0-9-g0aea095");
    n = psu_link_encode(&in, buf, sizeof buf);
    CHECK(n > 0 && n + 26u < PSU_LINK_MAX_AUTH_LINE);
    CHECK(dec(buf, &out) == PSU_LINK_OK && out.type == PSU_MSG_FW_BEGIN && out.u.fw_begin.size == 789024 &&
          memcmp(out.u.fw_begin.sha256, in.u.fw_begin.sha256, 32) == 0 &&
          strcmp(out.u.fw_begin.name, "LianMing-PSU-Controller") == 0 &&
          strcmp(out.u.fw_begin.ver, "v1.4.0-9-g0aea095") == 0);
    memset(in.u.fw_begin.name, 'n', PSU_VER_STR_MAX); in.u.fw_begin.name[PSU_VER_STR_MAX] = '\0';
    memset(in.u.fw_begin.ver, 'v', PSU_VER_STR_MAX);  in.u.fw_begin.ver[PSU_VER_STR_MAX] = '\0';
    in.u.fw_begin.size = 0x7FFFFFFFu;
    n = psu_link_encode(&in, buf, sizeof buf);
    CHECK(n > 0 && n + 26u < PSU_LINK_MAX_AUTH_LINE);
    in.u.fw_begin.name[0] = '\0';                                  // 沒有名稱：不送
    CHECK(psu_link_encode(&in, buf, sizeof buf) == 0);

    // FWD：一塊滿 PSU_FW_CHUNK，最大的 offset，加上驗證尾碼剛好放得進 ESP-NOW 封包（250 B）
    memset(&in, 0, sizeof in);
    in.type = PSU_MSG_FW_DATA;
    in.u.fw_data.offset = 0x7FFFFFFFu;
    in.u.fw_data.len = PSU_FW_CHUNK;
    for (int i = 0; i < (int)PSU_FW_CHUNK; i++) in.u.fw_data.data[i] = (uint8_t)(i * 7);
    n = psu_link_encode(&in, buf, sizeof buf);
    CHECK(n > 0 && n + 26u < PSU_LINK_MAX_AUTH_LINE && n + 26u + 1u <= 250u);
    printf("  longest FWD: %u bytes (+26 auth)\n", (unsigned)n);
    CHECK(dec(buf, &out) == PSU_LINK_OK && out.type == PSU_MSG_FW_DATA && out.u.fw_data.offset == 0x7FFFFFFFu &&
          out.u.fw_data.len == PSU_FW_CHUNK && memcmp(out.u.fw_data.data, in.u.fw_data.data, PSU_FW_CHUNK) == 0);
    in.u.fw_data.offset = 96; in.u.fw_data.len = 2; in.u.fw_data.data[0] = 0xE9; in.u.fw_data.data[1] = 0x05;
    psu_link_encode(&in, buf, sizeof buf);
    frame("FWD,96,E905", expect, sizeof expect);
    CHECK(strcmp(buf, expect) == 0);
    in.u.fw_data.len = 0;
    CHECK(psu_link_encode(&in, buf, sizeof buf) == 0);
    in.u.fw_data.len = PSU_FW_CHUNK + 1;
    CHECK(psu_link_encode(&in, buf, sizeof buf) == 0);

    // FWE、FWA、FWX
    memset(&in, 0, sizeof in);
    in.type = PSU_MSG_FW_END;
    psu_link_encode(&in, buf, sizeof buf);
    frame("FWE", expect, sizeof expect);
    CHECK(strcmp(buf, expect) == 0 && dec(buf, &out) == PSU_LINK_OK && out.type == PSU_MSG_FW_END);
    in.type = PSU_MSG_FW_ACK; in.u.fw_ack.offset = 192; in.u.fw_ack.result = PSU_FW_OFFSET;
    psu_link_encode(&in, buf, sizeof buf);
    frame("FWA,192,3", expect, sizeof expect);
    CHECK(strcmp(buf, expect) == 0 && dec(buf, &out) == PSU_LINK_OK && out.type == PSU_MSG_FW_ACK &&
          out.u.fw_ack.offset == 192 && out.u.fw_ack.result == PSU_FW_OFFSET);
    in.type = PSU_MSG_FW_ABORT; in.u.fw_abort.reason = PSU_FW_HASH;
    psu_link_encode(&in, buf, sizeof buf);
    frame("FWX,5", expect, sizeof expect);
    CHECK(strcmp(buf, expect) == 0 && dec(buf, &out) == PSU_LINK_OK && out.u.fw_abort.reason == PSU_FW_HASH);

    // 解碼端擋掉格式不對的
    frame("FWD,0,", expect, sizeof expect);                                    // 沒有資料
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
    frame("FWD,0,ABC", expect, sizeof expect);                                 // 奇數個 hex
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
    frame("FWE,1", expect, sizeof expect);
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
    frame("FWA,10", expect, sizeof expect);
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
    frame("FWB,10,00,x,v1", expect, sizeof expect);                            // SHA-256 太短
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
}

static void test_roundtrip(void)
{
    char buf[PSU_LINK_MAX_LINE];
    psu_msg_t in, out;

    in.type = PSU_MSG_HELLO; in.u.hello.proto_ver = PSU_LINK_PROTO_VER;
    CHECK(psu_link_encode(&in, buf, sizeof buf) > 0);
    CHECK(dec(buf, &out) == PSU_LINK_OK);
    CHECK(out.type == PSU_MSG_HELLO && out.u.hello.proto_ver == 2);

    in.type = PSU_MSG_CAP;
    in.u.cap = (psu_msg_cap_t){ 2, PSU_NODE_RECTIFIER,
        PSU_CAP_REPORT_V | PSU_CAP_REPORT_I | PSU_CAP_SET_V | PSU_CAP_SET_I | PSU_CAP_REPORT_MODE,
        12000, 10000, 131 };
    CHECK(psu_link_encode(&in, buf, sizeof buf) > 0);
    CHECK(dec(buf, &out) == PSU_LINK_OK);
    CHECK(out.type == PSU_MSG_CAP);
    CHECK(memcmp(&out.u.cap, &in.u.cap, sizeof in.u.cap) == 0);

    in.type = PSU_MSG_STATUS;
    in.u.status = (psu_msg_status_t){ 65535, 65535, -32768, PSU_MODE_CV, 0xFF };
    CHECK(psu_link_encode(&in, buf, sizeof buf) > 0);
    CHECK(dec(buf, &out) == PSU_LINK_OK);
    CHECK(out.u.status.seq == 65535 && out.u.status.v_cv == 65535);
    CHECK(out.u.status.i_ca == -32768 && out.u.status.flags == 0xFF);

    in.u.status.i_ca = 32767;
    CHECK(psu_link_encode(&in, buf, sizeof buf) > 0);
    CHECK(dec(buf, &out) == PSU_LINK_OK && out.u.status.i_ca == 32767);

    in.u.status.i_ca = -125;   // 量測模組的零點附近可能是負值
    CHECK(psu_link_encode(&in, buf, sizeof buf) > 0);
    CHECK(strstr(buf, ",-125,") != NULL);
    CHECK(dec(buf, &out) == PSU_LINK_OK && out.u.status.i_ca == -125);

    in.type = PSU_MSG_SET;
    in.u.set = (psu_msg_set_t){ 42, true, 5480, true, 1000 };
    CHECK(psu_link_encode(&in, buf, sizeof buf) > 0);
    CHECK(dec(buf, &out) == PSU_LINK_OK);
    CHECK(out.type == PSU_MSG_SET && out.u.set.seq == 42);
    CHECK(out.u.set.has_v && out.u.set.v_cv == 5480);
    CHECK(out.u.set.has_i && out.u.set.i_ca == 1000);

    in.type = PSU_MSG_ACK;
    in.u.ack = (psu_msg_ack_t){ 42, PSU_ACK_RANGE };
    CHECK(psu_link_encode(&in, buf, sizeof buf) > 0);
    CHECK(dec(buf, &out) == PSU_LINK_OK);
    CHECK(out.type == PSU_MSG_ACK && out.u.ack.seq == 42 && out.u.ack.result == PSU_ACK_RANGE);
}

static void test_power(void)
{
    char buf[PSU_LINK_MAX_LINE], expect[64];
    psu_msg_t in = { .type = PSU_MSG_POWER }, out;
    in.u.power = (psu_msg_power_t){ .vac_dv = 2205, .pmax_w = 3069, .ilim_da = 150, .src = PSU_AC_SRC_OUTLET };
    size_t n = psu_link_encode(&in, buf, sizeof buf);
    frame("PWR,2205,3069,150,1", expect, sizeof expect);
    CHECK(n == strlen(expect) && strcmp(buf, expect) == 0);
    printf("  golden PWR: %s", buf);
    CHECK(dec(buf, &out) == PSU_LINK_OK);
    CHECK(out.type == PSU_MSG_POWER);
    CHECK(out.u.power.vac_dv == 2205 && out.u.power.pmax_w == 3069);
    CHECK(out.u.power.ilim_da == 150 && out.u.power.src == PSU_AC_SRC_OUTLET);

    frame("PWR,0,0,0,0", expect, sizeof expect);        // 還沒讀到 AC：全 0 也合法
    CHECK(dec(expect, &out) == PSU_LINK_OK && out.u.power.pmax_w == 0);
    frame("PWR,2205,3069,150,3", expect, sizeof expect); // 不認得的來源
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
    frame("PWR,2205,3069,150", expect, sizeof expect);   // 少一欄
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
    frame("PWR,2205,70000,150,1", expect, sizeof expect);
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
}

static void test_channel(void)
{
    char buf[PSU_LINK_MAX_LINE], expect[32];
    psu_msg_t in = { .type = PSU_MSG_CHANNEL }, out;
    in.u.channel.channel = 9;
    size_t n = psu_link_encode(&in, buf, sizeof buf);
    frame("CHN,9", expect, sizeof expect);
    CHECK(n == strlen(expect) && strcmp(buf, expect) == 0);
    CHECK(dec(buf, &out) == PSU_LINK_OK && out.type == PSU_MSG_CHANNEL && out.u.channel.channel == 9);
    in.u.channel.channel = 0;
    CHECK(psu_link_encode(&in, buf, sizeof buf) == 0);
    in.u.channel.channel = 15;
    CHECK(psu_link_encode(&in, buf, sizeof buf) == 0);
    frame("CHN,0", expect, sizeof expect);
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
    frame("CHN,15", expect, sizeof expect);
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
    frame("CHN,9,1", expect, sizeof expect);
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
}

static void test_network(void)
{
    char buf[PSU_LINK_MAX_LINE], expect[PSU_LINK_MAX_LINE];
    psu_msg_t in = { .type = PSU_MSG_NETWORK }, out;
    const uint8_t bssid[6] = { 0xA0, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F };
    memcpy(in.u.network.bssid, bssid, 6);
    memcpy(in.u.network.ssid, "Home,5G", 7);          // 逗號也沒關係：十六進位
    in.u.network.ssid_len = 7;
    size_t n = psu_link_encode(&in, buf, sizeof buf);
    frame("NET,A01B2C3D4E5F,486F6D652C3547", expect, sizeof expect);
    CHECK(n == strlen(expect) && strcmp(buf, expect) == 0);
    CHECK(dec(buf, &out) == PSU_LINK_OK && out.type == PSU_MSG_NETWORK &&
          out.u.network.ssid_len == 7 && memcmp(out.u.network.ssid, "Home,5G", 7) == 0 &&
          memcmp(out.u.network.bssid, bssid, 6) == 0);
    // 最長的 SSID（32 B）加上驗證尾碼也放得下
    memset(in.u.network.ssid, 0xE5, PSU_SSID_MAX);
    in.u.network.ssid_len = PSU_SSID_MAX;
    n = psu_link_encode(&in, buf, sizeof buf);
    CHECK(n > 0 && n + 26u < PSU_LINK_MAX_AUTH_LINE);
    CHECK(dec(buf, &out) == PSU_LINK_OK && out.u.network.ssid_len == PSU_SSID_MAX);
    in.u.network.ssid_len = 0;
    CHECK(psu_link_encode(&in, buf, sizeof buf) == 0);
    in.u.network.ssid_len = PSU_SSID_MAX + 1;
    CHECK(psu_link_encode(&in, buf, sizeof buf) == 0);
    frame("NET,A01B2C3D4E5F,", expect, sizeof expect);            // 空 SSID
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
    frame("NET,A01B2C3D4E,486F6D65", expect, sizeof expect);       // BSSID 太短
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
    frame("NET,A01B2C3D4E5F,486F6D6", expect, sizeof expect);      // 奇數個 hex
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
    frame("NET,A01B2C3D4E5F", expect, sizeof expect);              // 少一欄
    CHECK(dec(expect, &out) == PSU_LINK_BAD_FIELDS);
}

static void test_set_partial(void)
{
    char buf[PSU_LINK_MAX_LINE];
    psu_msg_t in = { .type = PSU_MSG_SET }, out;

    in.u.set = (psu_msg_set_t){ 3, false, 0, true, 500 };   // 只設電流
    CHECK(psu_link_encode(&in, buf, sizeof buf) > 0);
    CHECK(strncmp(buf, "$SET,3,,500*", 12) == 0);
    CHECK(dec(buf, &out) == PSU_LINK_OK);
    CHECK(!out.u.set.has_v && out.u.set.has_i && out.u.set.i_ca == 500);

    in.u.set = (psu_msg_set_t){ 4, true, 4800, false, 0 };  // 只設電壓
    CHECK(psu_link_encode(&in, buf, sizeof buf) > 0);
    CHECK(strncmp(buf, "$SET,4,4800,*", 13) == 0);
    CHECK(dec(buf, &out) == PSU_LINK_OK);
    CHECK(out.u.set.has_v && !out.u.set.has_i && out.u.set.v_cv == 4800);

    in.u.set = (psu_msg_set_t){ 5, false, 0, false, 0 };    // 空的 SET 不送
    CHECK(psu_link_encode(&in, buf, sizeof buf) == 0);
    frame("SET,5,,", buf, sizeof buf);
    CHECK(dec(buf, &out) == PSU_LINK_BAD_FIELDS);
}

static void test_not_frame(void)
{
    psu_msg_t m;
    // 人下的文字指令、舊協定、配對訊息 —— 都不是本協定，要讓呼叫端自己處理
    CHECK(dec("PAIR\n", &m) == PSU_LINK_NOT_FRAME);
    CHECK(dec("ON", &m) == PSU_LINK_NOT_FRAME);
    CHECK(dec("V=48.0,I=10.0\n", &m) == PSU_LINK_NOT_FRAME);
    CHECK(dec("PSU_HELLO\n", &m) == PSU_LINK_NOT_FRAME);
    CHECK(dec("", &m) == PSU_LINK_NOT_FRAME);
    CHECK(dec("\r\n", &m) == PSU_LINK_NOT_FRAME);
}

static void test_corruption(void)
{
    char buf[PSU_LINK_MAX_LINE];
    psu_msg_t in = { .type = PSU_MSG_STATUS }, out;
    in.u.status = (psu_msg_status_t){ 1, 4820, 1050, PSU_MODE_CV, 0x07 };
    size_t n = psu_link_encode(&in, buf, sizeof buf);
    CHECK(n > 0);

    // 改掉一個數字 —— 「48.20 V 變 58.20 V」這種錯誤正是加 CRC 的理由
    char bad[PSU_LINK_MAX_LINE];
    memcpy(bad, buf, n + 1);
    char *p = strstr(bad, "4820"); CHECK(p != NULL); if (p) *p = '5';
    CHECK(dec(bad, &out) == PSU_LINK_BAD_CRC);

    // CRC 本身壞掉
    memcpy(bad, buf, n + 1);
    bad[n - 2] = (bad[n - 2] == '0') ? '1' : '0';
    CHECK(dec(bad, &out) == PSU_LINK_BAD_CRC);

    // 缺 CRC、CRC 不是十六進位、截斷
    CHECK(dec("$ST,1,4820,1050,2,07\n", &out) == PSU_LINK_BAD_CRC);
    CHECK(dec("$ST,1,4820,1050,2,07*ZZZZ\n", &out) == PSU_LINK_BAD_CRC);
    CHECK(dec("$ST,1,48", &out) == PSU_LINK_BAD_CRC);

    // 小寫十六進位的 CRC 也要接受
    memcpy(bad, buf, n + 1);
    for (char *q = strchr(bad, '*'); q && *q; q++) if (*q >= 'A' && *q <= 'F') *q = (char)(*q + 32);
    CHECK(dec(bad, &out) == PSU_LINK_OK);

    // 行尾是 \r\n、或完全沒有換行，都要能解
    memcpy(bad, buf, n + 1);
    bad[n - 1] = '\r'; bad[n] = '\n'; bad[n + 1] = '\0';
    CHECK(dec(bad, &out) == PSU_LINK_OK);
    CHECK(psu_link_decode(buf, n - 1, &out) == PSU_LINK_OK);
}

static void test_bad_fields(void)
{
    char buf[PSU_LINK_MAX_LINE];
    psu_msg_t m;

    frame("XYZ,1,2", buf, sizeof buf);             CHECK(dec(buf, &m) == PSU_LINK_BAD_TYPE);
    frame("ST,1,4820,1050,2", buf, sizeof buf);    CHECK(dec(buf, &m) == PSU_LINK_BAD_FIELDS);  // 少一欄
    frame("ST,1,4820,1050,2,07,9", buf, sizeof buf); CHECK(dec(buf, &m) == PSU_LINK_BAD_FIELDS); // 多一欄
    frame("ST,1,70000,1050,2,07", buf, sizeof buf); CHECK(dec(buf, &m) == PSU_LINK_BAD_FIELDS); // 電壓溢位
    frame("ST,1,4820,40000,2,07", buf, sizeof buf); CHECK(dec(buf, &m) == PSU_LINK_BAD_FIELDS); // 電流溢位
    frame("ST,1,48.2,1050,2,07", buf, sizeof buf); CHECK(dec(buf, &m) == PSU_LINK_BAD_FIELDS);  // 不接受小數
    frame("ST,1,,1050,2,07", buf, sizeof buf);     CHECK(dec(buf, &m) == PSU_LINK_BAD_FIELDS);  // 空欄位
    frame("ST,1,4820,1050,2,107", buf, sizeof buf); CHECK(dec(buf, &m) == PSU_LINK_BAD_FIELDS); // flags 只有 2 位
    frame("CAP,2,1,1F,12000,10000", buf, sizeof buf); CHECK(dec(buf, &m) == PSU_LINK_BAD_FIELDS);
    frame("ACK,1,256", buf, sizeof buf);           CHECK(dec(buf, &m) == PSU_LINK_BAD_FIELDS);
    frame("HELO,x", buf, sizeof buf);              CHECK(dec(buf, &m) == PSU_LINK_BAD_FIELDS);
    frame("", buf, sizeof buf);                    CHECK(dec(buf, &m) == PSU_LINK_BAD_TYPE);
}

static void test_limits(void)
{
    char buf[PSU_LINK_MAX_LINE];
    psu_msg_t in = { .type = PSU_MSG_CAP }, m;
    in.u.cap = (psu_msg_cap_t){ 255, 255, 0xFFFF, 65535, 65535, 65535 };
    size_t n = psu_link_encode(&in, buf, sizeof buf);
    CHECK(n > 0 && n < PSU_LINK_MAX_LINE);          // 最長的訊息也放得進緩衝區
    printf("  longest CAP: %u bytes\n", (unsigned)n);

    char small[10];
    CHECK(psu_link_encode(&in, small, sizeof small) == 0);   // 緩衝區不夠 → 0，不寫爆

    in.type = (psu_msg_type_t)99;
    CHECK(psu_link_encode(&in, buf, sizeof buf) == 0);

    char longline[PSU_LINK_MAX_LINE + 20];
    memset(longline, '1', sizeof longline);
    longline[0] = '$';
    longline[sizeof longline - 1] = '\0';
    CHECK(dec(longline, &m) == PSU_LINK_TOO_LONG);
}

int main(void)
{
    test_crc();
    test_golden();
    test_power();
    test_channel();
    test_network();
    test_info();
    test_fw();
    test_roundtrip();
    test_set_partial();
    test_not_frame();
    test_corruption();
    test_bad_fields();
    test_limits();
    printf("%d passed, %d failed\n", s_pass, s_fail);
    return s_fail ? 1 : 0;
}
