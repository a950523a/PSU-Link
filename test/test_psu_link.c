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
    test_roundtrip();
    test_set_partial();
    test_not_frame();
    test_corruption();
    test_bad_fields();
    test_limits();
    printf("%d passed, %d failed\n", s_pass, s_fail);
    return s_fail ? 1 : 0;
}
