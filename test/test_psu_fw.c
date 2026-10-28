// psu_fw（節點韌體更新的兩端狀態機）的主機端測試：兩端透過一條會掉封包的假連線對傳，
// 每則訊息都真的 encode → decode 一次
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "psu_link/psu_fw.h"

static int s_pass, s_fail;
#define CHECK(c) do { if (c) s_pass++; else { s_fail++; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

// ── 假節點：寫進 RAM，finish 時比對 ────────────────────────────────────────────
typedef struct {
    uint8_t  flash[300000];
    uint32_t size, written;
    int      begins, aborts, writes;
    bool     finished, fail_write_at_half, bad_hash;
    const uint8_t *expect;
} node_t;

static uint8_t n_begin(void *c, const psu_msg_fw_begin_t *b)
{
    node_t *n = c;
    n->begins++;
    if (strcmp(b->name, "LianMing-PSU-Controller") != 0) return PSU_FW_REFUSED;
    if (b->size > sizeof n->flash) return PSU_FW_REFUSED;
    n->size = b->size; n->written = 0;
    return PSU_FW_OK;
}
static uint8_t n_write(void *c, uint32_t off, const uint8_t *d, uint8_t len)
{
    node_t *n = c;
    n->writes++;
    if (off != n->written) return PSU_FW_FLASH;                 // 一定是依序
    if (n->fail_write_at_half && off >= n->size / 2) return PSU_FW_FLASH;
    memcpy(n->flash + off, d, len);
    n->written += len;
    return PSU_FW_OK;
}
static uint8_t n_finish(void *c)
{
    node_t *n = c;
    if (n->bad_hash || n->written != n->size || memcmp(n->flash, n->expect, n->size) != 0) return PSU_FW_HASH;
    n->finished = true;
    return PSU_FW_OK;
}
static void n_abort(void *c) { ((node_t *)c)->aborts++; }

// ── 假連線 ────────────────────────────────────────────────────────────────────
static uint32_t s_rng = 1;
static bool lose(int pct) { s_rng = s_rng * 1103515245u + 12345u; return (int)((s_rng >> 16) % 100) < pct; }

// 經過一次真的編碼／解碼（含 CRC）
static bool wire(const psu_msg_t *in, psu_msg_t *out)
{
    char line[PSU_LINK_MAX_LINE];
    size_t n = psu_link_encode(in, line, sizeof line);
    if (!n) return false;
    return psu_link_decode(line, n, out) == PSU_LINK_OK;
}

typedef struct { int msgs_tx, msgs_rx; uint32_t ms; } stats_t;

// 跑一次完整傳輸。loss_pct：每則訊息被丟掉的機率（兩個方向各自）
static psu_fw_tx_state_t run(node_t *node, psu_fw_rx_t *rx, const uint8_t *img, uint32_t size, const char *name,
                              int loss_pct, stats_t *st)
{
    static const psu_fw_rx_ops_t ops = { n_begin, n_write, n_finish, n_abort, NULL };
    psu_fw_rx_ops_t *o = malloc(sizeof *o);
    *o = ops; o->ctx = node;
    psu_fw_rx_init(rx, o);
    psu_fw_tx_t tx;
    uint8_t sha[32] = { 1, 2, 3 };
    psu_msg_t to_node, to_ctl, tmp;
    uint32_t now = 1000;
    memset(st, 0, sizeof *st);
    psu_fw_tx_start(&tx, img, size, sha, name, "v9.9.9", now, &to_node);
    bool have = true;
    for (int step = 0; step < 2000000 && psu_fw_tx_running(&tx); step++) {
        now += 5;
        if (have) {
            have = false;
            st->msgs_tx++;
            if (!lose(loss_pct) && wire(&to_node, &tmp)) {
                if (psu_fw_rx_handle(rx, &tmp, now, &to_ctl)) {
                    st->msgs_rx++;
                    if (!lose(loss_pct) && wire(&to_ctl, &tmp)) have = psu_fw_tx_on_msg(&tx, &tmp, now, &to_node);
                }
            }
            continue;
        }
        have = psu_fw_tx_tick(&tx, now, &to_node);
        if (have && to_node.type == PSU_MSG_FW_ABORT) {          // 放棄：FWX 也送過去
            if (wire(&to_node, &tmp)) psu_fw_rx_handle(rx, &tmp, now, &to_ctl);
            have = false;
        }
        psu_fw_rx_tick(rx, now);
    }
    st->ms = now - 1000;
    free(o);
    return tx.state;
}

static uint8_t s_img[250000];

int main(void)
{
    for (size_t i = 0; i < sizeof s_img; i++) s_img[i] = (uint8_t)(i * 31u + (i >> 8));
    static node_t node;
    psu_fw_rx_t rx;
    stats_t st;

    // 1. 乾淨的連線：一次傳完，節點驗證成功
    memset(&node, 0, sizeof node); node.expect = s_img;
    CHECK(run(&node, &rx, s_img, sizeof s_img, "LianMing-PSU-Controller", 0, &st) == PSU_FW_TX_DONE);
    CHECK(node.finished && node.begins == 1 && node.aborts == 0);
    CHECK(node.writes == (int)((sizeof s_img + PSU_FW_CHUNK - 1) / PSU_FW_CHUNK));   // 每塊剛好寫一次
    printf("  clean: %d messages\n", st.msgs_tx);

    // 2. 兩個方向各掉 15 %：重送、舊回應、跳號都要收斂，內容一樣
    memset(&node, 0, sizeof node); node.expect = s_img;
    CHECK(run(&node, &rx, s_img, sizeof s_img, "LianMing-PSU-Controller", 15, &st) == PSU_FW_TX_DONE);
    CHECK(node.finished && node.begins == 1 && node.aborts == 0);
    CHECK(node.writes == (int)((sizeof s_img + PSU_FW_CHUNK - 1) / PSU_FW_CHUNK));   // 掉包也不會重寫
    printf("  15%% loss: %d messages, %u s simulated\n", st.msgs_tx, (unsigned)(st.ms / 1000));

    // 3. 大小不是一塊的整數倍（最後一塊比較短）
    memset(&node, 0, sizeof node); node.expect = s_img;
    CHECK(run(&node, &rx, s_img, 1000, "LianMing-PSU-Controller", 5, &st) == PSU_FW_TX_DONE && node.finished);

    // 4. 不是這個節點的映像：FWB 就被拒絕，什麼都沒寫
    memset(&node, 0, sizeof node); node.expect = s_img;
    psu_fw_tx_state_t r = run(&node, &rx, s_img, sizeof s_img, "TES-charger", 0, &st);
    CHECK(r == PSU_FW_TX_FAILED && node.writes == 0);

    // 5. 寫到一半 flash 失敗：控制板失敗收場、節點丟掉寫到一半的
    memset(&node, 0, sizeof node); node.expect = s_img; node.fail_write_at_half = true;
    CHECK(run(&node, &rx, s_img, sizeof s_img, "LianMing-PSU-Controller", 0, &st) == PSU_FW_TX_FAILED);
    CHECK(!node.finished && node.aborts == 1 && !rx.active);

    // 6. 收完驗證失敗（SHA-256 不符）
    memset(&node, 0, sizeof node); node.expect = s_img; node.bad_hash = true;
    CHECK(run(&node, &rx, s_img, 5000, "LianMing-PSU-Controller", 0, &st) == PSU_FW_TX_FAILED);
    CHECK(!node.finished && node.aborts == 1);

    // 7. 節點完全沒回應：重送 PSU_FW_TX_MAX_TRIES 次後放棄
    {
        psu_fw_tx_t tx;
        psu_msg_t out;
        uint8_t sha[32] = { 0 };
        uint32_t now = 0;
        psu_fw_tx_start(&tx, s_img, 1000, sha, "x", "v1", now, &out);
        int sends = 1;
        while (psu_fw_tx_running(&tx) && now < 600000) { now += 100; if (psu_fw_tx_tick(&tx, now, &out)) sends++; }
        CHECK(tx.state == PSU_FW_TX_FAILED && tx.result == PSU_FW_ABORTED && out.type == PSU_MSG_FW_ABORT);
        CHECK(sends == (int)PSU_FW_TX_MAX_TRIES + 1);           // 10 次 FWB + 最後一則 FWX
    }

    // 8. 節點：重複的 FWB（同一個映像）從原位置接著，不重新開始
    {
        memset(&node, 0, sizeof node); node.expect = s_img;
        psu_fw_rx_ops_t ops = { n_begin, n_write, n_finish, n_abort, &node };
        psu_fw_rx_init(&rx, &ops);
        psu_msg_t m, reply;
        memset(&m, 0, sizeof m);
        m.type = PSU_MSG_FW_BEGIN; m.u.fw_begin.size = 500; strcpy(m.u.fw_begin.name, "LianMing-PSU-Controller");
        CHECK(psu_fw_rx_handle(&rx, &m, 0, &reply) && reply.u.fw_ack.result == PSU_FW_OK);
        psu_msg_t d; memset(&d, 0, sizeof d);
        d.type = PSU_MSG_FW_DATA; d.u.fw_data.offset = 0; d.u.fw_data.len = 96; memcpy(d.u.fw_data.data, s_img, 96);
        CHECK(psu_fw_rx_handle(&rx, &d, 1, &reply) && reply.u.fw_ack.offset == 96);
        CHECK(psu_fw_rx_handle(&rx, &m, 2, &reply) && reply.u.fw_ack.offset == 96 && node.begins == 1);
        // 跳號、重複：不寫，回要的位置
        d.u.fw_data.offset = 192;
        CHECK(psu_fw_rx_handle(&rx, &d, 3, &reply) && reply.u.fw_ack.result == PSU_FW_OFFSET && reply.u.fw_ack.offset == 96);
        d.u.fw_data.offset = 0;
        CHECK(psu_fw_rx_handle(&rx, &d, 4, &reply) && reply.u.fw_ack.result == PSU_FW_OFFSET && node.writes == 1);
        // 還沒收完就 FWE：回要的位置
        psu_msg_t e; memset(&e, 0, sizeof e); e.type = PSU_MSG_FW_END;
        CHECK(psu_fw_rx_handle(&rx, &e, 5, &reply) && reply.u.fw_ack.result == PSU_FW_OFFSET);
        // 太久沒收到東西：放棄
        psu_fw_rx_tick(&rx, 5 + PSU_FW_RX_IDLE_MS);
        CHECK(!rx.active && node.aborts == 1);
        // 沒開始就收到 FWD
        CHECK(psu_fw_rx_handle(&rx, &d, 6, &reply) && reply.u.fw_ack.result == PSU_FW_NOT_BEGUN);
        // 超出大小
        CHECK(psu_fw_rx_handle(&rx, &m, 7, &reply) && rx.active);
        d.u.fw_data.offset = 0; d.u.fw_data.len = 96;
        for (uint32_t off = 0; off < 480; off += 96) { d.u.fw_data.offset = off; psu_fw_rx_handle(&rx, &d, 8, &reply); }
        d.u.fw_data.offset = 480;
        CHECK(psu_fw_rx_handle(&rx, &d, 9, &reply) && reply.u.fw_ack.result == PSU_FW_REFUSED && !rx.active);
    }

    // 9. 成功的 FWA 掉了：重送 FWE 時節點已經不在傳輸中 → 完成但未確認
    {
        memset(&node, 0, sizeof node); node.expect = s_img;
        psu_fw_rx_ops_t ops = { n_begin, n_write, n_finish, n_abort, &node };
        psu_fw_rx_init(&rx, &ops);
        psu_fw_tx_t tx; psu_msg_t out, reply; uint8_t sha[32] = { 0 }; uint32_t now = 0;
        psu_fw_tx_start(&tx, s_img, 100, sha, "LianMing-PSU-Controller", "v1", now, &out);
        while (psu_fw_tx_running(&tx)) {
            now += 10;
            if (!psu_fw_rx_handle(&rx, &out, now, &reply)) break;
            if (out.type == PSU_MSG_FW_END && reply.u.fw_ack.result == PSU_FW_OK) {   // 這個回應掉了
                now += PSU_FW_TX_RETRY_MS;
                CHECK(psu_fw_tx_tick(&tx, now, &out) && out.type == PSU_MSG_FW_END);
                continue;
            }
            if (!psu_fw_tx_on_msg(&tx, &reply, now, &out)) break;
        }
        CHECK(node.finished && tx.state == PSU_FW_TX_DONE && tx.result == PSU_FW_NOT_BEGUN);
    }

    printf("psu_fw: %d passed, %d failed\n", s_pass, s_fail);
    return s_fail ? 1 : 0;
}
