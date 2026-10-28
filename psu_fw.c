// psu_fw.c — 見 psu_fw.h
#include "psu_link/psu_fw.h"
#include <string.h>

// ─── 節點（收）───────────────────────────────────────────────────────────────

static void ack(psu_msg_t *r, uint32_t offset, uint8_t result)
{
    memset(r, 0, sizeof *r);
    r->type = PSU_MSG_FW_ACK;
    r->u.fw_ack.offset = offset;
    r->u.fw_ack.result = result;
}

static void rx_stop(psu_fw_rx_t *rx)
{
    if (rx->active && rx->ops->abort) rx->ops->abort(rx->ops->ctx);
    rx->active = false;
}

void psu_fw_rx_init(psu_fw_rx_t *rx, const psu_fw_rx_ops_t *ops)
{
    memset(rx, 0, sizeof *rx);
    rx->ops = ops;
}

bool psu_fw_rx_handle(psu_fw_rx_t *rx, const psu_msg_t *m, uint32_t now_ms, psu_msg_t *reply)
{
    switch (m->type) {
    case PSU_MSG_FW_BEGIN: {
        const psu_msg_fw_begin_t *b = &m->u.fw_begin;
        // 同一個映像的 FWB 又來了（我們的 FWA 掉了，控制板重送）：從原位置接著傳，不重新準備
        if (rx->active && b->size == rx->size && memcmp(b->sha256, rx->sha256, 32) == 0) {
            rx->last_ms = now_ms;
            ack(reply, rx->next, PSU_FW_OK);
            return true;
        }
        rx_stop(rx);
        uint8_t r = (b->size == 0) ? PSU_FW_REFUSED : rx->ops->begin(rx->ops->ctx, b);
        if (r == PSU_FW_OK) {
            rx->active  = true;
            rx->size    = b->size;
            rx->next    = 0;
            rx->last_ms = now_ms;
            memcpy(rx->sha256, b->sha256, 32);
        }
        ack(reply, 0, r);
        return true;
    }
    case PSU_MSG_FW_DATA: {
        const psu_msg_fw_data_t *d = &m->u.fw_data;
        if (!rx->active) { ack(reply, 0, PSU_FW_NOT_BEGUN); return true; }
        rx->last_ms = now_ms;
        if (d->offset != rx->next) { ack(reply, rx->next, PSU_FW_OFFSET); return true; }   // 重複或跳號：不寫
        if ((uint64_t)d->offset + d->len > rx->size) {
            rx_stop(rx);
            ack(reply, rx->next, PSU_FW_REFUSED);
            return true;
        }
        if (rx->ops->write(rx->ops->ctx, d->offset, d->data, d->len) != PSU_FW_OK) {
            rx_stop(rx);
            ack(reply, rx->next, PSU_FW_FLASH);
            return true;
        }
        rx->next += d->len;
        ack(reply, rx->next, PSU_FW_OK);
        return true;
    }
    case PSU_MSG_FW_END: {
        if (!rx->active) { ack(reply, 0, PSU_FW_NOT_BEGUN); return true; }
        rx->last_ms = now_ms;
        if (rx->next != rx->size) { ack(reply, rx->next, PSU_FW_OFFSET); return true; }
        uint8_t r = rx->ops->finish(rx->ops->ctx);
        if (r != PSU_FW_OK && rx->ops->abort) rx->ops->abort(rx->ops->ctx);
        rx->active = false;
        ack(reply, rx->size, r);
        return true;
    }
    case PSU_MSG_FW_ABORT:
        rx_stop(rx);
        return false;
    default:
        return false;
    }
}

void psu_fw_rx_tick(psu_fw_rx_t *rx, uint32_t now_ms)
{
    if (rx->active && (uint32_t)(now_ms - rx->last_ms) >= PSU_FW_RX_IDLE_MS) rx_stop(rx);
}

// ─── 控制板（送）─────────────────────────────────────────────────────────────

static void tx_fail(psu_fw_tx_t *tx, uint8_t reason)
{
    tx->state  = PSU_FW_TX_FAILED;
    tx->result = reason ? reason : PSU_FW_ABORTED;
}

// 依目前狀態寫出要送的那一則
static void tx_emit(psu_fw_tx_t *tx, uint32_t now_ms, psu_msg_t *out)
{
    memset(out, 0, sizeof *out);
    if (tx->state == PSU_FW_TX_BEGIN) {
        out->type = PSU_MSG_FW_BEGIN;
        out->u.fw_begin = tx->begin;
    } else if (tx->state == PSU_FW_TX_DATA) {
        uint32_t left = tx->size - tx->next;
        tx->len = (uint8_t)(left < PSU_FW_CHUNK ? left : PSU_FW_CHUNK);
        out->type = PSU_MSG_FW_DATA;
        out->u.fw_data.offset = tx->next;
        out->u.fw_data.len    = tx->len;
        memcpy(out->u.fw_data.data, tx->img + tx->next, tx->len);
    } else {
        out->type = PSU_MSG_FW_END;
    }
    tx->sent_ms = now_ms;
}

// 到 next 之後：還有資料就送 FWD，送完就送 FWE
static void tx_go(psu_fw_tx_t *tx, uint32_t next, uint32_t now_ms, psu_msg_t *out)
{
    tx->next  = next;
    tx->state = (next >= tx->size) ? PSU_FW_TX_END : PSU_FW_TX_DATA;
    tx->tries = 1;
    tx_emit(tx, now_ms, out);
}

void psu_fw_tx_start(psu_fw_tx_t *tx, const uint8_t *img, uint32_t size, const uint8_t sha256[32],
                     const char *name, const char *ver, uint32_t now_ms, psu_msg_t *out)
{
    memset(tx, 0, sizeof *tx);
    tx->img  = img;
    tx->size = size;
    tx->begin.size = size;
    memcpy(tx->begin.sha256, sha256, 32);
    strncpy(tx->begin.name, name, PSU_VER_STR_MAX);
    strncpy(tx->begin.ver, ver, PSU_VER_STR_MAX);
    tx->state = PSU_FW_TX_BEGIN;
    tx->tries = 1;
    tx_emit(tx, now_ms, out);
}

bool psu_fw_tx_on_msg(psu_fw_tx_t *tx, const psu_msg_t *in, uint32_t now_ms, psu_msg_t *out)
{
    if (!psu_fw_tx_running(tx)) return false;
    if (in->type == PSU_MSG_FW_ABORT) { tx_fail(tx, in->u.fw_abort.reason); return false; }
    if (in->type != PSU_MSG_FW_ACK) return false;
    uint32_t off = in->u.fw_ack.offset;
    uint8_t  r   = in->u.fw_ack.result;

    switch (tx->state) {
    case PSU_FW_TX_BEGIN:
        if (r != PSU_FW_OK) { tx_fail(tx, r); return false; }
        if (off > tx->size) { tx_fail(tx, PSU_FW_REFUSED); return false; }
        tx_go(tx, off, now_ms, out);           // 0，或節點記得的位置（接著傳）
        return true;
    case PSU_FW_TX_DATA:
    case PSU_FW_TX_END:
        if (r == PSU_FW_OFFSET || r == PSU_FW_OK) {
            if (off > tx->size) { tx_fail(tx, PSU_FW_REFUSED); return false; }
            if (r == PSU_FW_OK && tx->state == PSU_FW_TX_END && off == tx->size) {
                tx->state = PSU_FW_TX_DONE;    // 節點驗證過、切換好了
                return false;
            }
            // 正常的 OK 是「送出中那塊的結尾」；比那更前面的 OK 是重送造成的舊回應，忽略
            if (r == PSU_FW_OK && !(tx->state == PSU_FW_TX_DATA && off == tx->next + tx->len)) return false;
            tx_go(tx, off, now_ms, out);       // 下一塊；或照節點說的位置重送
            return true;
        }
        // 送了不只一次 FWE、節點卻說沒開始：它多半已經驗證成功、重開機了（成功的 FWA 掉了）。
        // 算完成，但 result 記 NOT_BEGUN：呼叫端等節點重新連上，用 INF 的版本確認
        if (tx->state == PSU_FW_TX_END && r == PSU_FW_NOT_BEGUN && tx->tries > 1) {
            tx->state  = PSU_FW_TX_DONE;
            tx->result = PSU_FW_NOT_BEGUN;
            return false;
        }
        tx_fail(tx, r);                         // 節點寫入失敗、映像驗證失敗、沒開始…
        return false;
    default:
        return false;
    }
}

bool psu_fw_tx_tick(psu_fw_tx_t *tx, uint32_t now_ms, psu_msg_t *out)
{
    if (!psu_fw_tx_running(tx)) return false;
    uint32_t wait = (tx->state == PSU_FW_TX_BEGIN) ? PSU_FW_TX_BEGIN_MS : PSU_FW_TX_RETRY_MS;
    if ((uint32_t)(now_ms - tx->sent_ms) < wait) return false;
    if (tx->tries >= PSU_FW_TX_MAX_TRIES) {
        psu_fw_tx_abort(tx, PSU_FW_ABORTED, out);
        return true;
    }
    tx->tries++;
    tx_emit(tx, now_ms, out);
    return true;
}

void psu_fw_tx_abort(psu_fw_tx_t *tx, uint8_t reason, psu_msg_t *out)
{
    tx_fail(tx, reason);
    memset(out, 0, sizeof *out);
    out->type = PSU_MSG_FW_ABORT;
    out->u.fw_abort.reason = tx->result;
}

bool psu_fw_tx_running(const psu_fw_tx_t *tx)
{
    return tx->state == PSU_FW_TX_BEGIN || tx->state == PSU_FW_TX_DATA || tx->state == PSU_FW_TX_END;
}

int psu_fw_tx_percent(const psu_fw_tx_t *tx)
{
    if (tx->state == PSU_FW_TX_DONE) return 100;
    if (!tx->size || tx->state == PSU_FW_TX_BEGIN) return 0;
    if (tx->state == PSU_FW_TX_END) return 99;
    return (int)((uint64_t)tx->next * 99u / tx->size);
}
