/*
 * Clean-room libfprint-2-tod-1 (Touch OEM Device) GObject driver wrapper
 * for the CanvasBio CB2000 (2df0:0007) Match-on-Chip sensor.
 *
 * All SDCP cryptography (ECDH P-256, KBKDF, X.509 Model Cert + s_m/s_d
 * verification, constant-time MACs) and USB protocol framing run in Rust
 * via libcb2000_tod.a; this file bridges GLib/libfprint/GUsb to that FFI.
 *
 * SPDX-License-Identifier: MIT
 */

#define FP_COMPONENT "cb2000"

#include <glib.h>
#include <glib-object.h>
#include <gio/gio.h>
#include <gmodule.h>
#include <gusb.h>
#include <string.h>

#include <fpi-log.h>
#include <fpi-device.h>
#include <fpi-print.h>

#include "cb2000_tod.h"

#define CB2000_USB_VID 0x2df0
#define CB2000_USB_PID 0x0007
#define CB2000_USB_IFACE 0
#define CB2000_USB_EP_OUT 0x01
#define CB2000_USB_EP_IN 0x82
#define CB2000_USB_TIMEOUT_MS 5000
#define CB2000_ID_LEN 32

struct _FpiDeviceCb2000 {
    FpDevice parent;

    Cb2000TodHandle *handle;
    Cb2000TodCaps caps;
    gboolean iface_claimed;
    GCancellable *usb_cancellable;
    GMutex worker_mutex;
    gint enroll_stages_done;
};

#define FPI_TYPE_DEVICE_CB2000 (fpi_device_cb2000_get_type())
G_DECLARE_FINAL_TYPE(FpiDeviceCb2000, fpi_device_cb2000, FPI, DEVICE_CB2000, FpDevice)
G_DEFINE_TYPE(FpiDeviceCb2000, fpi_device_cb2000, FP_TYPE_DEVICE)

G_MODULE_EXPORT GType
fpi_tod_shared_driver_get_type(void)
{
    return fpi_device_cb2000_get_type();
}

static const FpIdEntry cb2000_id_table[] = {
    { .vid = CB2000_USB_VID, .pid = CB2000_USB_PID },
    { .vid = 0, .pid = 0 },
};

/* --- GUsb transport callbacks invoked from Rust under op_lock --- */

static int32_t
cb2000_usb_control_in(
    void *ctx,
    uint8_t request,
    uint16_t value,
    uint16_t index,
    uint8_t *buf,
    size_t len)
{
    FpiDeviceCb2000 *self = FPI_DEVICE_CB2000(ctx);
    GUsbDevice *usb_dev = fpi_device_get_usb_device(FP_DEVICE(self));
    g_autoptr(GError) err = NULL;
    gsize actual = 0;

    if (!g_usb_device_control_transfer(
            usb_dev,
            G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
            G_USB_DEVICE_REQUEST_TYPE_VENDOR,
            G_USB_DEVICE_RECIPIENT_DEVICE,
            request,
            value,
            index,
            buf,
            len,
            &actual,
            CB2000_USB_TIMEOUT_MS,
            self->usb_cancellable,
            &err)) {
        if (err && !g_error_matches(err, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
            fp_warn("GUsb control_in(req=0x%02x val=0x%04x) failed: %s",
                    request, value, err->message);
        }
        return -1;
    }
    if (actual > (gsize)G_MAXINT32) {
        return -1;
    }
    return (int32_t)actual;
}

static void
cb2000_zeroize(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len-- > 0) {
        *p++ = 0;
    }
}

static int32_t
cb2000_usb_bulk_out(void *ctx, const uint8_t *buf, size_t len)
{
    FpiDeviceCb2000 *self = FPI_DEVICE_CB2000(ctx);
    GUsbDevice *usb_dev = fpi_device_get_usb_device(FP_DEVICE(self));
    g_autoptr(GError) err = NULL;
    g_autofree uint8_t *tmp = NULL;
    uint8_t stack_buf[256];
    uint8_t *tx_buf = stack_buf;
    gsize actual = 0;
    int32_t rc = 0;

    if (len > 0) {
        if (len > sizeof(stack_buf)) {
            tmp = g_malloc(len);
            tx_buf = tmp;
        }
        memcpy(tx_buf, buf, len);
    }

    if (!g_usb_device_bulk_transfer(
            usb_dev,
            CB2000_USB_EP_OUT,
            tx_buf,
            len,
            &actual,
            CB2000_USB_TIMEOUT_MS,
            self->usb_cancellable,
            &err)) {
        if (err && !g_error_matches(err, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
            fp_warn("GUsb bulk_out(%zu) failed: %s", len, err->message);
        }
        rc = -1;
    } else if (actual != len) {
        fp_warn("GUsb bulk_out short write: expected %zu, wrote %" G_GSIZE_FORMAT,
                len, actual);
        rc = -1;
    }

    if (len > 0) {
        cb2000_zeroize(tx_buf, len);
    }
    return rc;
}

static int32_t
cb2000_usb_bulk_in(void *ctx, uint8_t *buf, size_t len)
{
    FpiDeviceCb2000 *self = FPI_DEVICE_CB2000(ctx);
    GUsbDevice *usb_dev = fpi_device_get_usb_device(FP_DEVICE(self));
    g_autoptr(GError) err = NULL;
    gsize actual = 0;

    if (!g_usb_device_bulk_transfer(
            usb_dev,
            CB2000_USB_EP_IN,
            buf,
            len,
            &actual,
            CB2000_USB_TIMEOUT_MS,
            self->usb_cancellable,
            &err)) {
        if (err && !g_error_matches(err, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
            fp_warn("GUsb bulk_in(%zu) failed: %s", len, err->message);
        }
        return -1;
    }
    if (actual > (gsize)G_MAXINT32) {
        return -1;
    }
    return (int32_t)actual;
}

static const Cb2000UsbVtable cb2000_usb_vtable = {
    .control_in = cb2000_usb_control_in,
    .bulk_out = cb2000_usb_bulk_out,
    .bulk_in = cb2000_usb_bulk_in,
};

/* --- Finger / Print helpers --- */

static uint8_t
fp_finger_to_sub_factor(FpFinger finger)
{
    switch (finger) {
    case FP_FINGER_LEFT_THUMB:
        return 1;
    case FP_FINGER_LEFT_INDEX:
        return 2;
    case FP_FINGER_LEFT_MIDDLE:
        return 3;
    case FP_FINGER_LEFT_RING:
        return 4;
    case FP_FINGER_LEFT_LITTLE:
        return 5;
    case FP_FINGER_RIGHT_THUMB:
        return 6;
    case FP_FINGER_RIGHT_INDEX:
        return 7;
    case FP_FINGER_RIGHT_MIDDLE:
        return 8;
    case FP_FINGER_RIGHT_RING:
        return 9;
    case FP_FINGER_RIGHT_LITTLE:
        return 10;
    default:
        return 1;
    }
}

static FpFinger
sub_factor_to_fp_finger(uint8_t sub_factor)
{
    switch (sub_factor) {
    case 1:
        return FP_FINGER_LEFT_THUMB;
    case 2:
        return FP_FINGER_LEFT_INDEX;
    case 3:
        return FP_FINGER_LEFT_MIDDLE;
    case 4:
        return FP_FINGER_LEFT_RING;
    case 5:
        return FP_FINGER_LEFT_LITTLE;
    case 6:
        return FP_FINGER_RIGHT_THUMB;
    case 7:
        return FP_FINGER_RIGHT_INDEX;
    case 8:
        return FP_FINGER_RIGHT_MIDDLE;
    case 9:
        return FP_FINGER_RIGHT_RING;
    case 10:
        return FP_FINGER_RIGHT_LITTLE;
    default:
        return FP_FINGER_UNKNOWN;
    }
}

static void
cb2000_print_set_data(FpPrint *print, uint8_t sub_factor, const uint8_t id[CB2000_ID_LEN])
{
    g_autoptr(GVariant) data = NULL;

    fpi_print_set_type(print, FPI_PRINT_RAW);
    fpi_print_set_device_stored(print, TRUE);
    fp_print_set_finger(print, sub_factor_to_fp_finger(sub_factor));

    data = g_variant_ref_sink(g_variant_new(
        "(y@ay)",
        (guchar)sub_factor,
        g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, id, CB2000_ID_LEN, 1)));
    g_object_set(print, "fpi-data", data, NULL);
}

static FpPrint *
cb2000_make_floating_print(FpDevice *device, uint8_t sub_factor, const uint8_t id[CB2000_ID_LEN])
{
    FpPrint *print = fp_print_new(device);
    cb2000_print_set_data(print, sub_factor, id);
    return print;
}

static gboolean
cb2000_print_get_id(FpPrint *print, uint8_t out_id[CB2000_ID_LEN])
{
    g_autoptr(GVariant) data = NULL;
    g_autoptr(GVariant) bytes_var = NULL;
    uint8_t sub_factor = 0;
    const uint8_t *raw = NULL;
    gsize n_elems = 0;

    if (!FP_IS_PRINT(print)) {
        return FALSE;
    }

    g_object_get(print, "fpi-data", &data, NULL);
    if (!data || !g_variant_is_of_type(data, G_VARIANT_TYPE("(yay)"))) {
        return FALSE;
    }

    g_variant_get(data, "(y@ay)", &sub_factor, &bytes_var);
    (void)sub_factor;
    if (!bytes_var) {
        return FALSE;
    }

    raw = g_variant_get_fixed_array(bytes_var, &n_elems, sizeof(uint8_t));
    if (!raw || n_elems != CB2000_ID_LEN) {
        return FALSE;
    }

    memcpy(out_id, raw, CB2000_ID_LEN);
    return TRUE;
}

static GError *
cb2000_error_to_gerror(FpiDeviceCb2000 *self, int32_t rc)
{
    char detail[256] = { 0 };
    const char *msg = NULL;

    if (fpi_device_action_is_cancelled(FP_DEVICE(self)) || rc == CB2000_TOD_ERR_CANCELLED) {
        return g_error_new_literal(G_IO_ERROR, G_IO_ERROR_CANCELLED, "Operation cancelled");
    }

    if (self->handle) {
        size_t n = cb2000_tod_last_error(self->handle, detail, sizeof(detail));
        if (n > 0) {
            msg = detail;
        }
    }

    switch (rc) {
    case CB2000_TOD_ERR_SLOTS_FULL:
        return fpi_device_error_new_msg(
            FP_DEVICE_ERROR_DATA_FULL,
            "%s",
            msg ? msg : "Sensor template storage is full");
    case CB2000_TOD_ERR_DUPLICATE:
        return fpi_device_error_new_msg(
            FP_DEVICE_ERROR_DATA_DUPLICATE,
            "%s",
            msg ? msg : "Fingerprint already enrolled on sensor");
    case CB2000_TOD_ERR_NOT_FOUND:
        return fpi_device_error_new_msg(
            FP_DEVICE_ERROR_DATA_NOT_FOUND,
            "%s",
            msg ? msg : "Template not found on sensor");
    case CB2000_TOD_ERR_TIMEOUT:
        return fpi_device_error_new_msg(
            FP_DEVICE_ERROR_GENERAL,
            "%s",
            msg ? msg : "Timed out waiting for finger");
    case CB2000_TOD_ERR_SDCP:
        return fpi_device_error_new_msg(
            FP_DEVICE_ERROR_PROTO,
            "%s",
            msg ? msg : "SDCP attestation or MAC verification failed");
    case CB2000_TOD_ERR_PROTOCOL:
    case CB2000_TOD_ERR_TRANSPORT:
        return fpi_device_error_new_msg(
            FP_DEVICE_ERROR_PROTO,
            "%s",
            msg ? msg : "USB or protocol error communicating with CB2000");
    default:
        return fpi_device_error_new_msg(
            FP_DEVICE_ERROR_GENERAL,
            "%s (code %d)",
            msg ? msg : "CB2000 driver error",
            rc);
    }
}

/* --- Main-loop progress & completion marshaling --- */

typedef struct {
    FpDevice *device;
    uint32_t event_kind;
    uint32_t value;
} Cb2000ProgressEvent;

static gboolean
cb2000_on_progress_idle(gpointer user_data)
{
    Cb2000ProgressEvent *ev = user_data;
    FpiDeviceCb2000 *self = FPI_DEVICE_CB2000(ev->device);
    FpiDeviceAction action = fpi_device_get_current_action(ev->device);

    if (action == FPI_DEVICE_ACTION_NONE || fpi_device_action_is_cancelled(ev->device)) {
        g_object_unref(ev->device);
        g_free(ev);
        return G_SOURCE_REMOVE;
    }

    switch (ev->event_kind) {
    case CB2000_TOD_EVENT_FINGER_NEEDED:
        fpi_device_report_finger_status(ev->device, FP_FINGER_STATUS_NEEDED);
        break;
    case CB2000_TOD_EVENT_FINGER_PRESENT:
        fpi_device_report_finger_status(ev->device, FP_FINGER_STATUS_PRESENT);
        break;
    case CB2000_TOD_EVENT_FINGER_REMOVED:
        fpi_device_report_finger_status(ev->device, FP_FINGER_STATUS_NONE);
        break;
    case CB2000_TOD_EVENT_STAGE_PASSED:
        if (action == FPI_DEVICE_ACTION_ENROLL) {
            self->enroll_stages_done = (gint)ev->value;
            fpi_device_enroll_progress(ev->device, (gint)ev->value, NULL, NULL);
        }
        break;
    case CB2000_TOD_EVENT_RETRY_SCAN:
        if (action == FPI_DEVICE_ACTION_ENROLL) {
            fpi_device_enroll_progress(
                ev->device,
                self->enroll_stages_done,
                NULL,
                fpi_device_retry_new(FP_DEVICE_RETRY_GENERAL));
        }
        break;
    default:
        break;
    }

    g_object_unref(ev->device);
    g_free(ev);
    return G_SOURCE_REMOVE;
}

static void
cb2000_worker_progress_cb(uint32_t event_kind, uint32_t value, void *ctx)
{
    Cb2000ProgressEvent *ev = g_new0(Cb2000ProgressEvent, 1);
    ev->device = g_object_ref(FP_DEVICE(ctx));
    ev->event_kind = event_kind;
    ev->value = value;
    g_idle_add(cb2000_on_progress_idle, ev);
}

typedef struct {
    FpDevice *device;
    GThread *thread;
    FpiDeviceAction action;
    int32_t rc;
    uint8_t sub_factor;
    uint8_t id[CB2000_ID_LEN];
    uint8_t bad_capture_code;
    Cb2000TodHandle *opened_handle;
    Cb2000TodHandle *handle_to_close;
    Cb2000TodCaps opened_caps;
    Cb2000TodSlot *listed_slots;
    size_t listed_count;
} Cb2000TaskCtx;

static void
cb2000_task_ctx_free(Cb2000TaskCtx *ctx)
{
    if (!ctx) {
        return;
    }
    g_clear_pointer(&ctx->handle_to_close, cb2000_tod_close);
    g_clear_pointer(&ctx->listed_slots, g_free);
    g_clear_object(&ctx->device);
    g_free(ctx);
}

static gboolean
cb2000_on_task_complete_idle(gpointer user_data)
{
    Cb2000TaskCtx *ctx = user_data;
    FpDevice *device = ctx->device;
    FpiDeviceCb2000 *self = FPI_DEVICE_CB2000(device);

    if (ctx->thread) {
        g_thread_join(g_steal_pointer(&ctx->thread));
    }
    g_clear_object(&self->usb_cancellable);

    switch (ctx->action) {
    case FPI_DEVICE_ACTION_OPEN:
        if (ctx->rc == CB2000_TOD_OK && ctx->opened_handle) {
            self->handle = ctx->opened_handle;
            self->caps = ctx->opened_caps;
            fpi_device_set_nr_enroll_stages(device, (gint)self->caps.enroll_stages);
            fpi_device_set_scan_type(device, FP_SCAN_TYPE_PRESS);
            fp_dbg("CB2000 opened via TOD: proto=V%u partition=%u enroll_stages=%u max_slots=%u",
                   self->caps.protocol_version,
                   self->caps.partition_id,
                   self->caps.enroll_stages,
                   self->caps.max_slots);
            fpi_device_open_complete(device, NULL);
        } else {
            GError *err = cb2000_error_to_gerror(self, ctx->rc);
            if (self->iface_claimed) {
                GUsbDevice *usb_dev = fpi_device_get_usb_device(device);
                g_usb_device_release_interface(
                    usb_dev, CB2000_USB_IFACE, G_USB_DEVICE_CLAIM_INTERFACE_NONE, NULL);
                self->iface_claimed = FALSE;
            }
            fpi_device_open_complete(device, err);
        }
        break;

    case FPI_DEVICE_ACTION_CLOSE: {
        GError *rel_err = NULL;
        self->handle = NULL;
        if (self->iface_claimed) {
            GUsbDevice *usb_dev = fpi_device_get_usb_device(device);
            g_usb_device_release_interface(
                usb_dev, CB2000_USB_IFACE, G_USB_DEVICE_CLAIM_INTERFACE_NONE, &rel_err);
            self->iface_claimed = FALSE;
        }
        fpi_device_close_complete(device, rel_err);
        break;
    }

    case FPI_DEVICE_ACTION_ENROLL:
        if (ctx->rc == CB2000_TOD_OK) {
            FpPrint *tmpl = NULL;
            FpPrint *out_print = NULL;
            fpi_device_get_enroll_data(device, &tmpl);
            out_print = tmpl ? g_object_ref(tmpl) : g_object_ref_sink(fp_print_new(device));
            cb2000_print_set_data(out_print, ctx->sub_factor, ctx->id);
            fpi_device_enroll_complete(device, out_print, NULL);
        } else {
            fpi_device_enroll_complete(device, NULL, cb2000_error_to_gerror(self, ctx->rc));
        }
        break;

    case FPI_DEVICE_ACTION_VERIFY:
        if (fpi_device_action_is_cancelled(device) || ctx->rc == CB2000_TOD_ERR_CANCELLED) {
            fpi_device_verify_complete(
                device, g_error_new_literal(G_IO_ERROR, G_IO_ERROR_CANCELLED, "Cancelled"));
        } else if (ctx->rc == CB2000_TOD_OK) {
            FpPrint *expected = NULL;
            uint8_t expected_id[CB2000_ID_LEN] = { 0 };
            fpi_device_get_verify_data(device, &expected);
            if (expected && cb2000_print_get_id(expected, expected_id) &&
                cb2000_tod_ct_eq_id(ctx->id, expected_id)) {
                FpPrint *scanned = cb2000_make_floating_print(device, ctx->sub_factor, ctx->id);
                fpi_device_verify_report(device, FPI_MATCH_SUCCESS, scanned, NULL);
            } else {
                fpi_device_verify_report(device, FPI_MATCH_FAIL, NULL, NULL);
            }
            fpi_device_verify_complete(device, NULL);
        } else if (ctx->rc == CB2000_TOD_ERR_NO_MATCH) {
            fpi_device_verify_report(device, FPI_MATCH_FAIL, NULL, NULL);
            fpi_device_verify_complete(device, NULL);
        } else if (ctx->rc == CB2000_TOD_ERR_BAD_CAPTURE) {
            fpi_device_verify_report(
                device,
                FPI_MATCH_ERROR,
                NULL,
                fpi_device_retry_new_msg(
                    FP_DEVICE_RETRY_GENERAL,
                    "Bad capture quality (0x%02x); please retry",
                    ctx->bad_capture_code));
            fpi_device_verify_complete(device, NULL);
        } else {
            fpi_device_verify_complete(device, cb2000_error_to_gerror(self, ctx->rc));
        }
        break;

    case FPI_DEVICE_ACTION_IDENTIFY:
        if (fpi_device_action_is_cancelled(device) || ctx->rc == CB2000_TOD_ERR_CANCELLED) {
            fpi_device_identify_complete(
                device, g_error_new_literal(G_IO_ERROR, G_IO_ERROR_CANCELLED, "Cancelled"));
        } else if (ctx->rc == CB2000_TOD_OK) {
            GPtrArray *gallery = NULL;
            FpPrint *matched = NULL;
            fpi_device_get_identify_data(device, &gallery);
            for (guint i = 0; gallery && i < gallery->len; i++) {
                FpPrint *cand = g_ptr_array_index(gallery, i);
                uint8_t cand_id[CB2000_ID_LEN] = { 0 };
                if (cb2000_print_get_id(cand, cand_id) &&
                    cb2000_tod_ct_eq_id(ctx->id, cand_id)) {
                    matched = cand;
                    break;
                }
            }
            if (matched) {
                FpPrint *scanned = cb2000_make_floating_print(device, ctx->sub_factor, ctx->id);
                fpi_device_identify_report(device, matched, scanned, NULL);
            } else {
                fpi_device_identify_report(device, NULL, NULL, NULL);
            }
            fpi_device_identify_complete(device, NULL);
        } else if (ctx->rc == CB2000_TOD_ERR_NO_MATCH) {
            fpi_device_identify_report(device, NULL, NULL, NULL);
            fpi_device_identify_complete(device, NULL);
        } else if (ctx->rc == CB2000_TOD_ERR_BAD_CAPTURE) {
            fpi_device_identify_report(
                device,
                NULL,
                NULL,
                fpi_device_retry_new_msg(
                    FP_DEVICE_RETRY_GENERAL,
                    "Bad capture quality (0x%02x); please retry",
                    ctx->bad_capture_code));
            fpi_device_identify_complete(device, NULL);
        } else {
            fpi_device_identify_complete(device, cb2000_error_to_gerror(self, ctx->rc));
        }
        break;

    case FPI_DEVICE_ACTION_LIST:
        if (ctx->rc == CB2000_TOD_OK) {
            g_autoptr(GPtrArray) prints = g_ptr_array_new_with_free_func(g_object_unref);
            for (size_t i = 0; i < ctx->listed_count; i++) {
                FpPrint *p = cb2000_make_floating_print(
                    device,
                    ctx->listed_slots[i].sub_factor,
                    ctx->listed_slots[i].enrollment_id);
                g_ptr_array_add(prints, g_object_ref_sink(p));
            }
            fpi_device_list_complete(device, g_steal_pointer(&prints), NULL);
        } else {
            fpi_device_list_complete(device, NULL, cb2000_error_to_gerror(self, ctx->rc));
        }
        break;

    case FPI_DEVICE_ACTION_DELETE:
        if (ctx->rc == CB2000_TOD_OK) {
            fpi_device_delete_complete(device, NULL);
        } else {
            fpi_device_delete_complete(device, cb2000_error_to_gerror(self, ctx->rc));
        }
        break;

    case FPI_DEVICE_ACTION_CLEAR_STORAGE:
        if (ctx->rc == CB2000_TOD_OK) {
            fpi_device_clear_storage_complete(device, NULL);
        } else {
            fpi_device_clear_storage_complete(device, cb2000_error_to_gerror(self, ctx->rc));
        }
        break;

    default:
        fp_warn("Unhandled completed action %d", (int)ctx->action);
        break;
    }

    cb2000_task_ctx_free(ctx);
    return G_SOURCE_REMOVE;
}

static gpointer
cb2000_worker_entry(gpointer user_data)
{
    Cb2000TaskCtx *ctx = user_data;
    FpiDeviceCb2000 *self = FPI_DEVICE_CB2000(ctx->device);

    switch (ctx->action) {
    case FPI_DEVICE_ACTION_OPEN:
        ctx->rc = cb2000_tod_open(
            &cb2000_usb_vtable,
            self,
            &ctx->opened_handle,
            &ctx->opened_caps);
        break;

    case FPI_DEVICE_ACTION_CLOSE:
        if (ctx->handle_to_close) {
            cb2000_tod_close(g_steal_pointer(&ctx->handle_to_close));
        }
        ctx->rc = CB2000_TOD_OK;
        break;

    case FPI_DEVICE_ACTION_ENROLL:
        ctx->rc = cb2000_tod_enroll(
            self->handle,
            ctx->sub_factor,
            cb2000_worker_progress_cb,
            ctx->device,
            ctx->id);
        break;

    case FPI_DEVICE_ACTION_VERIFY:
    case FPI_DEVICE_ACTION_IDENTIFY:
        ctx->rc = cb2000_tod_identify(
            self->handle,
            cb2000_worker_progress_cb,
            ctx->device,
            &ctx->sub_factor,
            ctx->id,
            &ctx->bad_capture_code);
        break;

    case FPI_DEVICE_ACTION_LIST: {
        size_t cap = self->caps.max_slots > 0 ? (size_t)self->caps.max_slots : 10;
        ctx->listed_slots = g_new0(Cb2000TodSlot, cap);
        ctx->rc = cb2000_tod_list_slots(
            self->handle,
            ctx->listed_slots,
            cap,
            &ctx->listed_count);
        break;
    }

    case FPI_DEVICE_ACTION_DELETE:
        ctx->rc = cb2000_tod_delete_by_id(self->handle, ctx->id);
        break;

    case FPI_DEVICE_ACTION_CLEAR_STORAGE: {
        size_t deleted = 0;
        ctx->rc = cb2000_tod_clear_storage(self->handle, &deleted);
        break;
    }

    default:
        ctx->rc = CB2000_TOD_ERR_INTERNAL;
        break;
    }

    /* Synchronize with worker_mutex so ctx->thread is stored before joining. */
    g_mutex_lock(&self->worker_mutex);
    g_mutex_unlock(&self->worker_mutex);

    g_idle_add(cb2000_on_task_complete_idle, ctx);
    return NULL;
}

static void
cb2000_spawn_worker(FpiDeviceCb2000 *self, Cb2000TaskCtx *ctx)
{
    g_clear_object(&self->usb_cancellable);
    self->usb_cancellable = g_cancellable_new();

    g_mutex_lock(&self->worker_mutex);
    ctx->thread = g_thread_new("cb2000-tod", cb2000_worker_entry, ctx);
    g_mutex_unlock(&self->worker_mutex);
}

/* --- FpDevice virtual methods --- */

static void
fpi_device_cb2000_open(FpDevice *device)
{
    FpiDeviceCb2000 *self = FPI_DEVICE_CB2000(device);
    GUsbDevice *usb_dev = fpi_device_get_usb_device(device);
    GError *err = NULL;
    Cb2000TaskCtx *ctx = NULL;

    if (!g_usb_device_claim_interface(
            usb_dev,
            CB2000_USB_IFACE,
            G_USB_DEVICE_CLAIM_INTERFACE_NONE,
            &err)) {
        fpi_device_open_complete(device, err);
        return;
    }
    self->iface_claimed = TRUE;

    ctx = g_new0(Cb2000TaskCtx, 1);
    ctx->device = g_object_ref(device);
    ctx->action = FPI_DEVICE_ACTION_OPEN;
    cb2000_spawn_worker(self, ctx);
}

static void
fpi_device_cb2000_close(FpDevice *device)
{
    FpiDeviceCb2000 *self = FPI_DEVICE_CB2000(device);
    Cb2000TaskCtx *ctx = g_new0(Cb2000TaskCtx, 1);

    ctx->device = g_object_ref(device);
    ctx->action = FPI_DEVICE_ACTION_CLOSE;
    /* Transfer ownership on the main thread before spawning close worker so cancel()
     * can never observe a dangling handle pointer. */
    ctx->handle_to_close = g_steal_pointer(&self->handle);
    cb2000_spawn_worker(self, ctx);
}

static void
fpi_device_cb2000_enroll(FpDevice *device)
{
    FpiDeviceCb2000 *self = FPI_DEVICE_CB2000(device);
    FpPrint *tmpl = NULL;
    FpFinger finger = FP_FINGER_UNKNOWN;
    Cb2000TaskCtx *ctx = g_new0(Cb2000TaskCtx, 1);

    fpi_device_get_enroll_data(device, &tmpl);
    if (tmpl) {
        finger = fp_print_get_finger(tmpl);
    }

    self->enroll_stages_done = 0;
    ctx->device = g_object_ref(device);
    ctx->action = FPI_DEVICE_ACTION_ENROLL;
    ctx->sub_factor = fp_finger_to_sub_factor(finger);
    cb2000_spawn_worker(self, ctx);
}

static void
fpi_device_cb2000_verify(FpDevice *device)
{
    FpiDeviceCb2000 *self = FPI_DEVICE_CB2000(device);
    FpPrint *expected = NULL;
    uint8_t expected_id[CB2000_ID_LEN] = { 0 };
    Cb2000TaskCtx *ctx = NULL;

    fpi_device_get_verify_data(device, &expected);
    if (!expected || !cb2000_print_get_id(expected, expected_id)) {
        fpi_device_verify_complete(
            device,
            fpi_device_error_new_msg(
                FP_DEVICE_ERROR_DATA_INVALID,
                "Stored FpPrint is missing CB2000 SDCP enrollment data"));
        return;
    }

    ctx = g_new0(Cb2000TaskCtx, 1);
    ctx->device = g_object_ref(device);
    ctx->action = FPI_DEVICE_ACTION_VERIFY;
    cb2000_spawn_worker(self, ctx);
}

static void
fpi_device_cb2000_identify(FpDevice *device)
{
    FpiDeviceCb2000 *self = FPI_DEVICE_CB2000(device);
    Cb2000TaskCtx *ctx = g_new0(Cb2000TaskCtx, 1);

    ctx->device = g_object_ref(device);
    ctx->action = FPI_DEVICE_ACTION_IDENTIFY;
    cb2000_spawn_worker(self, ctx);
}

static void
fpi_device_cb2000_list(FpDevice *device)
{
    FpiDeviceCb2000 *self = FPI_DEVICE_CB2000(device);
    Cb2000TaskCtx *ctx = g_new0(Cb2000TaskCtx, 1);

    ctx->device = g_object_ref(device);
    ctx->action = FPI_DEVICE_ACTION_LIST;
    cb2000_spawn_worker(self, ctx);
}

static void
fpi_device_cb2000_delete(FpDevice *device)
{
    FpiDeviceCb2000 *self = FPI_DEVICE_CB2000(device);
    FpPrint *target = NULL;
    uint8_t id[CB2000_ID_LEN] = { 0 };
    Cb2000TaskCtx *ctx = NULL;

    fpi_device_get_delete_data(device, &target);
    if (!target || !cb2000_print_get_id(target, id)) {
        fpi_device_delete_complete(
            device,
            fpi_device_error_new_msg(
                FP_DEVICE_ERROR_DATA_INVALID,
                "Target FpPrint is missing CB2000 SDCP enrollment ID"));
        return;
    }

    ctx = g_new0(Cb2000TaskCtx, 1);
    ctx->device = g_object_ref(device);
    ctx->action = FPI_DEVICE_ACTION_DELETE;
    memcpy(ctx->id, id, CB2000_ID_LEN);
    cb2000_spawn_worker(self, ctx);
}

static void
fpi_device_cb2000_clear_storage(FpDevice *device)
{
    FpiDeviceCb2000 *self = FPI_DEVICE_CB2000(device);
    Cb2000TaskCtx *ctx = g_new0(Cb2000TaskCtx, 1);

    ctx->device = g_object_ref(device);
    ctx->action = FPI_DEVICE_ACTION_CLEAR_STORAGE;
    cb2000_spawn_worker(self, ctx);
}

static void
fpi_device_cb2000_cancel(FpDevice *device)
{
    FpiDeviceCb2000 *self = FPI_DEVICE_CB2000(device);

    if (self->handle) {
        cb2000_tod_cancel(self->handle);
    }
    if (self->usb_cancellable) {
        g_cancellable_cancel(self->usb_cancellable);
    }
}

static void
fpi_device_cb2000_init(FpiDeviceCb2000 *self)
{
    g_mutex_init(&self->worker_mutex);
}

static void
fpi_device_cb2000_finalize(GObject *object)
{
    FpiDeviceCb2000 *self = FPI_DEVICE_CB2000(object);

    g_clear_pointer(&self->handle, cb2000_tod_close);
    g_clear_object(&self->usb_cancellable);
    g_mutex_clear(&self->worker_mutex);

    G_OBJECT_CLASS(fpi_device_cb2000_parent_class)->finalize(object);
}

static void
fpi_device_cb2000_class_init(FpiDeviceCb2000Class *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);
    FpDeviceClass *dev_class = FP_DEVICE_CLASS(klass);

    dev_class->id = FP_COMPONENT;
    dev_class->full_name = "CanvasBio CB2000 Match-on-Chip (SDCP)";
    dev_class->type = FP_DEVICE_TYPE_USB;
    dev_class->id_table = cb2000_id_table;
    dev_class->scan_type = FP_SCAN_TYPE_PRESS;
    dev_class->nr_enroll_stages = 15;
    dev_class->temp_hot_seconds = -1;

    dev_class->open = fpi_device_cb2000_open;
    dev_class->close = fpi_device_cb2000_close;
    dev_class->enroll = fpi_device_cb2000_enroll;
    dev_class->verify = fpi_device_cb2000_verify;
    dev_class->identify = fpi_device_cb2000_identify;
    dev_class->list = fpi_device_cb2000_list;
    dev_class->delete = fpi_device_cb2000_delete;
    dev_class->clear_storage = fpi_device_cb2000_clear_storage;
    dev_class->cancel = fpi_device_cb2000_cancel;

    fpi_device_class_auto_initialize_features(dev_class);
    dev_class->features |= FP_DEVICE_FEATURE_DUPLICATES_CHECK;

    object_class->finalize = fpi_device_cb2000_finalize;
}
