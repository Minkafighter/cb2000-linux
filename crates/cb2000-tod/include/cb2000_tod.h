#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes returned by cb2000_tod_* functions. */
enum {
    CB2000_TOD_OK = 0,
    CB2000_TOD_ERR_INVALID_ARG = -1,
    CB2000_TOD_ERR_TRANSPORT = -2,
    CB2000_TOD_ERR_SDCP = -3,
    CB2000_TOD_ERR_PROTOCOL = -4,
    CB2000_TOD_ERR_CANCELLED = -5,
    CB2000_TOD_ERR_TIMEOUT = -6,
    CB2000_TOD_ERR_SLOTS_FULL = -7,
    CB2000_TOD_ERR_DUPLICATE = -8,
    CB2000_TOD_ERR_NOT_FOUND = -9,
    CB2000_TOD_ERR_NO_MATCH = -10,
    CB2000_TOD_ERR_BAD_CAPTURE = -11,
    CB2000_TOD_ERR_INTERNAL = -12,
};

/* Progress/status event kinds emitted via Cb2000ProgressCb. */
enum {
    CB2000_TOD_EVENT_FINGER_NEEDED = 1,
    CB2000_TOD_EVENT_FINGER_PRESENT = 2,
    CB2000_TOD_EVENT_FINGER_REMOVED = 3,
    CB2000_TOD_EVENT_STAGE_PASSED = 4,
    CB2000_TOD_EVENT_RETRY_SCAN = 5,
};

typedef struct Cb2000TodHandle Cb2000TodHandle;

/* Synchronous USB transport callbacks backed by libfprint's GUsbDevice. */
typedef struct Cb2000UsbVtable {
    int32_t (*control_in)(
        void *ctx,
        uint8_t request,
        uint16_t value,
        uint16_t index,
        uint8_t *buf,
        size_t len);
    int32_t (*bulk_out)(
        void *ctx,
        const uint8_t *buf,
        size_t len);
    int32_t (*bulk_in)(
        void *ctx,
        uint8_t *buf,
        size_t len);
} Cb2000UsbVtable;

/* Device capabilities discovered during probe + SDCP handshake. */
typedef struct Cb2000TodCaps {
    uint8_t protocol_version;
    uint8_t partition_id;
    uint8_t supports_finger_up_poll;
    uint8_t _reserved;
    uint32_t enroll_stages;
    uint32_t max_slots;
} Cb2000TodCaps;

/* One enrolled slot record owned by this Linux host partition. */
typedef struct Cb2000TodSlot {
    uint8_t slot_index;
    uint8_t sub_factor;
    uint8_t enrollment_id[32];
} Cb2000TodSlot;

typedef void (*Cb2000ProgressCb)(uint32_t event_kind, uint32_t value, void *ctx);

/* Open the sensor, verify SDCP attestation, and establish an authenticated session. */
int32_t cb2000_tod_open(
    const Cb2000UsbVtable *vtable,
    void *usb_ctx,
    Cb2000TodHandle **out_handle,
    Cb2000TodCaps *out_caps);

/* Close and free the handle cleanly. Safe to pass NULL. */
void cb2000_tod_close(Cb2000TodHandle *handle);

/* Thread-safe, lock-free cancellation signal for an in-flight enroll/identify. */
void cb2000_tod_cancel(const Cb2000TodHandle *handle);

/* Enroll a finger for `sub_factor`, outputting the 32-byte SDCP `enrollment_id`. */
int32_t cb2000_tod_enroll(
    const Cb2000TodHandle *handle,
    uint8_t sub_factor,
    Cb2000ProgressCb progress_cb,
    void *progress_ctx,
    uint8_t out_enrollment_id[32]);

/* Capture and match a finger with constant-time SDCP AuthorizedIdentity MAC verification. */
int32_t cb2000_tod_identify(
    const Cb2000TodHandle *handle,
    Cb2000ProgressCb progress_cb,
    void *progress_ctx,
    uint8_t *out_sub_factor,
    uint8_t out_enrollment_id[32],
    uint8_t *out_bad_capture_code);

/* Enumerate occupied template slots belonging to this Linux partition. */
int32_t cb2000_tod_list_slots(
    const Cb2000TodHandle *handle,
    Cb2000TodSlot *out_slots,
    size_t max_slots,
    size_t *out_count);

/* Delete the Linux-owned slot(s) matching `enrollment_id`. */
int32_t cb2000_tod_delete_by_id(
    const Cb2000TodHandle *handle,
    const uint8_t enrollment_id[32]);

/* Delete all template slots owned by this Linux partition (preserving other OS partitions). */
int32_t cb2000_tod_clear_storage(
    const Cb2000TodHandle *handle,
    size_t *out_deleted);

/* Constant-time 32-byte enrollment ID comparison. */
bool cb2000_tod_ct_eq_id(const uint8_t a[32], const uint8_t b[32]);

/* Copy the last human-readable error message as a NUL-terminated UTF-8 string. */
size_t cb2000_tod_last_error(const Cb2000TodHandle *handle, char *buf, size_t buf_len);

#ifdef __cplusplus
}
#endif
