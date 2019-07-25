
#include <stdbool.h>

#include "upd_http_retrieval_thread.h"
#include "fw_upgrade.h"
#include "tl_upgrade.h"
#include "message_bin.h"
#include "gateway.h"
#include "gateway_macro.h"
#include "platform_os.h"
#include "event_group_bit_flags.h"

#include "semphr.h"
#include <virgil/iot/logger/logger.h>

static xTaskHandle upd_retrieval_thread;

static const uint16_t upd_retrieval_stack = 10 * 1024;

static bool retrieval_started;

/*************************************************************************/
static void
sw_retrieval_mb_notify(gtwy_t *gtwy, upd_request_t *request) {
    // It should be immediately available given that this starts first
    while (xSemaphoreTake(gtwy->firmware_semaphore, portMAX_DELAY) == pdFALSE) {
    }
    VS_LOG_DEBUG("[MB_NOTIFY]:In while loop and got firmware semaphore");

    VS_LOG_DEBUG("[MB_NOTIFY]: Fetch new firmware from URL %s", request->upd_file_url);
    if (GATEWAY_OK == fetch_and_store_fw_file(request->upd_file_url, NULL)) {
        VS_LOG_DEBUG("[MB_NOTIFY]:FW Successful fetched");
        // TODO: Check for firmware
    }

    (void)xSemaphoreGive(gtwy->firmware_semaphore);
    VS_LOG_DEBUG("[MB_NOTIFY]:Firmware semaphore freed");

    // This thread needs to be signaled by the off chance that there was a powerloss
    xEventGroupSetBits(gtwy->firmware_event_group, NEW_FIRMWARE_HTTP_BIT);
    vPortFree(request);
}

/*************************************************************************/
static void
tl_retrieval_mb_notify(gtwy_t *gtwy, upd_request_t *request) {
    while (xSemaphoreTake(gtwy->tl_semaphore, portMAX_DELAY) == pdFALSE) {
    }
    VS_LOG_DEBUG("[MB_NOTIFY]:In while loop and got TL semaphore\r\n");

    if (GATEWAY_OK == fetch_and_store_tl(request->upd_file_url, NULL)) {
        VS_LOG_DEBUG("[MB_NOTIFY]:TL Successful fetched\r\n");
        // TODO: Check for firmware
    }

    (void)xSemaphoreGive(gtwy->tl_semaphore);
    VS_LOG_DEBUG("[MB_NOTIFY]:TL semaphore freed\r\n");
    vPortFree(request);
}

/*************************************************************************/
static void
upd_http_retrieval(void *pvParameters) {
    gtwy_t *gtwy = get_gateway_ctx();

    // Wait for the sdmp stack and services to be up before looking for new firmware
    wait_indefinitely(gtwy->shared_event_group, SDMP_INIT_FINITE_BIT, pdTRUE);
    VS_LOG_DEBUG("upd_http_retrieval thread started");

    while (1) {
        upd_request_t *request;

        xEventGroupWaitBits(gtwy->firmware_event_group, MSG_BIN_RECEIVE_BIT, pdTRUE, pdFALSE, portMAX_DELAY);

        VS_LOG_DEBUG("upd_http_retrieval thread resume");

        while (message_bin_get_request(&request)) {
            if (MSG_BIN_UPD_TYPE_FW == request->upd_type) {
                sw_retrieval_mb_notify(gtwy, request);
            } else if (MSG_BIN_UPD_TYPE_TL == request->upd_type) {
                tl_retrieval_mb_notify(gtwy, request);
            } else {
                vPortFree(request);
            }
        }
    }
}

/*************************************************************************/
xTaskHandle *
start_upd_http_retrieval_thread(void) {
    if (!retrieval_started) {
        retrieval_started = (pdTRUE == xTaskCreate(upd_http_retrieval,
                                                   "sw-http-retrieval",
                                                   upd_retrieval_stack,
                                                   0,
                                                   OS_PRIO_3,
                                                   &upd_retrieval_thread));
    }
    return &upd_retrieval_thread;
}
