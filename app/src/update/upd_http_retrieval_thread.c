
#include <stdbool.h>

#include "upd_http_retrieval_thread.h"
#include "message_bin.h"
#include "gateway.h"
#include "gateway_macro.h"
#include "platform/platform_os.h"
#include "event_group_bit_flags.h"

#include "semphr.h"
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/logger/logger.h>

static xTaskHandle upd_retrieval_thread;

static const uint16_t upd_retrieval_stack = 10 * 1024;

static bool retrieval_started;

#define FWDIST_QUEUE_SZ 10
xQueueHandle *fwdist_event_queue;

/*************************************************************************/
static void
_sw_retrieval_mb_notify(gtwy_t *gtwy, upd_request_t *request) {
    vs_cloud_firmware_header_t header;
    vs_firmware_info_t *fw_info = NULL;
    int res;
    // It should be immediately available given that this starts first
    while (xSemaphoreTake(gtwy->firmware_semaphore, portMAX_DELAY) == pdFALSE) {
    }
    VS_LOG_DEBUG("[MB_NOTIFY]:In while loop and got firmware semaphore");

    VS_LOG_DEBUG("[MB_NOTIFY]: Fetch new firmware from URL %s", request->upd_file_url);

    res = vs_cloud_fetch_and_store_fw_file(request->upd_file_url, &header);
    if (VS_CLOUD_ERR_OK == res) {
        VS_LOG_DEBUG("[MB_NOTIFY]:FW image stored succesfully");

        res = vs_update_verify_firmware(&header.descriptor);
        if (VS_UPDATE_ERR_OK == res) {

            VS_LOG_DEBUG("[MB_NOTIFY]:FW Successful fetched");

            fw_info = (vs_firmware_info_t *)pvPortMalloc(sizeof(vs_firmware_info_t));
            VS_IOT_MEMCPY(fw_info, &header.descriptor.info, sizeof(vs_firmware_info_t));

            if (pdTRUE != xQueueSendToBack(*fwdist_event_queue, &fw_info, OS_NO_WAIT)) {
                vPortFree(fw_info);
                VS_LOG_ERROR("[MB] Failed to send fw info to output processing!!!");
            }

        } else {
            VS_LOG_DEBUG("[MB_NOTIFY]:Error verify firmware image\r\n");
            vs_update_delete_firmware(&header.descriptor);
        }

    } else {
        VS_LOG_DEBUG("[MB_NOTIFY]:Error fetch new firmware\r\n");
    }

    (void)xSemaphoreGive(gtwy->firmware_semaphore);
    VS_LOG_DEBUG("[MB_NOTIFY]:Firmware semaphore freed");

    // This thread needs to be signaled by the off chance that there was a powerloss
    xEventGroupSetBits(gtwy->firmware_event_group, NEW_FIRMWARE_HTTP_BIT);
    vPortFree(request);
}

/*************************************************************************/
static void
_tl_retrieval_mb_notify(gtwy_t *gtwy, upd_request_t *request) {
    while (xSemaphoreTake(gtwy->tl_semaphore, portMAX_DELAY) == pdFALSE) {
    }
    VS_LOG_DEBUG("[MB_NOTIFY]:In while loop and got TL semaphore\r\n");

    if (VS_CLOUD_ERR_OK == vs_cloud_fetch_and_store_tl(request->upd_file_url)) {
        VS_LOG_DEBUG("[MB_NOTIFY]:TL Successful fetched\r\n");
    } else {
        VS_LOG_DEBUG("[MB_NOTIFY]:Error fetch new TL\r\n");
    }

    (void)xSemaphoreGive(gtwy->tl_semaphore);
    VS_LOG_DEBUG("[MB_NOTIFY]:TL semaphore freed\r\n");
    vPortFree(request);
}

/*************************************************************************/
static void
vs_upd_http_retrieval(void *pvParameters) {
    gtwy_t *gtwy = get_gateway_ctx();

    // Wait for the sdmp stack and services to be up before looking for new firmware
    wait_indefinitely(gtwy->shared_event_group, SDMP_INIT_FINITE_BIT, pdTRUE);
    xEventGroupSetBits(gtwy->shared_event_group, SDMP_INIT_FINITE_BIT);
    VS_LOG_DEBUG("vs_upd_http_retrieval thread started");

    while (1) {
        upd_request_t *request;

        xEventGroupWaitBits(gtwy->firmware_event_group, MSG_BIN_RECEIVE_BIT, pdTRUE, pdFALSE, portMAX_DELAY);

        VS_LOG_DEBUG("vs_upd_http_retrieval thread resume");

        while (message_bin_get_request(&request)) {
            if (MSG_BIN_UPD_TYPE_FW == request->upd_type) {
                _sw_retrieval_mb_notify(gtwy, request);
            } else if (MSG_BIN_UPD_TYPE_TL == request->upd_type) {
                _tl_retrieval_mb_notify(gtwy, request);
            } else {
                vPortFree(request);
            }
        }
    }
}

/*************************************************************************/
xTaskHandle *
vs_start_upd_http_retrieval_thread(void) {
    if (!retrieval_started) {
        fwdist_event_queue = (xQueueHandle *)pvPortMalloc(sizeof(xQueueHandle));
        CHECK_NOT_ZERO(fwdist_event_queue, NULL);
        *fwdist_event_queue = xQueueCreate(FWDIST_QUEUE_SZ, sizeof(vs_firmware_info_t *));
        retrieval_started = (pdTRUE == xTaskCreate(vs_upd_http_retrieval,
                                                   "sw-http-retrieval",
                                                   upd_retrieval_stack,
                                                   0,
                                                   OS_PRIO_3,
                                                   &upd_retrieval_thread));
    }
    return &upd_retrieval_thread;
}

/*************************************************************************/
bool
vs_upd_http_retrieval_get_request(vs_firmware_info_t **request) {

    if (uxQueueMessagesWaiting(*fwdist_event_queue)) {
        if (pdTRUE == xQueueReceive(*fwdist_event_queue, request, 0))
            return true;
    }
    *request = NULL;
    return false;
}
