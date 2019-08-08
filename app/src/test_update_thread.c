#if SIM_FETCH_FIRMWARE
#include "test_update_thread.h"
#include <virgil/iot/logger/logger.h>
#include "platform/platform_os.h"
#include "message_bin.h"

#include "queue.h"
#include "event_groups.h"
#include "hal/file_io_hal.h"
#include <virgil/iot/cloud/private/cloud_hal.h>
#include "event_group_bit_flags.h"
#include "gateway.h"

#define SIM_FETCH_QUEUE_SZ 10
xQueueHandle *upd_event_queue;
static xTaskHandle sim_fetch_fw_thread;
static const uint16_t sim_fetch_fw_stack = 2 * 1024;
static bool sim_fetch_fw_started;

/*************************************************************************/
static void
sim_fetch_fw_func(void *pvParameters) {
    gtwy_t *gtwy = get_gateway_ctx();

    wait_indefinitely(gtwy->shared_event_group, SDMP_INIT_FINITE_BIT, pdTRUE);
    xEventGroupSetBits(gtwy->shared_event_group, SDMP_INIT_FINITE_BIT);

    upd_request_t *fw_url = (upd_request_t *)VS_IOT_CALLOC(sizeof(upd_request_t), 1);

    fw_url->upd_type = MSG_BIN_UPD_TYPE_FW;

    if (pdTRUE != xQueueSendToBack(*upd_event_queue, &fw_url, OS_NO_WAIT)) {
        VS_LOG_ERROR("[MB] Failed to send MSG BIN data to output processing!!!");
        vPortFree(fw_url);
    } else {
        xEventGroupSetBits(gtwy->firmware_event_group, MSG_BIN_RECEIVE_BIT);
        VS_LOG_ERROR("[MB] Send simulated upadte request");
    }

    while (true) {
        vTaskDelay(portMAX_DELAY);
    }
}

/*************************************************************************/
xTaskHandle *
start_sim_fetch_thread(void) {
    if (!sim_fetch_fw_started) {
        upd_event_queue = (xQueueHandle *)pvPortMalloc(sizeof(xQueueHandle));
        *upd_event_queue = xQueueCreate(SIM_FETCH_QUEUE_SZ, sizeof(upd_request_t *));
        sim_fetch_fw_started = (pdTRUE == xTaskCreate(sim_fetch_fw_func,
                                                      "sim_fetch_fw_task",
                                                      sim_fetch_fw_stack,
                                                      0,
                                                      OS_PRIO_3,
                                                      &sim_fetch_fw_thread));
    }
    return &sim_fetch_fw_thread;
}
#endif // SIM_FETCH_FIRMWARE