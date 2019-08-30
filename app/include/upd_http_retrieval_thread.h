/*
 * upd_http_retrieval_thread.h
 *
 *  Created on: Jan 19, 2018
 */

#ifndef UPD_HTTP_RETRIEVAL_THREAD_H_
#define UPD_HTTP_RETRIEVAL_THREAD_H_

#include <stdint.h>
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "event_groups.h"
#include <virgil/iot/update/update.h>

xTaskHandle *
vs_start_upd_http_retrieval_thread(void);

bool
vs_upd_http_retrieval_get_request(vs_firmware_info_t **request);

#define MINS_TO_S(mins) (mins * 60)
#define HOURS_TO_S(hours) (hours * MINS_TO_S(60))

#endif // UPD_HTTP_RETRIEVAL_THREAD_H_
