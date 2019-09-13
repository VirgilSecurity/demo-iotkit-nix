
#ifndef IOT_RPI_GATEWAY_TEST_UPDATE_THREAD_H
#define IOT_RPI_GATEWAY_TEST_UPDATE_THREAD_H

#include <stdint.h>
#include "FreeRTOS.h"
#include "task.h"

xTaskHandle *
start_sim_fetch_thread(void);
#endif // IOT_RPI_GATEWAY_TEST_UPDATE_THREAD_H
