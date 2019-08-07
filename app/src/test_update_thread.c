
#include "test_update_thread.h"
#include <virgil/iot/logger/logger.h>
#include "platform/platform_os.h"

static xTaskHandle test_update_thread;

static const uint16_t test_update_stack = 2 * 1024;

static bool test_update_started;

static const char _test_message[] = TEST_UPDATE_MESSAGE;

static void
test_update(void *pvParameters) {

    while (true) {
        if (_test_message[0] != 0) {
            VS_LOG_INFO(_test_message);
        }
        vTaskDelay(300 / portTICK_PERIOD_MS);
    }
}

xTaskHandle *
start_test_update_thread(void) {
    if (!test_update_started) {
        test_update_started =
                (pdTRUE ==
                 xTaskCreate(test_update, "test-update", test_update_stack, 0, OS_PRIO_3, &test_update_thread));
    }
    return &test_update_thread;
}