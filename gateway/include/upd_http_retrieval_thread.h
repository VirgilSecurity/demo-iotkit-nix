/*
 * upd_http_retrieval_thread.h
 *
 *  Created on: Jan 19, 2018
 */

#ifndef UPD_HTTP_RETRIEVAL_THREAD_H_
#define UPD_HTTP_RETRIEVAL_THREAD_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <virgil/iot/update/update.h>

typedef struct __attribute__((__packed__)) {
    enum vs_update_file_type_id_t file_type;
    union {
        vs_firmware_info_t fw_info;
    };
} queued_file_t;

pthread_t *
vs_start_upd_http_retrieval_thread(void);

bool
vs_upd_http_retrieval_get_request(queued_file_t **request);

#endif // UPD_HTTP_RETRIEVAL_THREAD_H_
