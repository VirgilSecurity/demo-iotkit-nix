#include <string.h>
#include <stdbool.h>
#include <stdint.h>
//#include <json_parser.h>

#include <virgil/iot/logger/logger.h>
#include "gateway.h"
#include "gateway_macro.h"
#include "tl_upgrade.h"
#include "event_group_bit_flags.h"

/*************************************************************************/
int
parse_tl_mainfest(void *payload, size_t payload_len, char *tl_url, gtwy_t *gtwy) {
    VS_LOG_DEBUG("NEW TL: %s", (char *)payload);
    return GATEWAY_OK;
}

/*************************************************************************/
int
fetch_tl(gtwy_t *gtwy, void *data_source, tl_info_t *tl_info) {
    return GATEWAY_ERROR;
}

/*************************************************************************/
int
fetch_and_store_tl(const char *tl_file_url, void *pData) {
    return GATEWAY_ERROR;
}