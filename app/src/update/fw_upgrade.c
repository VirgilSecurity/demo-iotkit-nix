#include <string.h>
#include <stdbool.h>
#include <stdint.h>
//#include <json_parser.h>

#include <virgil/iot/logger/logger.h>
#include "gateway.h"
#include "gateway_macro.h"
#include "fw_upgrade.h"


/*************************************************************************/
int
fetch_firmware(gtwy_t *gtwy, void *data_source, firmware_info_t *fw_info) {
    return GATEWAY_ERROR;
}

/*************************************************************************/
int
parseFirmwareManifest(void *payload, size_t payload_len, char *fw_url, gtwy_t *gtwy) {
    memset(fw_url, 0, UPD_URL_STR_SIZE);
    VS_LOG_DEBUG("NEW FIRMWARE: %s", (char *)payload);
    return GATEWAY_OK;
}

/*************************************************************************/
int
fetch_and_store_fw_file(const char *fw_file_url, void *pData) {
    return GATEWAY_ERROR;
}