#include <string.h>
#include <stdbool.h>
#include <stdint.h>
//#include <json_parser.h>

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
    return GATEWAY_ERROR;
}

/*************************************************************************/
int
fetch_and_store_fw_file(const char *fw_file_url, void *pData) {
    return GATEWAY_ERROR;
}