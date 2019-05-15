#ifndef GATEWAY_FW_UPGRADE
#define GATEWAY_FW_UPGRADE

#include <stdint.h>
#include "gateway.h"
#include "iot_mqtt.h"
#define MANIFEST "manifest"
#define FW_URL "firmware_url"

#define MANUFACTURE_ID_MB "manufacturer_id"
#define MODEL_ID_MB "model_type"
#define FW_VERSION_MB "version"

#define FW_TIMESTAMP "build_timestamp"
#define FW_TOPIC_MASK "fw/"

typedef struct __attribute__((__packed__)) {
    uint32_t application_type;
    uint8_t fw_major;
    uint8_t fw_minor;
    uint8_t fw_patch;
    uint8_t fw_dev_milestone;
    uint8_t fw_dev_build;
    char build_timestamp[12];
} firmware_version_t;

typedef struct __attribute__((__packed__)) firmware_info_s {
    uint32_t manufacturer;
    uint32_t model;
    firmware_version_t version_info;
} firmware_info_t;

typedef union {
    uint32_t id;
    char str[sizeof(uint32_t) + 1];
} readable_id_t;

typedef struct __attribute__((__packed__)) {
    readable_id_t manufID;
    readable_id_t modelID;
    char firmwareVersion[16];
    char fw_file_url[UPD_URL_STR_SIZE];
    char timestamp[13];
} firmware_manifest_entry;

int
fetch_firmware(gtwy_t *gtwy, void *data_source, firmware_info_t *fw_info);
int
parseFirmwareManifest(void *payload, size_t payload_len, char *fw_url, gtwy_t *gtwy);
int
fetch_and_store_fw_file(const char *fw_file_url, void *pData);


#endif // GATEWAY_FW_UPGRADE
