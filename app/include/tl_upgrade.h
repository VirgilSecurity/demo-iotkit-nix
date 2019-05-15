#ifndef GATEWAY_TL_UPGRADE
#define GATEWAY_TL_UPGRADE
#include <stdint.h>
#include "iot_mqtt.h"

#define TL_TOPIC_MASK "tl/"

#define TL_URL_FILED "trustlist_url"
#define TL_VERSION_FILED "version"
#define TL_TYPE_FILED "type"

typedef struct __attribute__((__packed__)) {
    uint16_t version;
    uint8_t type;
} tl_info_t;

typedef struct {
    int version;
    int type;
    char file_url[UPD_URL_STR_SIZE];
} tl_manifest_entry;

int
parse_tl_mainfest(void *payload, size_t payload_len, char *tl_url, gtwy_t *gtwy);
int
fetch_tl(gtwy_t *gtwy, void *data_source, tl_info_t *tl_info);

int
fetch_and_store_tl(const char *tl_file_url, void *pData);
#endif // GATEWAY_TL_UPGRADE
