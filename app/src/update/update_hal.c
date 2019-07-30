#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/update/update.h>
#include <virgil/iot/update/update_interface.h>

/*************************************************************************/
int
vs_update_load_firmware_chunk(vs_firmware_descriptor_t *descriptor,
                              uint32_t offset,
                              uint8_t *data,
                              uint32_t buff_sz,
                              uint32_t *data_sz) {
    CHECK_NOT_ZERO(descriptor, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(data, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(data_sz, VS_UPDATE_ERR_INVAL);

    return VS_UPDATE_ERR_OK;
}

/*************************************************************************/
int
vs_update_save_firmware_chunk(vs_firmware_descriptor_t *descriptor,
                              uint8_t *chunk,
                              uint32_t chunk_sz,
                              uint32_t offset) {
    CHECK_NOT_ZERO(descriptor, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(chunk, VS_UPDATE_ERR_INVAL);

    return VS_UPDATE_ERR_OK;
}

/*************************************************************************/
int
vs_update_save_firmware_footer(vs_firmware_descriptor_t *descriptor, uint8_t *footer) {
    CHECK_NOT_ZERO(descriptor, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(footer, VS_UPDATE_ERR_INVAL);

    return VS_UPDATE_ERR_OK;
}

/*************************************************************************/
int
vs_update_load_firmware_footer(vs_firmware_descriptor_t *descriptor,
                               uint8_t *data,
                               uint32_t buff_sz,
                               uint32_t *data_sz) {
    CHECK_NOT_ZERO(descriptor, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(data, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(data_sz, VS_UPDATE_ERR_INVAL);

    return VS_UPDATE_ERR_OK;
}
