
#include "FreeRTOS.h"
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/update/update.h>
#include <virgil/iot/update/update_interface.h>

#include <hal/file_io_hal.h>
#include <virgil/iot/cloud/cloud.h>
#include <virgil/iot/provision/provision.h>
#include <virgil/iot/hsm/hsm_helpers.h>

#define DESCRIPTORS_FILENAME "firmware_descriptors"
/*************************************************************************/
static int
_create_firmware_filename(uint8_t *uuid, uint8_t *dev_type, char *filename, uint32_t buf_sz) {

    int res = snprintf(filename,
                       buf_sz,
                       "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x_%x%x%x%x",
                       uuid[0],
                       uuid[1],
                       uuid[2],
                       uuid[3],
                       uuid[4],
                       uuid[5],
                       uuid[6],
                       uuid[7],
                       uuid[8],
                       uuid[9],
                       uuid[10],
                       uuid[11],
                       uuid[12],
                       uuid[13],
                       uuid[14],
                       uuid[15],
                       dev_type[0],
                       dev_type[1],
                       dev_type[2],
                       dev_type[3]);

    CHECK_RET(res > 0, VS_UPDATE_ERR_FAIL, "snprintf error result %d", res)

    return VS_UPDATE_ERR_OK;
}

/*************************************************************************/
int
vs_update_load_firmware_chunk(vs_firmware_descriptor_t *descriptor,
                              uint32_t offset,
                              uint8_t *data,
                              uint16_t buff_sz,
                              uint16_t *data_sz) {
    char filename[FILENAME_MAX];
    CHECK_NOT_ZERO(descriptor, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(data, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(data_sz, VS_UPDATE_ERR_INVAL);

    CHECK_RET(VS_UPDATE_ERR_OK ==
                      _create_firmware_filename(
                              descriptor->manufacture_id, descriptor->device_type, filename, sizeof(filename)),
              VS_UPDATE_ERR_FAIL,
              "Error create filename")

    return vs_gateway_read_file_data(vs_gateway_get_firmware_dir(), filename, offset, data, buff_sz, data_sz)
                   ? VS_UPDATE_ERR_OK
                   : VS_UPDATE_ERR_FAIL;
}

/*************************************************************************/
int
vs_update_save_firmware_chunk(vs_firmware_descriptor_t *descriptor,
                              uint8_t *chunk,
                              uint16_t chunk_sz,
                              uint32_t offset) {
    char filename[FILENAME_MAX];

    CHECK_NOT_ZERO(descriptor, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(chunk, VS_UPDATE_ERR_INVAL);

    CHECK_RET(VS_UPDATE_ERR_OK ==
                      _create_firmware_filename(
                              descriptor->manufacture_id, descriptor->device_type, filename, sizeof(filename)),
              VS_UPDATE_ERR_FAIL,
              "Error create filename")

    return vs_gateway_write_file_data(vs_gateway_get_firmware_dir(), filename, offset, chunk, chunk_sz)
                   ? VS_UPDATE_ERR_OK
                   : VS_UPDATE_ERR_FAIL;
}

/*************************************************************************/
int
vs_update_save_firmware_footer(vs_firmware_descriptor_t *descriptor, uint8_t *footer) {
    char filename[FILENAME_MAX];
    uint16_t footer_sz = sizeof(vs_firmware_footer_t);
    vs_firmware_footer_t *f = (vs_firmware_footer_t *)footer;

    CHECK_NOT_ZERO(descriptor, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(footer, VS_UPDATE_ERR_INVAL);

    CHECK_RET(VS_UPDATE_ERR_OK ==
                      _create_firmware_filename(
                              descriptor->manufacture_id, descriptor->device_type, filename, sizeof(filename)),
              VS_UPDATE_ERR_FAIL,
              "Error create filename")

    if (0 != memcmp(descriptor, &f->descriptor, sizeof(vs_firmware_descriptor_t))) {
        VS_LOG_ERROR("Invalid firmware descriptor");
        return VS_UPDATE_ERR_INVAL;
    }

    for (uint8_t i = 0; i < f->signatures_count; ++i) {
        int key_len;
        int sign_len;
        vs_sign_t *sign = (vs_sign_t *)(footer + footer_sz);

        sign_len = vs_hsm_get_signature_len(sign->ec_type);
        key_len = vs_hsm_get_pubkey_len(sign->ec_type);

        CHECK_RET(sign_len > 0 && key_len > 0, VS_UPDATE_ERR_INVAL, "Unsupported signature ec_type")

        footer_sz += sizeof(vs_sign_t) + sign_len + key_len;
    }

    return vs_gateway_write_file_data(
                   vs_gateway_get_firmware_dir(), filename, descriptor->firmware_length, footer, footer_sz)
                   ? VS_UPDATE_ERR_OK
                   : VS_UPDATE_ERR_FAIL;
}

/*************************************************************************/
int
vs_update_load_firmware_footer(vs_firmware_descriptor_t *descriptor,
                               uint8_t *data,
                               uint16_t buff_sz,
                               uint16_t *data_sz) {
    char filename[FILENAME_MAX];

    CHECK_NOT_ZERO(descriptor, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(data, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO(data_sz, VS_UPDATE_ERR_INVAL);

    CHECK_RET(VS_UPDATE_ERR_OK ==
                      _create_firmware_filename(
                              descriptor->manufacture_id, descriptor->device_type, filename, sizeof(filename)),
              VS_UPDATE_ERR_FAIL,
              "Error create filename")

    return vs_gateway_read_file_data(
                   vs_gateway_get_firmware_dir(), filename, descriptor->firmware_length, data, buff_sz, data_sz)
                   ? VS_UPDATE_ERR_OK
                   : VS_UPDATE_ERR_FAIL;
}

/*************************************************************************/
int
vs_update_save_firmware_descriptor(vs_firmware_descriptor_t *descriptor) {
    int file_sz;
    uint8_t *buf = NULL;
    uint32_t offset = 0;

    CHECK_NOT_ZERO(descriptor, VS_UPDATE_ERR_INVAL);

    file_sz = vs_gateway_get_file_len(vs_gateway_get_firmware_dir(), DESCRIPTORS_FILENAME);

    if (file_sz > 0) {
        uint16_t read_sz;
        buf = VS_IOT_CALLOC(1, file_sz);
        CHECK_NOT_ZERO(buf, VS_UPDATE_ERR_FAIL);

        if (!vs_gateway_read_file_data(
                    vs_gateway_get_firmware_dir(), DESCRIPTORS_FILENAME, 0, buf, file_sz, &read_sz)) {
            VS_IOT_FREE(buf);
            return VS_UPDATE_ERR_FAIL;
        }

        while (offset < file_sz || offset + sizeof(vs_firmware_descriptor_t) > file_sz) {
            vs_firmware_descriptor_t *ptr = (vs_firmware_descriptor_t *)(buf + offset);

            if (0 == memcmp(ptr->manufacture_id, descriptor->manufacture_id, MANUFACTURE_ID_SIZE) &&
                0 == memcmp(ptr->device_type, descriptor->device_type, DEVICE_TYPE_SIZE)) {
                VS_IOT_MEMCPY(ptr, descriptor, sizeof(vs_firmware_descriptor_t));
                break;
            }

            offset += sizeof(vs_firmware_descriptor_t);
        }
    }

    VS_IOT_FREE(buf);

    return vs_gateway_write_file_data(vs_gateway_get_firmware_dir(),
                                      DESCRIPTORS_FILENAME,
                                      offset,
                                      descriptor,
                                      sizeof(vs_firmware_descriptor_t))
                   ? VS_UPDATE_ERR_OK
                   : VS_UPDATE_ERR_FAIL;
}

/*************************************************************************/
int
vs_update_load_firmware_descriptor(uint8_t manufacture_id[MANUFACTURE_ID_SIZE],
                                   uint8_t device_type[DEVICE_TYPE_SIZE],
                                   vs_firmware_descriptor_t *descriptor) {

    int file_sz;
    uint8_t *buf = NULL;
    uint32_t offset = 0;

    CHECK_NOT_ZERO(descriptor, VS_UPDATE_ERR_INVAL);

    file_sz = vs_gateway_get_file_len(vs_gateway_get_firmware_dir(), DESCRIPTORS_FILENAME);

    if (file_sz <= 0) {
        return VS_UPDATE_ERR_FAIL;
    }

    uint16_t read_sz;
    buf = VS_IOT_CALLOC(1, file_sz);
    CHECK_NOT_ZERO(buf, VS_UPDATE_ERR_FAIL);

    if (!vs_gateway_read_file_data(vs_gateway_get_firmware_dir(), DESCRIPTORS_FILENAME, 0, buf, file_sz, &read_sz)) {
        VS_IOT_FREE(buf);
        return VS_UPDATE_ERR_FAIL;
    }

    while (offset < file_sz || offset + sizeof(vs_firmware_descriptor_t) > file_sz) {
        vs_firmware_descriptor_t *ptr = (vs_firmware_descriptor_t *)(buf + offset);

        if (0 == memcmp(ptr->manufacture_id, manufacture_id, MANUFACTURE_ID_SIZE) &&
            0 == memcmp(ptr->device_type, manufacture_id, DEVICE_TYPE_SIZE)) {
            VS_IOT_MEMCPY(descriptor, ptr, sizeof(vs_firmware_descriptor_t));
            break;
        }

        offset += sizeof(vs_firmware_descriptor_t);
    }

    VS_IOT_FREE(buf);

    return VS_UPDATE_ERR_OK;
}