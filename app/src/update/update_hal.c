#include <errno.h>

#include <pwd.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libgen.h>

#include "FreeRTOS.h"
#include "gateway.h"
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/update/update.h>
#include <virgil/iot/update/update_interface.h>

#include <hal/file_io_hal.h>

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


/******************************************************************************/
int
vs_update_get_firmware_descriptor_table_len_hal(void) {
    int file_sz;
    file_sz = vs_gateway_get_file_len(vs_gateway_get_firmware_dir(), DESCRIPTORS_FILENAME);

    return (file_sz > 0) ? file_sz : VS_UPDATE_ERR_NOT_FOUND;
}

/******************************************************************************/
int
vs_update_get_firmware_image_len_hal(uint8_t *manufacture_id, uint8_t *device_type) {

    char filename[FILENAME_MAX];
    int file_sz;

    CHECK_NOT_ZERO_RET(manufacture_id, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO_RET(device_type, VS_UPDATE_ERR_INVAL);
    CHECK_RET(VS_UPDATE_ERR_OK == _create_firmware_filename(manufacture_id, device_type, filename, sizeof(filename)),
              VS_UPDATE_ERR_FAIL,
              "Error create filename")

    file_sz = vs_gateway_get_file_len(vs_gateway_get_firmware_dir(), filename);

    return (file_sz > 0) ? file_sz : VS_UPDATE_ERR_NOT_FOUND;
}

/******************************************************************************/
int
vs_update_read_firmware_descriptor_table_hal(uint8_t *data, uint16_t buf_sz, uint16_t *read_sz) {
    CHECK_NOT_ZERO_RET(data, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO_RET(read_sz, VS_UPDATE_ERR_INVAL);
    return vs_gateway_read_file_data(vs_gateway_get_firmware_dir(), DESCRIPTORS_FILENAME, 0, data, buf_sz, read_sz)
                   ? VS_UPDATE_ERR_OK
                   : VS_UPDATE_ERR_FAIL;
}

/******************************************************************************/
int
vs_update_read_firmware_data_hal(uint8_t *manufacture_id,
                                 uint8_t *device_type,
                                 uint32_t offset,
                                 uint8_t *data,
                                 uint16_t buf_sz,
                                 uint16_t *read_sz) {
    CHECK_NOT_ZERO_RET(data, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO_RET(read_sz, VS_UPDATE_ERR_INVAL);

    char filename[FILENAME_MAX];

    CHECK_NOT_ZERO_RET(manufacture_id, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO_RET(device_type, VS_UPDATE_ERR_INVAL);

    CHECK_RET(VS_UPDATE_ERR_OK == _create_firmware_filename(manufacture_id, device_type, filename, sizeof(filename)),
              VS_UPDATE_ERR_FAIL,
              "Error create filename")
    return vs_gateway_read_file_data(vs_gateway_get_firmware_dir(), filename, offset, data, buf_sz, read_sz)
                   ? VS_UPDATE_ERR_OK
                   : VS_UPDATE_ERR_FAIL;
}

/******************************************************************************/
int
vs_update_write_firmware_descriptor_table_hal(const void *data, uint16_t data_sz) {

    CHECK_NOT_ZERO_RET(data, VS_UPDATE_ERR_INVAL);
    return vs_gateway_write_file_data(vs_gateway_get_firmware_dir(), DESCRIPTORS_FILENAME, 0, data, data_sz)
                   ? VS_UPDATE_ERR_OK
                   : VS_UPDATE_ERR_FAIL;
}

/******************************************************************************/
int
vs_update_write_firmware_data_hal(uint8_t *manufacture_id,
                                  uint8_t *device_type,
                                  uint32_t offset,
                                  const void *data,
                                  uint16_t data_sz) {
    char filename[FILENAME_MAX];
    CHECK_NOT_ZERO_RET(data, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO_RET(manufacture_id, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO_RET(device_type, VS_UPDATE_ERR_INVAL);

    CHECK_RET(VS_UPDATE_ERR_OK == _create_firmware_filename(manufacture_id, device_type, filename, sizeof(filename)),
              VS_UPDATE_ERR_FAIL,
              "Error create filename")
    return vs_gateway_write_file_data(vs_gateway_get_firmware_dir(), filename, offset, data, data_sz)
                   ? VS_UPDATE_ERR_OK
                   : VS_UPDATE_ERR_FAIL;
}

/******************************************************************************/
int
vs_update_remove_firmware_descriptor_table_hal(void) {
    return vs_gateway_remove_file_data(vs_gateway_get_firmware_dir(), DESCRIPTORS_FILENAME) ? VS_UPDATE_ERR_OK
                                                                                            : VS_UPDATE_ERR_FAIL;
}

/******************************************************************************/
int
vs_update_remove_firmware_data_hal(uint8_t *manufacture_id, uint8_t *device_type) {

    char filename[FILENAME_MAX];

    CHECK_NOT_ZERO_RET(manufacture_id, VS_UPDATE_ERR_INVAL);
    CHECK_NOT_ZERO_RET(device_type, VS_UPDATE_ERR_INVAL);

    CHECK_RET(VS_UPDATE_ERR_OK == _create_firmware_filename(manufacture_id, device_type, filename, sizeof(filename)),
              VS_UPDATE_ERR_FAIL,
              "Error create filename")
    return vs_gateway_remove_file_data(vs_gateway_get_firmware_dir(), filename) ? VS_UPDATE_ERR_OK : VS_UPDATE_ERR_FAIL;
}


/******************************************************************************/
int
vs_update_install_prepare_space_hal(void) {
    char filename[FILENAME_MAX];

    VS_IOT_STRCPY(filename, self_path);

    strcat(filename, ".new");
    remove(filename);
    return VS_UPDATE_ERR_OK;
}

/******************************************************************************/
int
vs_update_install_append_data_hal(const void *data, uint16_t data_sz) {

    int res = VS_UPDATE_ERR_FAIL;
    char filename[FILENAME_MAX];
    FILE *fp = NULL;

    CHECK_NOT_ZERO_RET(data, VS_UPDATE_ERR_INVAL);

    VS_IOT_STRCPY(filename, self_path);

    strcat(filename, ".new");

    fp = fopen(filename, "a+b");
    if (fp) {

        if (1 != fwrite(data, data_sz, 1, fp)) {
            VS_LOG_ERROR("Unable to write %d bytes to the file %s. errno = %d (%s)",
                         data_sz,
                         filename,
                         errno,
                         strerror(errno));
        } else {
            res = VS_UPDATE_ERR_OK;
        }
        fclose(fp);
    }

    return res;
}

/******************************************************************************/
int
vs_update_restart_app_hal(void){
    vTaskEndScheduler();
    while (1)
        ;
}