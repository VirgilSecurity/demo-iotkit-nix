#include <errno.h>

#include <pwd.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libgen.h>

#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <stdlib-config.h>
#include "sdk-impl/storage/storage-nix-impl.h"

#include "sdk-impl/netif/netif-queue.h"

#include "helpers/file-io.h"
#include <virgil/iot/firmware/firmware.h>
#include <virgil/iot/cloud/cloud.h>
#include <update-config.h>

#define NEW_APP_EXTEN ".new"
#define BACKUP_APP_EXTEN ".old"

#define CMD_STR_CPY_TEMPLATE "cp %s %s"
#define CMD_STR_MV_TEMPLATE "mv %s %s"
#define CMD_STR_START_TEMPLATE "%s %s"

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/storage_hal/storage_hal.h>

char *self_path = NULL;

/******************************************************************************/
vs_status_e
vs_firmware_install_prepare_space_hal(void) {
    char filename[FILENAME_MAX];

    CHECK_NOT_ZERO_RET(self_path, VS_CODE_ERR_INCORRECT_PARAMETER);
    VS_IOT_STRCPY(filename, self_path);

    strcat(filename, ".new");
    remove(filename);
    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_firmware_install_append_data_hal(const void *data, uint16_t data_sz) {

    vs_status_e res = VS_CODE_ERR_FILE;
    char filename[FILENAME_MAX];
    FILE *fp = NULL;

    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_INCORRECT_PARAMETER);
    CHECK_NOT_ZERO_RET(self_path, VS_CODE_ERR_INCORRECT_PARAMETER);

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
            res = VS_CODE_OK;
        }
        fclose(fp);
    }

    return res;
}

/******************************************************************************/
// static void
//_delete_bad_firmware(const char *manufacture_id_str, const char *device_type_str) {

//    vs_device_manufacture_id_t manufacture_id;
//    vs_device_type_t device_type;
//    vs_storage_op_ctx_t op_ctx;
//    vs_firmware_descriptor_t desc;
//
//    assert(manufacture_id_str);
//    assert(device_type_str);
//
//    op_ctx.impl_func = vs_rpi_storage_impl_func();
//    assert(op_ctx.impl_func.deinit);
//    op_ctx.file_sz_limit = VS_MAX_FIRMWARE_UPDATE_SIZE;
//
//    op_ctx.impl_data = vs_rpi_storage_impl_data_init(vs_rpi_get_firmware_dir());
//
//    _create_field(manufacture_id, manufacture_id_str, VS_DEVICE_MANUFACTURE_ID_SIZE);
//    _create_field(device_type, device_type_str, VS_DEVICE_TYPE_SIZE);
//
//    if (VS_CODE_OK != vs_firmware_load_firmware_descriptor(&op_ctx, manufacture_id, device_type, &desc)) {
//        VS_LOG_WARNING("Unable to obtain Firmware's descriptor");
//    } else {
//        vs_firmware_delete_firmware(&op_ctx, &desc);
//    }
//
//    op_ctx.impl_func.deinit(op_ctx.impl_data);
//    VS_LOG_INFO("Bad firmware has been deleted");
//}

/******************************************************************************/
int
vs_rpi_hal_update(const char *manufacture_id_str, const char *device_type_str, int argc, char *argv[]) {
    //    char old_app[FILENAME_MAX];
    //    char new_app[FILENAME_MAX];
    //    char cmd_str[sizeof(new_app) + sizeof(old_app) + 1];
    //
    //    //    if (!_need_restart) {
    //    //        return 0;
    //    //    }
    //
    //    if (NULL == _self_path) {
    //        return -1;
    //    }
    //
    //    size_t pos;
    //
    //    VS_LOG_INFO("Try to update app");
    //
    //    strncpy(new_app, _self_path, sizeof(new_app) - sizeof(NEW_APP_EXTEN));
    //    strncpy(old_app, _self_path, sizeof(new_app) - sizeof(BACKUP_APP_EXTEN));
    //
    //    strcat(old_app, BACKUP_APP_EXTEN);
    //    strcat(new_app, NEW_APP_EXTEN);
    //
    //    uint32_t args_len = 0;
    //
    //    for (pos = 1; pos < argc; ++pos) {
    //        args_len += strlen(argv[pos]);
    //    }
    //
    //    // argc == number of necessary spaces + \0 (because of we use argv starting from the 1st cell, not zero cell)
    //    char copy_args[args_len + argc];
    //    copy_args[0] = 0;
    //
    //    for (pos = 1; pos < argc; ++pos) {
    //        strcat(copy_args, argv[pos]);
    //        strcat(copy_args, " ");
    //    }
    //
    //    // Create backup of current app
    //    VS_IOT_SNPRINTF(cmd_str, sizeof(cmd_str), CMD_STR_CPY_TEMPLATE, _self_path, old_app);
    //    if (-1 == system(cmd_str)) {
    //        VS_LOG_ERROR("Error backup current app. errno = %d (%s)", errno, strerror(errno));
    //
    //        // restart self
    //        VS_LOG_INFO("Restart current app");
    //        VS_IOT_SNPRINTF(cmd_str, sizeof(cmd_str), CMD_STR_START_TEMPLATE, _self_path, copy_args);
    //        if (-1 == execl("/bin/bash", "/bin/bash", "-c", cmd_str, NULL)) {
    //            VS_LOG_ERROR("Error restart current app. errno = %d (%s)", errno, strerror(errno));
    //            return -1;
    //        }
    //    }
    //
    //    // Update current app to new
    //    VS_IOT_SNPRINTF(cmd_str, sizeof(cmd_str), CMD_STR_MV_TEMPLATE, new_app, _self_path);
    //    if (-1 == system(cmd_str) || -1 == chmod(_self_path, S_IXUSR | S_IWUSR | S_IRUSR)) {
    //        VS_LOG_ERROR("Error update app. errno = %d (%s)", errno, strerror(errno));
    //
    //        // restart self
    //        VS_LOG_INFO("Restart current app");
    //        VS_IOT_SNPRINTF(cmd_str, sizeof(cmd_str), CMD_STR_START_TEMPLATE, _self_path, copy_args);
    //        if (-1 == execl("/bin/bash", "/bin/bash", "-c", cmd_str, NULL)) {
    //            VS_LOG_ERROR("Error restart current app. errno = %d (%s)", errno, strerror(errno));
    //            return -1;
    //        }
    //    }
    //
    //    // Start new app
    //    if (-1 == execv(_self_path, argv)) {
    //        VS_LOG_ERROR("Error start new app. errno = %d (%s)", errno, strerror(errno));
    //
    //        // remove the bad stored firmware image
    //        _delete_bad_firmware(manufacture_id_str, device_type_str);
    //
    //        // restore current app
    //        VS_LOG_INFO("Restore current app");
    //        VS_IOT_SNPRINTF(cmd_str, sizeof(cmd_str), CMD_STR_MV_TEMPLATE, old_app, _self_path);
    //        if (-1 == system(cmd_str)) {
    //            VS_LOG_ERROR("Error restore current app. errno = %d (%s)", errno, strerror(errno));
    //            return -1;
    //        }
    //
    //        // restart self
    //        VS_LOG_INFO("Restart current app");
    //        VS_IOT_SNPRINTF(cmd_str, sizeof(cmd_str), CMD_STR_START_TEMPLATE, _self_path, copy_args);
    //        if (-1 == execl("/bin/bash", "/bin/bash", "-c", cmd_str, NULL)) {
    //            VS_LOG_ERROR("Error restart current app. errno = %d (%s)", errno, strerror(errno));
    //            return -1;
    //        }
    //    }
    //
    //    VS_LOG_ERROR("Something wrong");
    return -1;
}


/******************************************************************************/
// static void
//_ntoh_fw_desdcriptor(vs_firmware_descriptor_t *desc) {
//    desc->chunk_size = ntohs(desc->chunk_size);
//    desc->app_size = ntohl(desc->app_size);
//    desc->firmware_length = ntohl(desc->firmware_length);
//    desc->info.version.timestamp = ntohl(desc->info.version.timestamp);
//}

/******************************************************************************/
vs_status_e
vs_load_own_footer(uint8_t *footer, uint16_t footer_sz) {
    //    FILE *fp = NULL;
    vs_status_e res = VS_CODE_ERR_FILE_READ;
    //    ssize_t length;
    //
    //    assert(footer);
    //    assert(_self_path);
    //
    //    CHECK_NOT_ZERO_RET(footer, VS_CODE_ERR_FILE_READ);
    //    CHECK_NOT_ZERO_RET(_self_path, VS_CODE_ERR_FILE_READ);
    //
    //    vs_firmware_footer_t *own_footer = (vs_firmware_footer_t *)footer;
    //
    //    fp = fopen(_self_path, "rb");
    //
    //    CHECK(fp, "Unable to open file %s. errno = %d (%s)", _self_path, errno, strerror(errno));
    //
    //    CHECK(0 == fseek(fp, 0, SEEK_END), "Unable to seek file %s. errno = %d (%s)", _self_path, errno,
    //    strerror(errno));
    //
    //    length = ftell(fp);
    //    CHECK(length > 0, "Unable to get file length %s. errno = %d (%s)", _self_path, errno, strerror(errno));
    //    CHECK(length > footer_sz, "Wrong self file format");
    //
    //    CHECK(0 == fseek(fp, length - footer_sz, SEEK_SET),
    //          "Unable to seek file %s. errno = %d (%s)",
    //          _self_path,
    //          errno,
    //          strerror(errno));
    //
    //    CHECK(1 == fread((void *)footer, footer_sz, 1, fp),
    //          "Unable to read file %s. errno = %d (%s)",
    //          _self_path,
    //          errno,
    //          strerror(errno));
    //
    //    vs_cloud_ntoh_fw_descriptor(&own_footer->descriptor);
    //
    //    // Simple validation of own descriptor
    //    if (own_footer->signatures_count != VS_FW_SIGNATURES_QTY ||
    //        0 != memcmp(own_footer->descriptor.info.device_type, _device_type, sizeof(vs_device_type_t)) ||
    //        0 != memcmp(own_footer->descriptor.info.manufacture_id, _manufacture_id,
    //        sizeof(vs_device_manufacture_id_t))) { VS_LOG_ERROR("Bad own descriptor!!!! Application aborted");
    //        exit(-1);
    //    }
    //
    //    res = VS_CODE_OK;
    //
    // terminate:
    //    if (fp) {
    //        fclose(fp);
    //    }

    return res;
}

/******************************************************************************/
vs_status_e
vs_firmware_get_own_firmware_footer_hal(void *footer, size_t footer_sz) {
    assert(footer);
    CHECK_NOT_ZERO_RET(footer, VS_CODE_ERR_NULLPTR_ARGUMENT);

    return vs_load_own_footer(footer, footer_sz);
}

/******************************************************************************/
