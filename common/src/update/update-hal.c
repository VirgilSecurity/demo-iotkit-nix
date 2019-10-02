#include <errno.h>

#include <pwd.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libgen.h>

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/storage_hal/storage_hal.h>

char *self_path = NULL;

/******************************************************************************/
vs_status_code_e
vs_firmware_install_prepare_space_hal(void) {
    char filename[FILENAME_MAX];

    CHECK_NOT_ZERO_RET(self_path, VS_CODE_ERR_INCORRECT_PARAMETER);
    VS_IOT_STRCPY(filename, self_path);

    strcat(filename, ".new");
    remove(filename);
    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_code_e
vs_firmware_install_append_data_hal(const void *data, uint16_t data_sz) {

    int res = VS_CODE_ERR_FILE;
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
