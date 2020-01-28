import os
from optparse import OptionParser
from shutil import rmtree

import common
from utils import trust_provisioner
from utils.processes import CmdSubProcess


def cleanup_output():
    if os.path.exists(common.OUTPUT_FOLDER):
        rmtree(common.OUTPUT_FOLDER)
    os.makedirs(common.OUTPUT_FOLDER)


def create_tp_config(iot_api_url):
    trust_provisioner.create_config(config_path=common.TP_CONFIG_PATH,
                                    storage_path=common.OUTPUT_FOLDER,
                                    log_path=common.OUTPUT_FOLDER,
                                    provision_pack_path=common.TP_PROVISION_PACK_FOLDER,
                                    iot_api_url=iot_api_url)


def create_factory_info_json():
    trust_provisioner.create_factory_info_json(common.FACTORY_INFO_JSON_PATH)


def prepare_tp_process(virgil_app_token):
    cmd = 'virgil-trust-provisioner -c {0} -t {1} -i {2} -y'.format(common.TP_CONFIG_PATH,
                                                                    virgil_app_token,
                                                                    common.FACTORY_INFO_JSON_PATH)
    process = CmdSubProcess(cmd, print_output=True)
    process.run_in_thread()
    return process


def generate_provision_package(virgil_app_token):
    tp_process = prepare_tp_process(virgil_app_token)
    try:
        tp = trust_provisioner.TrustProvisioner(tp_process)
        tp.generate_upper_level_keys()
        tp.generate_release_trust_list()
        tp.export_provision_package()
        tp.exit()
    finally:
        tp_process.kill()


if __name__ == '__main__':
    # Parse arguments
    parser = OptionParser()
    parser.add_option('-t', '--virgil-app-token',
                      dest='virgil_app_token',
                      help='Virgil Application token')
    parser.add_option('-u', '--iot-api-url',
                      dest='iot_api_url',
                      help='Virgil IoT api URL')
    (options, args) = parser.parse_args()

    # Cleanup previous provision package and temp files
    cleanup_output()

    # Create config for Trust Provisioner
    create_tp_config(options.iot_api_url)

    # Create sample json with factory info
    create_factory_info_json()

    # Generate provision package
    generate_provision_package(options.virgil_app_token)
