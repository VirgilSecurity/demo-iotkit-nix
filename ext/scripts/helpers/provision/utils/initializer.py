import os
import re


def _find_files(path, pattern, regex=False):
    result = []
    for root, dirs, files in os.walk(path):
        for f_name in files:
            full_path = os.path.join(root, f_name)
            search_in = full_path.split(path)[-1]
            if regex:
                match = re.search(pattern, search_in)
            else:
                match = pattern in search_in
            if match:
                result.append(full_path)
    return result


def prepare_cmd(provision_pack_path,
                initializer_exe,
                output_file,
                info_output_file):
    private = os.path.join(provision_pack_path, 'private')
    pubkeys = os.path.join(provision_pack_path, 'pubkeys')

    # Public keys
    auth_pub_key_1, auth_pub_key_2 = _find_files(provision_pack_path, 'auth_')
    rec_pub_key_1, rec_pub_key_2 = _find_files(pubkeys, 'recovery_')
    tl_pub_key_1, tl_pub_key_2 = _find_files(pubkeys, 'tl_')
    fw_pub_key_1, fw_pub_key_2 = _find_files(pubkeys, 'firmware_')

    # Private key
    factory_key, *_ = _find_files(private, 'factory_')

    # Trust List
    trust_list, *_ = _find_files(provision_pack_path, 'TrustList_')

    cmd = (
        '{initializer_exe} '
        '--output "{output_file}" '
        '--device_info_output "{info_output_file}" '
        '--auth_pub_key_1 "{auth_pub_key_1}" '
        '--auth_pub_key_2 "{auth_pub_key_2}" '
        '--rec_pub_key_1 "{rec_pub_key_1}" '
        '--rec_pub_key_2 "{rec_pub_key_2}" '
        '--tl_pub_key_1 "{tl_pub_key_1}" '
        '--tl_pub_key_2 "{tl_pub_key_2}" '
        '--fw_pub_key_1 "{fw_pub_key_1}" '
        '--fw_pub_key_2 "{fw_pub_key_2}" '
        '--trust_list "{trust_list}" '
        '--factory_key "{factory_key}"'
    ).format(**locals())

    return cmd

