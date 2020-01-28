from optparse import OptionParser

import common
from utils import initializer


def print_initializer_cmd(exe):
    cmd = initializer.prepare_cmd(provision_pack_path=common.TP_PROVISION_PACK_FOLDER,
                                  initializer_exe=exe,
                                  output_file=common.INITIALIZER_OUTPUT,
                                  info_output_file=common.INITIALIZER_INFO_OUTPUT)
    print(cmd.replace(' --', ' \\\n\t--'))


if __name__ == '__main__':
    # Parse arguments
    parser = OptionParser()
    parser.add_option('-e', '--initializer-exe',
                      dest='initializer_exe',
                      help='Path to Virgil Device Initializer')
    (options, args) = parser.parse_args()

    # Print Virgil Device Initializer invocation command
    print_initializer_cmd(options.initializer_exe)
