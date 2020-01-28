#!/bin/bash

#
#   Global variables
#
SCRIPT_FOLDER="$( cd "$( dirname "$0" )" && pwd )"
DEVICE_INITIALIZER="${SCRIPT_FOLDER}/../../cmake-build-debug/ext/virgil-iot-sdk/tools/virgil-device-initializer/virgil-device-initializer"

#
#   Functions
#
check_error() {
   local RES=$?
   local WHAT=${1}
   if [ $RES != 0 ]; then
        echo "============================================"
        echo "FAILED: ${WHAT}"
        echo "============================================"
        exit $RES
   else
        echo "============================================"
        echo "SUCCESS: ${WHAT}"
        echo "============================================"
   fi
}

#
# Run Virgil Device Initializer
#
cmd=$(python3 ${SCRIPT_FOLDER}/helpers/provision/print_initializer_cmd.py --initializer-exe="${DEVICE_INITIALIZER}")
printf "Run Virgil Device Initializer:\n${cmd}\n\n"
eval "${cmd}"
check_error "Perform devices provision"
