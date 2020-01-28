#!/bin/bash

#
#   Global variables
#
SCRIPT_FOLDER="$( cd "$( dirname "$0" )" && pwd )"
IOT_API_URL="https://api-iot.virgilsecurity.com"
VIRGIL_APP_TOKEN="AT.Ge7saviGgmroNwnzczpjpIGaCVKFKDrX"

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
#   Install Virgil Trust Provisioner and requirements for helper scripts
#
pushd ${SCRIPT_FOLDER}/../virgil-iot-sdk/tools/virgil-trust-provisioner
    pip3 install .
    check_error "Install Trust Provisioner"
popd

pushd ${SCRIPT_FOLDER}/helpers/provision
    pip3 install -r requirements.txt
    check_error "Install requirements for helper scripts"
popd

#
#   Generate provision
#
python3 ${SCRIPT_FOLDER}/helpers/provision/generate.py \
    --virgil-app-token=${VIRGIL_APP_TOKEN} \
    --iot-api-url=${IOT_API_URL}
check_error "Generating provision package"
