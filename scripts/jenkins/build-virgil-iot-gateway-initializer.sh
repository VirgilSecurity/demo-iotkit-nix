#!/bin/bash


SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

check_error() {
   RETRIES=$?
   if [ $RETRIES != 0 ]; then
        echo "----------------------------------------------------------------------"
        echo "############# !!! PROCESS ERROR ERRORCODE=[$RETRIES] ##################"
        echo "----------------------------------------------------------------------"
     exit $RETRIES
   else
        echo "-------------Process OK. ---------------------------------------------"
   fi
}

# Build User space
cd "${SCRIPT_FOLDER}/../../"
echo "----------------------------------------------------------------------"
echo "################# BUILDING VIRGIL IOT GATEWAY INITIALIZER ############"
echo "----------------------------------------------------------------------"
echo "------------- Preparing for build ------------------------------------"
rm -rf cmake-build-debug
mkdir -p cmake-build-debug
cd ./cmake-build-debug && cmake -DVIRGIL_IOT_MCU_BUILD=OFF $@ "../"
check_error
echo "------------- Build virgil-iot-gateway-initializer.sh -----------------------------------"
make virgil-iot-gateway-initializer -j 8
check_error
echo "----------------------------------------------------------------------"
echo "##### FINISH VIRGIL IOT GATEWAY INITIALIZER BUILDING #################"
echo "----------------------------------------------------------------------"
