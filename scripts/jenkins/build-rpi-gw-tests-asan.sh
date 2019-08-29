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
echo "################# BUILDING RPI GW TESTS (with ASAN) ##################"
echo "----------------------------------------------------------------------"
echo "------------- Preparing for build ------------------------------------"
rm -rf cmake-build-debug
mkdir -p cmake-build-debug
cd ./cmake-build-debug && cmake -DUSE_ASAN=ON -DVIRGIL_IOT_MCU_BUILD=OFF $@ "../"
check_error
echo "------------- Build rpi_gw_tests -------------------------------------"
make rpi_gw_tests -j 4
check_error
echo "----------------------------------------------------------------------"
echo "################# FINISH RPI GW TESTS BUILDING #######################"
echo "----------------------------------------------------------------------"
