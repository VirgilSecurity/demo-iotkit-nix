#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$SCRIPT_FOLDER/../.."
BUILD_OUTPUT="$PROJECT_ROOT/build-test"

#Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'


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

cleanup() {
   cd "$PROJECT_ROOT"
   rm -rf cmake-build-debug && mkdir -p cmake-build-debug
   cd ./cmake-build-debug
}

rm -rf BUILD_OUTPUT
mkdir -p $BUILD_OUTPUT
echo "Files will be stored at $BUILD_OUTPUT"


echo "----------------------------------------------------------------------"
echo "################# BUILDING VIRGIL IOT GATEWAY ########################"
echo "----------------------------------------------------------------------"

echo "------------- Build virgil-iot-gateway-initializer -------------------"
cleanup
cmake -DVIRGIL_IOT_MCU_BUILD=OFF $@ "../"
check_error
make virgil-iot-gateway-initializer -j 8
check_error
mv initializer/virgil-iot-gateway-initializer $BUILD_OUTPUT/
check_error

echo "------------- Build virgil-iot-gateway-app (initial) -----------------"
cleanup
cmake -DVIRGIL_IOT_MCU_BUILD=OFF \
      -DGATEWAY_SIMULATOR=ON \
      -DTEST_UPDATE_MESSAGE="${RED}[ Hello from initial Gateway firmware ]${NC}" $@ "../"
check_error
make virgil-iot-gateway-app -j 8
check_error
mv app/virgil-iot-gateway-app $BUILD_OUTPUT/virgil-iot-gateway-app-initial
check_error

echo "------------- Build virgil-iot-gateway-app (update) -----------------"
cleanup
cmake -DVIRGIL_IOT_MCU_BUILD=OFF \
      -DGATEWAY_SIMULATOR=ON \
      -DTEST_UPDATE_MESSAGE="${GREEN}[ Hello from updated Gateway firmware ]${NC}" $@ "../"
check_error
make virgil-iot-gateway-app -j 8
check_error
mv app/virgil-iot-gateway-app $BUILD_OUTPUT/virgil-iot-gateway-app-update
check_error

echo "----------------------------------------------------------------------"
echo "################### FINISH VIRGIL IOT GATEWAY  #######################"
echo "Files are stored to: $BUILD_OUTPUT"
ls -l $BUILD_OUTPUT
echo "----------------------------------------------------------------------"
