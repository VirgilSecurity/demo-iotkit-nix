#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR="/tmp/build"
INSTALL_DIR="${SCRIPT_FOLDER}/../ext/deps"

function create_clean_dir() {
  if [ -d "${1}" ]; then
    rm -rf "${1}"
  fi
  mkdir "${1}"
}

create_clean_dir "${BUILD_DIR}"
create_clean_dir "${INSTALL_DIR}"

#
#   Install Virgil Crypto C
#
pushd "${BUILD_DIR}"
  git clone https://github.com/VirgilSecurity/virgil-crypto-c
  cd virgil-crypto-c
  git checkout 1d52c33953f1d692f1f28757f14947f3a003577e
  cmake -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}" -DENABLE_TESTING=OFF -DVIRGIL_C_TESTING=OFF -DVIRGIL_LIB_PYTHIA=OFF -DVIRGIL_LIB_RATCHET=OFF -DVIRGIL_LIB_PHE=OFF -Bbuild -H.
  cmake --build build
  cmake --build build --target install
popd

if [ -d "${INSTALL_DIR}/lib64" ]; then
    mv -f "${INSTALL_DIR}/lib64" "${INSTALL_DIR}/lib"
fi
