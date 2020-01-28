#!/bin/bash

TMP_FILE="/tmp/cert.tmp"

while read cert; do
	echo ${cert} | base64 --decode > "${TMP_FILE}"
	openssl x509 -inform der -in "${TMP_FILE}" -text -noout
	echo "-----------------------"
done <${1}