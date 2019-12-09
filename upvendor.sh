#!/bin/bash
set -e

# Enumerate the vendors in this file
VENDORS=('stanford')

function main() {
	VENDOR_ROOT="${PWD}/vendor"

	# Delete the whole vendor folder and make a clean one
	rm -rf ${VENDOR_ROOT} && mkdir -p "${VENDOR_ROOT}"

	# Upvendor each of the listed vendors
	for VENDOR in ${VENDORS[@]}; do
		upvendor $VENDOR
	done

	return 0
}

function upvendor() {
	VENDOR_FOLDER="${VENDOR_ROOT}/$1"
	mkdir -p "${VENDOR_FOLDER}"

	echo "INFO: Upvendoring: $1"
	cd ${VENDOR_FOLDER}
	$1
}

function stanford() {
	wget -nv "http://www.scs.stanford.edu/brop/nginx-1.4.0-exp.tgz"
	gunzip nginx-1.4.0-exp.tgz
	tar xvf nginx-1.4.0-exp.tar
	rm nginx-1.4.0-exp.tar
}

main "$@"
exit $?
