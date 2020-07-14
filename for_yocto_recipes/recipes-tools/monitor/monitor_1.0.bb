SUMMARY = "Monitor"
PROVIDES = "monitor"
RPROVIDE = "monitor"

PR = "r0"

LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "file://README;md5=df850c680a7b2a127093b29c705ce0f5"

SRC_URI = "file://monitor-1.0.tar.bz2 "

#SRC_URI[md5sum] = "94ab3a89621902bec619136696e4380e"
#SRC_URI[sha256sum] = "1c52a9532fdc0ec07973caa937ab0e19336b69867adc29e93d5d08be64b3b5c3"

#S = "${WORKDIR}/monitor-${PV}"

#inherit module

do_install () {
	install -D -m 750 ${B}/monitor ${D}${sbindir}/monitor
	install -D -m 750 ${B}/test ${D}/root/test
}

