EXTRA_DIST += \
	debian/changelog \
	debian/compat \
	debian/control \
	debian/control.modules.in \
	debian/copyright \
	debian/copyright.in \
	debian/dkms.conf.in \
	debian/dirs \
	debian/libopenvswitch.install \
	debian/libopenvswitch-dev.install \
	debian/openvswitch-dpdk-common.dirs \
	debian/openvswitch-dpdk-common.docs \
	debian/openvswitch-dpdk-common.install \
	debian/openvswitch-dpdk-common.manpages \
	debian/openvswitch-datapath-module-_KVERS_.postinst.modules.in \
	debian/openvswitch-datapath-dkms.postinst \
	debian/openvswitch-datapath-dkms.prerm \
	debian/openvswitch-datapath-source.README.Debian \
	debian/openvswitch-datapath-source.copyright \
	debian/openvswitch-datapath-source.dirs \
	debian/openvswitch-datapath-source.install \
	debian/openvswitch-ipsec.dirs \
	debian/openvswitch-ipsec.init \
	debian/openvswitch-ipsec.install \
	debian/openvswitch-pki.dirs \
	debian/openvswitch-pki.postinst \
	debian/openvswitch-pki.postrm \
	debian/openvswitch-dpdk-switch.README.Debian \
	debian/openvswitch-dpdk-switch.dirs \
	debian/openvswitch-dpdk-switch.init \
	debian/openvswitch-dpdk-switch.install \
	debian/openvswitch-dpdk-switch.logrotate \
	debian/openvswitch-dpdk-switch.manpages \
	debian/openvswitch-dpdk-switch.postinst \
	debian/openvswitch-dpdk-switch.postrm \
	debian/openvswitch-dpdk-switch.template \
	debian/openvswitch-dpdk-switch.links \
	debian/openvswitch-dpdk-switch.service \
	debian/openvswitch-test.dirs \
	debian/openvswitch-test.install \
	debian/openvswitch-test.manpages \
	debian/openvswitch-testcontroller.README.Debian \
	debian/openvswitch-testcontroller.default \
	debian/openvswitch-testcontroller.dirs \
	debian/openvswitch-testcontroller.init \
	debian/openvswitch-testcontroller.install \
	debian/openvswitch-testcontroller.manpages \
	debian/openvswitch-testcontroller.postinst \
	debian/openvswitch-testcontroller.postrm \
	debian/openvswitch-vtep.default \
	debian/openvswitch-vtep.dirs \
	debian/openvswitch-vtep.init \
	debian/openvswitch-vtep.install \
	debian/openvswitch-vtep.manpages \
	debian/python3-openvswitch.dirs \
	debian/python3-openvswitch.install \
	debian/rules \
	debian/rules.modules \
	debian/ifupdown.sh \
	debian/source/format

check-debian-changelog-version:
	@DEB_VERSION=`echo '$(VERSION)' | sed 's/pre/~pre/'`;		     \
	if $(FGREP) '($(DEB_VERSION)' $(srcdir)/debian/changelog >/dev/null; \
	then								     \
	  :;								     \
	else								     \
	  echo "Update debian/changelog to mention version $(VERSION)";	     \
	  exit 1;							     \
	fi
ALL_LOCAL += check-debian-changelog-version
DIST_HOOKS += check-debian-changelog-version

$(srcdir)/debian/copyright: AUTHORS.rst debian/copyright.in
	$(AM_V_GEN) \
	{ sed -n -e '/%AUTHORS%/q' -e p < $(srcdir)/debian/copyright.in;   \
	  sed '34,/^$$/d' $(srcdir)/AUTHORS.rst |			   \
		sed -n -e '/^$$/q' -e 's/^/  /p';			   \
	  sed -e '34,/%AUTHORS%/d' $(srcdir)/debian/copyright.in;	   \
	} > $@

CLEANFILES += debian/copyright
