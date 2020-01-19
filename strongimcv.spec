%global _hardened_build 1
%global name2 strongswan

Name:           strongimcv
Version:        5.2.0
Release:        3%{?dist}
Summary:        Trusted Network Connect (TNC) Architecture
Group:          Applications/System
License:        GPLv2+
URL:            http://www.strongswan.org/
Source0:        http://download.strongswan.org/strongswan-%{version}.tar.bz2
Patch0:         strongswan-init.patch
Patch1:         libstrongswan-plugin.patch
Patch2:         libstrongswan-973315.patch
Patch3:         strongimcv-systemd-service.patch
Patch4:         imcv_ipsec_script.patch
Patch5:         strongimcv-openssl-threading.patch
Patch6:         strongimcv-1179330.patch

BuildRequires:  autoconf automake
BuildRequires:  libcurl-devel
BuildRequires:  openssl-devel
BuildRequires:  sqlite-devel
BuildRequires:  gettext-devel
BuildRequires:  trousers-devel
BuildRequires:  libxml2-devel
BuildRequires:  json-c-devel

%if 0%{?fedora} >= 15 || 0%{?rhel} >= 7
BuildRequires:  systemd
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
%else
Requires(post): chkconfig
Requires(preun): chkconfig
Requires(preun): initscripts
%endif

%description
This package provides Trusted Network Connect's (TNC) architecture support.
It includes support for TNC client and server (IF-TNCCS), IMC and IMV message
exchange (IF-M), interface between IMC/IMV and TNC client/server (IF-IMC
and IF-IMV). It also includes PTS based IMC/IMV for TPM based remote
attestation, SWID IMC/IMV, and OS IMC/IMV. It's IMC/IMV dynamic libraries
modules can be used by any third party TNC Client/Server implementation
possessing a standard IF-IMC/IMV interface. In addition, it implements
PT-TLS to support TNC over TLS.

This package has disabled it's IKE features as those are not supported.

%prep
%setup -q -n %{name2}-%{version}
%patch0 -p1
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1
%patch5 -p1
%patch6 -p1

%build
# for initscript patch to work
autoreconf
%configure --disable-static \
    --with-ipsec-script=%{name} \
    --sysconfdir=%{_sysconfdir}/%{name} \
    --with-ipsecdir=%{_libexecdir}/%{name} \
    --bindir=%{_libexecdir}/%{name} \
    --with-ipseclibdir=%{_libdir}/%{name} \
    --with-fips-mode=2 \
    --with-tss=trousers \
    --enable-openssl \
    --disable-aes \
    --disable-des \
    --disable-md5 \
    --disable-rc2 \
    --disable-sha1 \
    --disable-sha2 \
    --disable-fips-prf \
    --disable-gmp \
    --disable-pubkey \
    --disable-pkcs1 \
    --disable-pkcs7 \
    --disable-pkcs8 \
    --disable-pkcs12 \
    --disable-dnskey \
    --disable-sshkey \
    --disable-xauth-generic \
    --disable-updown \
    --disable-resolve \
    --disable-ikev1 \
    --disable-ikev2 \
    --enable-sqlite \
    --enable-tnc-ifmap \
    --enable-tnc-pdp \
    --enable-imc-test \
    --enable-imv-test \
    --enable-imc-scanner \
    --enable-imv-scanner  \
    --enable-imc-attestation \
    --enable-imv-attestation \
    --enable-imv-os \
    --enable-imc-os \
    --enable-imc-swid \
    --enable-imv-swid \
    --enable-tnccs-20 \
    --enable-tnccs-11 \
    --enable-tnccs-dynamic \
    --enable-tnc-imc \
    --enable-tnc-imv \
    --enable-curl \
    --enable-acert \
    --enable-aikgen

make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}
#deleting ipsec/ike related man pages
find %{buildroot}%{_mandir} -type f -name 'ipsec*' -delete
# prefix man pages
for i in %{buildroot}%{_mandir}/*/*; do
    if echo "$i" | grep -vq '/%{name}[^\/]*$'; then
        mv "$i" "`echo "$i" | sed -re 's|/([^/]+)$|/%{name}_\1|'`"
    fi
done
# delete unwanted library files
rm %{buildroot}%{_libdir}/%{name}/*.so
find %{buildroot} -type f -name '*.la' -delete
# fix config permissions
#chmod 644 %{buildroot}%{_sysconfdir}/%{name}/%{name2}.conf
# protect configuration from ordinary user's eyes
#chmod 700 %{buildroot}%{_sysconfdir}/%{name}
# setup systemd unit or initscript
%if 0%{?fedora} >= 15 || 0%{?rhel} >= 7
mv  %{buildroot}%{_unitdir}/%{name2}.service %{buildroot}%{_unitdir}/%{name}.service
%else
install -D -m 755 init/sysvinit/%{name} %{buildroot}/%{_initddir}/%{name}
%endif
##rename /usr/bin/pki to avoid conflict with pki-core/pki-tools
#mv %{buildroot}%{_bindir}/pki %{buildroot}%{_bindir}/%{name}-pki
#move /usr/bin/pki to avoid conflict with pki-core/pki-tools
#mv %{buildroot}%{_bindir}/pki %{buildroot}%{_libexecdir}/%{name}/pki
#rename swid tag directory
mv %{buildroot}%{_datadir}/regid.2004-03.org.%{name2} %{buildroot}%{_datadir}/regid.2004-03.org.%{name}
#move templates files
mv %{buildroot}%{_datadir}/%{name2} %{buildroot}%{_datadir}/%{name}

# Create ipsec.d directory tree.
install -d -m 700 %{buildroot}%{_sysconfdir}/%{name}/ipsec.d
for i in aacerts acerts certs cacerts crls ocspcerts private reqs; do
    install -d -m 700 %{buildroot}%{_sysconfdir}/%{name}/ipsec.d/${i}
done


%post
/sbin/ldconfig
%if 0%{?fedora} >= 15 || 0%{?rhel} >= 7
%systemd_post %{name}.service
%else
/sbin/chkconfig --add %{name}
%endif

%preun
%if 0%{?fedora} >= 15 || 0%{?rhel} >= 7
%systemd_preun %{name}.service
%else
if [ $1 -eq 0 ] ; then
    # Package removal, not upgrade
    /sbin/service %{name} stop >/dev/null 2>&1
    /sbin/chkconfig --del %{name}
fi
%endif

%postun
/sbin/ldconfig
%if 0%{?fedora} >= 15 || 0%{?rhel} >= 7
%systemd_postun_with_restart %{name}.service
%else
%endif

%files
%doc README COPYING NEWS TODO
%attr(755,root,root) %dir %{_sysconfdir}/%{name}
%{_sysconfdir}/%{name}/ipsec.d/
%config(noreplace) %attr(644,root,root) %{_sysconfdir}/%{name}/ipsec.conf
%config(noreplace) %attr(644,root,root) %{_sysconfdir}/%{name}/%{name2}.conf
%{_sysconfdir}/%{name}/%{name2}.d/
%if 0%{?fedora} >= 15 || 0%{?rhel} >= 7
%{_unitdir}/%{name}.service
%else
%{_initddir}/%{name}
%endif
%dir %{_libdir}/%{name}
%{_libdir}/%{name}/libcharon.so.0
%{_libdir}/%{name}/libcharon.so.0.0.0
%{_libdir}/%{name}/libhydra.so.0
%{_libdir}/%{name}/libhydra.so.0.0.0
%{_libdir}/%{name}/libtls.so.0
%{_libdir}/%{name}/libtls.so.0.0.0
%{_libdir}/%{name}/libpttls.so.0
%{_libdir}/%{name}/libpttls.so.0.0.0
%{_libdir}/%{name}/lib%{name2}.so.0
%{_libdir}/%{name}/lib%{name2}.so.0.0.0
%dir %{_libdir}/%{name}/plugins
%{_libdir}/%{name}/plugins/lib%{name2}-attr.so
%{_libdir}/%{name}/plugins/lib%{name2}-cmac.so
%{_libdir}/%{name}/plugins/lib%{name2}-constraints.so
%{_libdir}/%{name}/plugins/lib%{name2}-hmac.so
%{_libdir}/%{name}/plugins/lib%{name2}-kernel-netlink.so
%{_libdir}/%{name}/plugins/lib%{name2}-xcbc.so
%{_libdir}/%{name}/plugins/lib%{name2}-nonce.so
%{_libdir}/%{name}/plugins/lib%{name2}-openssl.so
%{_libdir}/%{name}/plugins/lib%{name2}-pem.so
%{_libdir}/%{name}/plugins/lib%{name2}-pgp.so
%{_libdir}/%{name}/plugins/lib%{name2}-random.so
%{_libdir}/%{name}/plugins/lib%{name2}-revocation.so
%{_libdir}/%{name}/plugins/lib%{name2}-socket-default.so
%{_libdir}/%{name}/plugins/lib%{name2}-stroke.so
%{_libdir}/%{name}/plugins/lib%{name2}-x509.so
%{_libdir}/%{name}/plugins/lib%{name2}-curl.so
%{_libdir}/%{name}/plugins/lib%{name2}-acert.so
%attr(755,root,root) %dir %{_libexecdir}/%{name}
%attr(755,root,root) %{_libexecdir}/%{name}/_copyright
%attr(755,root,root) %{_libexecdir}/%{name}/charon
%attr(755,root,root) %{_libexecdir}/%{name}/scepclient
%attr(755,root,root) %{_libexecdir}/%{name}/starter
%attr(755,root,root) %{_libexecdir}/%{name}/stroke
%attr(755,root,root) %{_libexecdir}/%{name}/pki
%attr(755,root,root) %{_libexecdir}/%{name}/aikgen
%attr(755,root,root) %{_sbindir}/%{name}
%{_mandir}/man1/%{name}_pki*.1.gz
%{_mandir}/man5/%{name}_%{name2}.conf.5.gz
%{_mandir}/man8/%{name}.8.gz
%{_mandir}/man8/%{name}_scepclient.8.gz
%{_libdir}/%{name}/libimcv.so.0
%{_libdir}/%{name}/libimcv.so.0.0.0
%{_libdir}/%{name}/libpts.so.0
%{_libdir}/%{name}/libpts.so.0.0.0
%{_libdir}/%{name}/libtnccs.so.0
%{_libdir}/%{name}/libtnccs.so.0.0.0
%{_libdir}/%{name}/libradius.so.0
%{_libdir}/%{name}/libradius.so.0.0.0
%dir %{_libdir}/%{name}/imcvs
%{_libdir}/%{name}/imcvs/imc-attestation.so
%{_libdir}/%{name}/imcvs/imc-scanner.so
%{_libdir}/%{name}/imcvs/imc-test.so
%{_libdir}/%{name}/imcvs/imc-os.so
%{_libdir}/%{name}/imcvs/imc-swid.so
%{_libdir}/%{name}/imcvs/imv-attestation.so
%{_libdir}/%{name}/imcvs/imv-scanner.so
%{_libdir}/%{name}/imcvs/imv-test.so
%{_libdir}/%{name}/imcvs/imv-os.so
%{_libdir}/%{name}/imcvs/imv-swid.so
%{_libdir}/%{name}/plugins/lib%{name2}-sqlite.so
%{_libdir}/%{name}/plugins/lib%{name2}-tnc-imc.so
%{_libdir}/%{name}/plugins/lib%{name2}-tnc-imv.so
%{_libdir}/%{name}/plugins/lib%{name2}-tnc-tnccs.so
%{_libdir}/%{name}/plugins/lib%{name2}-tnccs-20.so
%{_libdir}/%{name}/plugins/lib%{name2}-tnccs-11.so
%{_libdir}/%{name}/plugins/lib%{name2}-tnccs-dynamic.so
%{_libdir}/%{name}/plugins/lib%{name2}-tnc-ifmap.so
%{_libdir}/%{name}/plugins/lib%{name2}-tnc-pdp.so
%attr(755,root,root) %{_libexecdir}/%{name}/_imv_policy
%attr(755,root,root) %{_libexecdir}/%{name}/imv_policy_manager
%attr(755,root,root) %{_libexecdir}/%{name}/attest
%attr(755,root,root) %{_libexecdir}/%{name}/pacman
%attr(755,root,root) %{_libexecdir}/%{name}/pt-tls-client
#swid files
%{_libexecdir}/%{name}/*.swidtag
%dir %{_datadir}/regid.2004-03.org.%{name}
%{_datadir}/regid.2004-03.org.%{name}/*.swidtag
#template conf files
%dir %{_datadir}/%{name}/
%{_datadir}/%{name}/

%changelog
* Thu Jan 8 2015 Avesh Agarwal <avagarwa@redhat.com> - 5.2.0-3
Resolves: #1179330

* Wed Sep 24 2014 Avesh Agarwal <avagarwa@redhat.com> - 5.2.0-2
Resolves: #1144511
Resolves: #1144524

* Tue Aug 26 2014 Avesh Agarwal <avagarwa@redhat.com> - 5.2.0-1
Resolves: #1120371
- Rebase to new upstream release 5.2.0
- IMA/TPM based remote attestation
- Aikgen tool to generate an Attestation Identity Key bound
  to a TPM
- PT-EAP transport protocol (RFC 7171) for TNC
- Enabled support for acert for checking X509 attribute certificate
- Updates local patches
- Spec file update
- openac tool replaced with pki --acert

* Thu Feb 20 2014 Avesh Agarwal <avagarwa@redhat.com> - 5.1.1-4
Resolves:#1067119
- Fixed full hardening for strongswan (full relro and PIE).
  The previous macros had a typo and did not work
  (see bz#1067119).
- Fixed files permissions for executables and config files to
  correctly reflect their intent.
- Fixed tnc package description to eliminate rpmlint errors.
- Fixed pki binary and moved it to /usr/libexece/strongswan as
  others binaries are there too to eliminate rpmlint errors.
- Fixed systemd service name to "strongimv TNC".
- Removed the dependency on gmp-devel

* Fri Jan 24 2014 Daniel Mach <dmach@redhat.com> - 5.1.1-3
- Mass rebuild 2014-01-24

* Wed Jan 15 2014 Avesh Agarwal <avagarwa@redhat.com> - 5.1.1-2
Resolves: #1049523
Resolves: #1036846
Resolves: #1007548
- A typo caused a patch not being applied, so fixed that and
  bumping the number number.

* Wed Jan 15 2014 Avesh Agarwal <avagarwa@redhat.com> - 5.1.1-1
Resolves: #1049523
Resolves: #1036846
Resolves: #1007548
- Modified spec file significantly to reflect the current state of
  the package, as this rebase enables several major modules: TNC
  client and server (IF-TNCCS), IMC-IMV (IF-M), PT-TLS (RFC 6876),
  SWID IMC/IMV, charon daemon and it related libs and modules,
  tnc-pdp, tnc-ifmap plugins.

* Fri Dec 27 2013 Daniel Mach <dmach@redhat.com> - 5.1.0-3
- Mass rebuild 2013-12-27

* Thu Sep 12 2013 Avesh Agarwal <avagarwa@redhat.com> - 5.1.0-2
- Fixed initialization crash of IMV and IMC particularly
  attestation imv/imc as libstrongswas was not getting initialized.

* Thu Sep 5 2013 Avesh Agarwal <avagarwa@redhat.com> - 5.1.0-1
- Initial packaging of strongimcv for RHEL 
