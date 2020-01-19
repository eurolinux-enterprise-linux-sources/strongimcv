%global hardened_build 1
%global name2 strongswan

Name:           strongimcv
Version:        5.1.0
Release:        2%{?dist}
Summary:        Trusted Network Connect's (TNC) IMCs and IMVs
Group:          Applications/System
License:        GPLv2+
URL:            http://www.strongswan.org/
Source0:        http://download.strongswan.org/strongswan-%{version}.tar.bz2
Patch1:         strongswan-pts-dh.patch
Patch2:         libstrongswan-plugin.patch
Patch3:         libstrongswan-settings-debug.patch
Patch4:         imcv-initialization-crash-git-5ec08.patch

BuildRequires:  openssl-devel
BuildRequires:  sqlite-devel
BuildRequires:  gettext-devel
BuildRequires:  trousers-devel
BuildRequires:  libxml2-devel

%description
This package provides Trusted Network Connect's (TNC) IMC and IMV functionality.
Specifically it includes PTS based IMC/IMV for TPM based remote attestation and 
scanner and test IMCs and IMVs. The Strongswan's IMC/IMV dynamic libraries can be
used by any third party TNC Client/Server implementation possessing a standard 
IF-IMC/IMV interface.


%prep
%setup -q -n %{name2}-%{version}
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1

%build
%configure --disable-static \
    --with-ipsec-script=%{name} \
    --sysconfdir=%{_sysconfdir}/%{name} \
    --with-ipsecdir=%{_libexecdir}/%{name} \
    --with-ipseclibdir=%{_libdir}/%{name} \
    --with-fips-mode=2 \
    --with-tss=trousers \
    --with-systemdsystemunitdir="" \
    --enable-openssl \
    --disable-charon \
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
    --disable-stroke \
    --disable-xauth-generic \
    --disable-updown \
    --disable-resolve \
    --disable-kernel-netlink \
    --disable-socket-default \
    --enable-sqlite \
    --enable-imc-test \
    --enable-imv-test \
    --enable-imc-scanner \
    --enable-imv-scanner  \
    --enable-imc-attestation \
    --enable-imv-attestation \
    --enable-imv-os \
    --enable-imc-os 


make %{?_smp_mflags}
sed -i 's/\t/    /' src/strongswan.conf

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
chmod 644 %{buildroot}%{_sysconfdir}/%{name}/%{name2}.conf
# protect configuration from ordinary user's eyes
chmod 700 %{buildroot}%{_sysconfdir}/%{name}

%files
%doc README COPYING NEWS TODO
%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/%{name2}.conf
%dir %{_libdir}/%{name}
%{_libdir}/%{name}/lib%{name2}.so.0
%{_libdir}/%{name}/lib%{name2}.so.0.0.0
%dir %{_libdir}/%{name}/plugins
%{_libdir}/%{name}/plugins/lib%{name2}-cmac.so
%{_libdir}/%{name}/plugins/lib%{name2}-constraints.so
%{_libdir}/%{name}/plugins/lib%{name2}-hmac.so
%{_libdir}/%{name}/plugins/lib%{name2}-xcbc.so
%{_libdir}/%{name}/plugins/lib%{name2}-nonce.so
%{_libdir}/%{name}/plugins/lib%{name2}-openssl.so
%{_libdir}/%{name}/plugins/lib%{name2}-pem.so
%{_libdir}/%{name}/plugins/lib%{name2}-pgp.so
%{_libdir}/%{name}/plugins/lib%{name2}-random.so
%{_libdir}/%{name}/plugins/lib%{name2}-revocation.so
%{_libdir}/%{name}/plugins/lib%{name2}-x509.so
%dir %{_libexecdir}/%{name}
%{_libexecdir}/%{name}/_copyright
%{_libexecdir}/%{name}/openac
%{_libexecdir}/%{name}/pki
%{_libexecdir}/%{name}/scepclient
%{_sbindir}/%{name}
%{_mandir}/man5/%{name}_%{name2}.conf.5.gz
%{_mandir}/man8/%{name}.8.gz
%{_mandir}/man8/%{name}_openac.8.gz
%{_mandir}/man8/%{name}_scepclient.8.gz
%{_libdir}/%{name}/libimcv.so.0
%{_libdir}/%{name}/libimcv.so.0.0.0
%{_libdir}/%{name}/libpts.so.0
%{_libdir}/%{name}/libpts.so.0.0.0
%dir %{_libdir}/%{name}/imcvs
%{_libdir}/%{name}/imcvs/imc-attestation.so
%{_libdir}/%{name}/imcvs/imc-scanner.so
%{_libdir}/%{name}/imcvs/imc-test.so
%{_libdir}/%{name}/imcvs/imc-os.so
%{_libdir}/%{name}/imcvs/imv-attestation.so
%{_libdir}/%{name}/imcvs/imv-scanner.so
%{_libdir}/%{name}/imcvs/imv-test.so
%{_libdir}/%{name}/imcvs/imv-os.so
%{_libdir}/%{name}/plugins/lib%{name2}-sqlite.so
%{_libexecdir}/%{name}/_imv_policy
%{_libexecdir}/%{name}/imv_policy_manager
%{_libexecdir}/%{name}/attest
%{_libexecdir}/%{name}/pacman

%changelog
* Thu Sep 12 2013 Avesh Agarwal <avagarwa@redhat.com> - 5.1.0-2
- Fixed initialization crash of IMV and IMC particularly
  attestation imv/imc as libstrongswas was not getting initialized.

* Thu Sep 5 2013 Avesh Agarwal <avagarwa@redhat.com> - 5.1.0-1
- Initial packaging of strongimcv for RHEL 
