Name:           stamp-suite
Version:        0.6.0
Release:        1%{?dist}
Summary:        Simple Two-Way Active Measurement Protocol (STAMP)

License:        MIT
URL:            https://github.com/asmie/stamp-suite
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust >= 1.93.0
BuildRequires:  cargo >= 1.93.0
BuildRequires:  systemd-rpm-macros

%{?systemd_requires}

%description
stamp-suite is a Rust implementation of the Simple Two-Way Active
Measurement Protocol (STAMP) as defined in RFC 8762 and RFC 8972.
It provides a client-server application pair for measuring packet
loss and network delays.

%prep
%autosetup

%build
cargo build --release

%install
install -D -m 0755 target/release/%{name} %{buildroot}%{_bindir}/%{name}
install -D -m 0644 dist/systemd/%{name}.service %{buildroot}%{_unitdir}/%{name}.service
install -D -m 0644 mibs/STAMP-SUITE-MIB.mib %{buildroot}%{_datadir}/snmp/mibs/STAMP-SUITE-MIB.mib

%pre
getent group stamp >/dev/null || groupadd -r stamp
getent passwd stamp >/dev/null || \
    useradd -r -g stamp -s /sbin/nologin -d /nonexistent \
    -c "STAMP Suite service account" stamp
exit 0

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%files
%license LICENSE
%doc README.md
%{_bindir}/%{name}
%{_unitdir}/%{name}.service
%{_datadir}/snmp/mibs/STAMP-SUITE-MIB.mib

%changelog
* Tue Feb 17 2026 Piotr Olszewski <asmie@asmie.pl> - 0.5.0-1
- Initial RPM packaging
