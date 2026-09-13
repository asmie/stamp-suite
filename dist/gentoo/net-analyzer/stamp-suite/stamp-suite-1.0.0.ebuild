# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

# CRATES and the dependent-crate LICENSE line below are generated from
# Cargo.lock by pycargoebuild. After any lockfile change refresh them with:
#   pycargoebuild -i stamp-suite-<ver>.ebuild <path to checkout>

EAPI=8

CRATES="
	aho-corasick@1.1.5
	android_system_properties@0.1.6
	anes@0.1.6
	anstream@1.0.0
	anstyle-parse@1.0.0
	anstyle-query@1.1.5
	anstyle-wincon@3.0.11
	anstyle@1.0.14
	arc-swap@1.9.2
	atomic-waker@1.1.2
	autocfg@1.5.1
	aws-lc-rs@1.18.0
	aws-lc-sys@0.44.0
	axum-core@0.5.6
	axum-server@0.8.0
	axum@0.8.9
	base64@0.22.1
	bitflags@2.13.1
	block-buffer@0.12.1
	bumpalo@3.20.3
	bytes@1.12.1
	cast@0.3.0
	cc@1.4.4
	cfg-if@1.0.4
	cfg_aliases@0.2.2
	chrono@0.4.45
	ciborium-io@0.2.2
	ciborium-ll@0.2.2
	ciborium@0.2.2
	clap@4.6.6
	clap_builder@4.6.6
	clap_derive@4.6.4
	clap_lex@1.1.0
	clap_mangen@0.3.3
	cmake@0.1.58
	cmov@0.5.4
	colorchoice@1.0.5
	const-oid@0.10.2
	core-foundation-sys@0.8.7
	core-foundation@0.10.1
	cpufeatures@0.3.1
	criterion-plot@0.5.0
	criterion@0.5.1
	crossbeam-epoch@0.9.20
	crossbeam-utils@0.8.22
	crunchy@0.2.4
	crypto-common@0.2.2
	ctutils@0.4.2
	digest@0.11.3
	dunce@1.0.5
	either@1.18.0
	equivalent@1.0.2
	errno@0.3.14
	evmap@11.0.0
	fastrand@2.5.0
	find-msvc-tools@0.1.11
	fnv@1.0.7
	foldhash@0.2.0
	form_urlencoded@1.2.2
	fs-err@3.3.1
	fs_extra@1.3.0
	futures-channel@0.3.34
	futures-core@0.3.34
	futures-macro@0.3.34
	futures-sink@0.3.34
	futures-task@0.3.34
	futures-util@0.3.34
	generator@0.8.9
	getrandom@0.2.17
	getrandom@0.3.4
	getrandom@0.4.3
	glob@0.3.4
	h2@0.4.19
	half@2.7.1
	hashbag@0.1.13
	hashbrown@0.16.1
	hashbrown@0.17.1
	heck@0.5.0
	hermit-abi@0.5.3
	hex@0.4.3
	hmac@0.13.0
	http-body-util@0.1.5
	http-body@1.1.0
	http@1.5.0
	httparse@1.10.1
	httpdate@1.0.3
	hybrid-array@0.4.14
	hyper-rustls@0.27.9
	hyper-util@0.1.20
	hyper@1.11.1
	iana-time-zone-haiku@0.1.2
	iana-time-zone@0.1.65
	indexmap@2.14.1
	ipnet@2.12.1
	ipnetwork@0.20.0
	is-terminal@0.4.17
	is_terminal_polyfill@1.70.2
	itertools@0.10.5
	itoa@1.0.18
	jobserver@0.1.35
	js-sys@0.3.104
	lazy_static@1.5.0
	left-right@0.11.8
	libc@0.2.189
	linux-raw-sys@0.12.1
	log@0.4.34
	loom@0.7.2
	matchers@0.2.0
	matchit@0.8.4
	memchr@2.8.3
	memoffset@0.9.1
	metrics-exporter-prometheus@0.18.3
	metrics-util@0.20.4
	metrics@0.24.6
	mime@0.3.17
	mio@1.2.2
	nix@0.31.3
	no-std-net@0.6.0
	nu-ansi-term@0.50.3
	num-traits@0.2.19
	once_cell@1.21.4
	once_cell_polyfill@1.70.2
	oorandom@11.1.5
	openssl-probe@0.2.1
	percent-encoding@2.3.2
	pin-project-lite@0.2.17
	pkg-config@0.3.34
	pnet@0.35.0
	pnet_base@0.35.0
	pnet_datalink@0.35.0
	pnet_macros@0.35.0
	pnet_macros_support@0.35.0
	pnet_packet@0.35.0
	pnet_sys@0.35.0
	pnet_transport@0.35.0
	portable-atomic@1.15.0
	ppv-lite86@0.2.21
	proc-macro2@1.0.107
	proptest@1.11.0
	quanta@0.12.6
	quote@1.0.47
	r-efi@5.3.0
	r-efi@6.0.0
	rand@0.9.5
	rand_chacha@0.9.0
	rand_core@0.9.5
	rand_xorshift@0.4.0
	rand_xoshiro@0.7.0
	rapidhash@4.5.1
	raw-cpuid@11.6.0
	regex-automata@0.4.18
	regex-syntax@0.8.11
	regex@1.13.1
	ring@0.17.14
	roff@1.1.1
	rustix@1.1.4
	rustls-native-certs@0.8.4
	rustls-pki-types@1.15.1
	rustls-webpki@0.103.15
	rustls@0.23.43
	rustversion@1.0.23
	ryu@1.0.23
	same-file@1.0.6
	schannel@0.1.29
	scoped-tls@1.0.1
	security-framework-sys@2.17.0
	security-framework@3.7.0
	serde@1.0.229
	serde_core@1.0.229
	serde_derive@1.0.229
	serde_json@1.0.151
	serde_path_to_error@0.1.20
	serde_spanned@1.1.1
	serde_urlencoded@0.7.1
	sha2@0.11.0
	sharded-slab@0.1.7
	shlex@2.0.1
	signal-hook-registry@1.4.8
	sketches-ddsketch@0.3.1
	slab@0.4.12
	smallvec@1.15.2
	socket2@0.6.5
	strsim@0.11.1
	subtle@2.6.1
	syn@2.0.119
	syn@3.0.4
	sync_wrapper@1.0.2
	tempfile@3.27.0
	thiserror-impl@2.0.20
	thiserror@2.0.20
	thread_local@1.1.10
	tinytemplate@1.2.1
	tokio-macros@2.7.2
	tokio-rustls@0.26.4
	tokio-util@0.7.19
	tokio@1.53.1
	toml@1.1.4+spec-1.1.0
	toml_datetime@1.1.1+spec-1.1.0
	toml_parser@1.1.3+spec-1.1.0
	tower-layer@0.3.3
	tower-service@0.3.3
	tower@0.5.3
	tracing-attributes@0.1.31
	tracing-core@0.1.36
	tracing-log@0.2.0
	tracing-serde@0.2.0
	tracing-subscriber@0.3.23
	tracing@0.1.44
	try-lock@0.2.5
	typenum@1.20.1
	unarray@0.1.4
	unicode-ident@1.0.24
	untrusted@0.9.0
	utf8parse@0.2.2
	valuable@0.1.1
	walkdir@2.5.0
	want@0.3.1
	wasi@0.11.1+wasi-snapshot-preview1
	wasip2@1.0.4+wasi-0.2.12
	wasm-bindgen-macro-support@0.2.127
	wasm-bindgen-macro@0.2.127
	wasm-bindgen-shared@0.2.127
	wasm-bindgen@0.2.127
	web-sys@0.3.104
	winapi-i686-pc-windows-gnu@0.4.0
	winapi-util@0.1.11
	winapi-x86_64-pc-windows-gnu@0.4.0
	winapi@0.3.9
	windows-core@0.62.2
	windows-implement@0.60.2
	windows-interface@0.59.3
	windows-link@0.2.1
	windows-result@0.4.1
	windows-strings@0.5.1
	windows-sys@0.52.0
	windows-sys@0.61.2
	windows-targets@0.52.6
	windows_aarch64_gnullvm@0.52.6
	windows_aarch64_msvc@0.52.6
	windows_i686_gnu@0.52.6
	windows_i686_gnullvm@0.52.6
	windows_i686_msvc@0.52.6
	windows_x86_64_gnu@0.52.6
	windows_x86_64_gnullvm@0.52.6
	windows_x86_64_msvc@0.52.6
	winnow@1.0.4
	wit-bindgen@0.57.1
	zerocopy-derive@0.8.56
	zerocopy@0.8.56
	zeroize@1.9.0
	zmij@1.0.23
"

# Cargo.toml `rust-version`; the floor is Debian trixie's compiler so every
# distribution build uses the same MSRV. ring/rustls (USE=control) need only
# a C toolchain, no system libraries.
RUST_MIN_VER="1.85.0"

inherit cargo systemd

DESCRIPTION="Simple Two-Way Active Measurement Protocol (RFC 8762/8972) sender and reflector"
HOMEPAGE="https://github.com/asmie/stamp-suite"
SRC_URI="
	https://github.com/asmie/${PN}/archive/v${PV}.tar.gz -> ${P}.gh.tar.gz
	${CARGO_CRATE_URIS}
"

LICENSE="MIT"
# Dependent crate licenses
LICENSE+=" Apache-2.0 BSD ISC MIT Unicode-3.0 ZLIB"
SLOT="0"
KEYWORDS="~amd64 ~arm64"
IUSE="control +hwtstamp metrics snmp test"
# The suite drives real UDP sockets over loopback only, which the network
# sandbox permits. Tiers needing root/netns/raw capture gate themselves.
RESTRICT="!test? ( test )"

RDEPEND="
	acct-group/stamp
	acct-user/stamp
"

# Rust binaries: no LDFLAGS/CFLAGS to check.
QA_FLAGS_IGNORED="usr/bin/${PN}"

src_configure() {
	# Feature names match Cargo.toml [features]; ttl-nix is the Linux socket
	# backend (the one Debian/RPM packages ship). The crate has no default
	# features, so the flag below merely makes the selection explicit.
	local myfeatures=(
		ttl-nix
		$(usev control)
		$(usev hwtstamp)
		$(usev metrics)
		$(usev snmp)
	)
	cargo_src_configure --no-default-features
}

src_install() {
	cargo_src_install

	doman dist/man/${PN}.1

	systemd_dounit dist/systemd/${PN}.service
	newinitd "${FILESDIR}"/${PN}.initd ${PN}
	newconfd "${FILESDIR}"/${PN}.confd ${PN}

	dodoc README.md CHANGELOG.md SECURITY.md \
		doc/usage.md doc/architecture.md doc/security.md

	if use snmp; then
		insinto /usr/share/snmp/mibs
		doins mibs/STAMP-SUITE-MIB.mib
	fi
}

pkg_postinst() {
	elog "The reflector service runs as the unprivileged 'stamp' user and is"
	elog "granted CAP_NET_BIND_SERVICE for UDP/862 by the systemd unit and the"
	elog "OpenRC script. Extra reflector flags go in /etc/conf.d/${PN}"
	elog "(OpenRC) or a systemd drop-in; see the docs in /usr/share/doc/${PF}/."
}
