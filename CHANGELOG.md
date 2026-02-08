# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-02-08

### Added

- **RFC 8972 TLV Extension Support**: Full implementation of Type-Length-Value extensions
  - New `tlv` module with `TlvFlags`, `TlvType`, `RawTlv`, `TlvList`, `ExtraPaddingTlv`, `HmacTlv`, and `SessionSenderId` types
  - TLV handling modes: `ignore` (strip TLVs) and `echo` (reflect TLVs with appropriate flags)
  - `--tlv-mode` CLI option to control TLV handling behavior (default: `echo`)
  - `--verify-tlv-hmac` CLI option to verify incoming TLV HMAC
  - `--ssid` CLI option for sender to include Session-Sender Identifier in Extra Padding TLV
  - HMAC TLV (Type 8) support for TLV integrity verification
  - Proper flag handling: U-flag for unrecognized types, M-flag for malformed TLVs, I-flag for integrity failures
- Extended packet types: `ExtendedPacketAuthenticated`, `ExtendedPacketUnauthenticated`, and their reflected variants
- Lenient packet parsing with `from_bytes_lenient()` methods for short-packet interoperability (RFC 8762 Section 4.6)
- Canonical buffer support for HMAC verification of zero-padded short packets
- Wire-order preservation for TLV failure echo paths per RFC 8972 Section 4.8
- Truncated TLV byte-exact echo: preserves original wire length in header for malformed TLVs
- Sender-side TLV validation with `validate_reflected_tlvs()` helper
- Configuration validation: `--verify-tlv-hmac` now requires `--hmac-key` or `--hmac-key-file`

### Changed

- **Breaking**: `auth_mode` now only accepts exactly `A` (authenticated) or `O` (open/unauthenticated)
  - Composite strings like `AO` are no longer valid (modes are mutually exclusive per RFC 8762)
  - `is_auth()` and `is_open()` now use exact string matching instead of substring search
- Receiver assembly functions updated to handle TLV extensions
- Both `nix` and `pnet` receiver backends updated for TLV-aware packet processing
- HMAC verification in authenticated mode now uses canonical zero-padded buffers

### Fixed

- Sender TLV-HMAC validation now uses fixed base offset (44/112 bytes) instead of fragile inference from packet length
- Short authenticated packets are now properly zero-filled before HMAC verification
- Malformed TLVs are echoed byte-exactly with original declared length preserved

### Removed

- Removed unsupported `process` TLV handling mode from documentation
- Removed `E` (encrypted) auth mode option (not defined in RFC 8762)

## [0.2.0] - 2024-12-01

### Added

- Multi-session support in reflector with `SessionManager`
- Stateful reflector mode (`--stateful-reflector`) per RFC 8972
- Session timeout configuration (`--session-timeout`)
- HMAC authentication support with `--hmac-key` and `--hmac-key-file` options
- `--require-hmac` option to mandate HMAC verification
- Error estimate configuration (`--error-scale`, `--error-multiplier`, `--clock-synchronized`)
- Integration tests using loopback interface
- RFC 8762 compatibility improvements

### Changed

- Improved packet serialization using big-endian encoding
- Enhanced error handling throughout the codebase

## [0.1.0] - 2024-01-01

### Added

- Initial implementation of STAMP protocol (RFC 8762)
- Session-Sender and Session-Reflector modes
- Unauthenticated and authenticated packet formats
- NTP and PTP timestamp support
- IPv4 and IPv6 support
- Basic RTT and packet loss statistics
- CLI interface with clap
