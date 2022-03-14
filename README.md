# stamp-suite
Simple Two-Way Active Measurement Protocol (STAMP)

[![Rust](https://github.com/asmie/stamp-suite/actions/workflows/rust.yml/badge.svg)](https://github.com/asmie/stamp-suite/actions/workflows/rust.yml)
[![Dependency status](https://deps.rs/repo/github/asmie/stamp-suite/status.svg)](https://deps.rs/repo/github/asmie/stamp-suite)
[![License](https://img.shields.io/crates/l/stamp-suite.svg)](https://opensource.org/licenses/MIT)
[![Latest version](https://img.shields.io/crates/v/stamp-suite.svg)](https://crates.io/crates/stamp-suite)

## A word about
stamp-suite consists of one application called stamp(.exe) that can be used to perform full STAMP sending and receiving packets. It's intended to be fully compatible with RFC 8762 and incorporate extensions from RFC 8972.

The main aim to use STAMP is to measure the packet loss and delays in networks between the two ends. Beside the configuration both ends need to have their time synchronized either using NTP or PTP standards. Then, STAMP can be used to determine the link quality in one direction (stateless) or both directions (stateful).

STAMP is simple protocol where configuration and sessions handling is out of the standard's scope. As the RFC stands it does not matter what communication channel will be used to provide both endpoints (sender and reflector) with proper configuration. stamp-suite is using command line as the main source for the configuration and therefore it needs to be executed with complementary settings on both sides.

## Usage
Basic usage is just to call the binary with the correct options. Anytime you can use -h for help.

```
USAGE:
    stamp [OPTIONS]

OPTIONS:
    -c, --clock-source <CLOCK_SOURCE>    Clock source to be used [default: NTP]
    -h, --help                           Print help information
    -l, --local-addr <LOCAL_ADDR>        Local address to bind for [default: 0.0.0.0]
    -o, --local-port <LOCAL_PORT>        UDP port number for incoming packets [default: 852]
    -p, --remote-port <REMOTE_PORT>      UDP port number for outgoing packets [default: 852]
    -r, --remote-addr <REMOTE_ADDR>      Remote address for Session Reflector
    -V, --version                        Print version information
```

## Further development
stamp-suite handles only one session at the time so it can be used to associate exactly one sender with exactly one reflector. This can be improved in the future as one reflector can handle many senders. Of course, it's simple when we're talking about the stateless mode as the only thing that reflector needs to do is copy original fields and generate own timestamp (in unauthorized mode). The things is going worse when we're talking about the stateful mode and multiple sessions, when some of them can be started and some of them can be terminated. As STAMP does not handles session management itself it needs to be done outside (somehow). Using 4-tuple params is of course problematic as configuring session-reflector for each 4-tuple can drive everybody crazy, using optional session identifiers described in the RFC 8972 seems to be the best way to handle state. 

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## Versioning

I use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/asmie/stamp-suite). 

## Authors

* **Piotr Olszewski** - *Original work* - [asmie](https://github.com/asmie)

See also the list of [contributors](https://github.com/asmie/stamp-suite/contributors) who participated in this project.


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details


