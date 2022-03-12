pub enum ConfigurationErr {
    InvalidConfiguration

}

enum StampModes {
    Unauthenticated,
    Authenticated,
}

enum StampReflectorModes {
    Stateless,
    Stateful,
}

enum ClockSource {
    NTP,
    PTP,
}

struct Configuration
{

}