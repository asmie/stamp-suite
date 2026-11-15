//! Process memory observations outside the timed load; no peak/heap attribution.
use serde::Serialize;
use std::{fs, io, time::Instant};

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct Memory {
    rss_bytes: u64,
    pss_bytes: u64,
    private_bytes: u64,
    shared_bytes: u64,
    swap_bytes: u64,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl Memory {
    fn parse(text: &str) -> io::Result<Self> {
        // Use only exact aggregate keys, not similarly named Pss_Anon etc.
        let keys = [
            "Rss:",
            "Pss:",
            "Private_Clean:",
            "Private_Dirty:",
            "Shared_Clean:",
            "Shared_Dirty:",
            "Swap:",
        ];
        let mut values = [None; 7];
        for line in text.lines() {
            let mut words = line.split_whitespace();
            let Some(index) = words
                .next()
                .and_then(|key| keys.iter().position(|k| *k == key))
            else {
                continue;
            };
            if values[index].is_some() {
                return Err(invalid("duplicate smaps_rollup field"));
            }
            let value = words
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .and_then(|value| value.checked_mul(1024))
                .ok_or_else(|| invalid("invalid smaps_rollup size"))?;
            if words.next() != Some("kB") || words.next().is_some() {
                return Err(invalid("invalid smaps_rollup unit"));
            }
            values[index] = Some(value);
        }
        let mut bytes = [0; 7];
        for (slot, value) in bytes.iter_mut().zip(values) {
            *slot = value.ok_or_else(|| invalid("missing smaps_rollup field"))?;
        }
        Ok(Self {
            rss_bytes: bytes[0],
            pss_bytes: bytes[1],
            private_bytes: bytes[2]
                .checked_add(bytes[3])
                .ok_or_else(|| invalid("private memory size overflow"))?,
            shared_bytes: bytes[4]
                .checked_add(bytes[5])
                .ok_or_else(|| invalid("shared memory size overflow"))?,
            swap_bytes: bytes[6],
        })
    }
}

#[derive(Serialize)]
struct Process {
    pid: u32,
    #[serde(flatten)]
    memory: Memory,
}

impl Process {
    fn read(pid: u32) -> io::Result<Self> {
        let path = format!("/proc/{pid}/smaps_rollup");
        let result = fs::read_to_string(&path).and_then(|text| Memory::parse(&text));
        let memory = result.map_err(|error| {
            io::Error::new(error.kind(), format!("cannot measure {path}: {error}"))
        })?;
        Ok(Self { pid, memory })
    }
}

#[derive(Serialize)]
pub(super) struct Snapshot {
    reflector: Process,
    generator: Process,
    collection_seconds: f64,
}

pub(super) fn snapshot(enabled: bool, reflector_pid: u32) -> io::Result<Option<Snapshot>> {
    if !enabled {
        return Ok(None);
    }
    let start = Instant::now();
    // Sequential process observations, not one atomic system snapshot.
    let reflector = Process::read(reflector_pid)?;
    let generator = Process::read(std::process::id())?;
    Ok(Some(Snapshot {
        reflector,
        generator,
        collection_seconds: start.elapsed().as_secs_f64(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "00400000-ffff0000 ---p 00000000 00:00 0 [rollup]\n\
        Rss: 120 kB\nPss: 90 kB\nPrivate_Clean: 10 kB\nPrivate_Dirty: 50 kB\n\
        Shared_Clean: 40 kB\nShared_Dirty: 20 kB\nSwap: 8 kB\n\
        Pss_Anon: 40 kB\nSwapPss: 4 kB\nUnknown: ignored\n";

    #[test]
    fn rollup_uses_exact_fields_and_binary_kilobytes() {
        assert_eq!(
            Memory::parse(SAMPLE).unwrap(),
            Memory {
                rss_bytes: 120 * 1024,
                pss_bytes: 90 * 1024,
                private_bytes: 60 * 1024,
                shared_bytes: 60 * 1024,
                swap_bytes: 8 * 1024,
            }
        );
        let zero = SAMPLE.replace("Swap: 8", "Swap: 0");
        assert_eq!(Memory::parse(&zero).unwrap().swap_bytes, 0);
    }

    #[test]
    fn malformed_or_incomplete_observations_are_not_zero_memory() {
        for bad in [
            SAMPLE.replace("Rss: 120 kB\n", ""),
            format!("{SAMPLE}Rss: 120 kB\n"),
            SAMPLE.replace("120 kB", "-1 kB"),
            SAMPLE.replace("120 kB", "120 MB"),
            SAMPLE.replace("120 kB", "120"),
            SAMPLE.replace("120 kB", "120 kB extra"),
            SAMPLE.replace("120 kB", "18446744073709551615 kB"),
            SAMPLE
                .replace("Private_Clean: 10", "Private_Clean: 18014398509481983")
                .replace("Private_Dirty: 50", "Private_Dirty: 18014398509481983"),
        ] {
            assert_eq!(
                Memory::parse(&bad).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn disabled_observation_does_not_open_proc_and_enabled_errors_name_the_path() {
        assert!(snapshot(false, u32::MAX).unwrap().is_none());
        let error = Process::read(u32::MAX).err().unwrap();
        assert!(error.to_string().contains("/proc/4294967295/smaps_rollup"));
    }
}
