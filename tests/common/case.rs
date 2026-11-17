//! Names the case a matrix test is running, so a failed assertion inside a
//! loop says which combination failed.
#![allow(dead_code)] // Each integration target uses a different helper subset.

/// Prints its label to stderr if the thread panics while the guard is alive.
/// The test harness shows a failing test's captured stderr.
pub struct Case(String);

impl Case {
    pub fn new(label: String) -> Self {
        Self(label)
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("failed case: {}", self.0);
        }
    }
}
