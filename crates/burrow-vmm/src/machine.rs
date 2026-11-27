//! What every backend's VM answers to. [`crate::Vm`] dispatches each call to
//! its variant's implementation; a backend leaves out what it cannot do, and
//! the default refuses it.

use std::path::Path;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::process::VmmProcess;
use crate::{DriveSpec, Hypervisor, Phases};

pub(crate) trait Machine {
    fn hypervisor(&self) -> Hypervisor;

    fn workdir(&self) -> &Path;

    fn boot_latency(&self) -> Duration;

    async fn pause(&self) -> Result<()>;

    async fn resume(&self) -> Result<()>;

    /// Snapshots a **paused** VM in full, into its layout.
    async fn snapshot(&self) -> Result<()>;

    /// Stops the VMM and reaps it, then releases its cgroup.
    async fn kill(self) -> Result<()>;

    /// The display socket, for a VM given a display.
    fn display(&self) -> Option<std::path::PathBuf> {
        None
    }

    /// The VMM process, where this node spawned one.
    fn process(&self) -> Option<&VmmProcess> {
        None
    }

    fn process_mut(&mut self) -> Option<&mut VmmProcess> {
        None
    }

    fn pid(&self) -> Option<u32> {
        self.process()?.pid()
    }

    fn cpu_usage_usec(&self) -> Option<u64> {
        self.process()?.cpu_usage_usec()
    }

    fn phases(&self) -> Phases {
        Phases::default()
    }

    async fn console_tail(&self, _lines: usize) -> String {
        String::new()
    }

    async fn console_write(&mut self, _input: &str) -> Result<()> {
        Err(Error::ConsoleUnavailable)
    }

    async fn snapshot_diff(&self, _mem_file: &str) -> Result<()> {
        Err(self.unsupported("take a diff snapshot"))
    }

    fn can_map_diff(&self) -> bool {
        false
    }

    async fn attach_drive(&self, _drive: &DriveSpec) -> Result<()> {
        Err(self.unsupported("attach a drive to a running guest"))
    }

    async fn resize_disk(&self, _id: &str, _bytes: u64) -> Result<()> {
        Err(self.unsupported("grow a disk the guest has mounted"))
    }

    async fn resize_vcpus(&self, _vcpus: u32) -> Result<()> {
        Err(self.unsupported("change a running guest's vcpus"))
    }

    async fn request_memory(&self, _plugged_mib: u32) -> Result<()> {
        Err(self.unsupported("change a running guest's memory"))
    }

    async fn plugged_memory(&self) -> Result<u32> {
        Ok(0)
    }

    /// Waits for the guest to shut itself down, as after a `shutdown -h` in
    /// it.
    async fn wait_stopped(&self, _timeout: Duration) -> Result<()> {
        Err(self.unsupported("wait for a guest to shut down"))
    }

    fn unsupported(&self, what: &'static str) -> Error {
        Error::Unsupported {
            hypervisor: self.hypervisor(),
            what,
        }
    }
}
