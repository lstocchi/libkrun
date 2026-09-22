// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "linux")]
pub const DEFAULT_KERNEL_CMDLINE: &str = "reboot=k panic=-1 panic_print=0 nomodule console=hvc0 \
                                          rootfstype=virtiofs rw quiet no-kvmapf";
#[cfg(target_os = "macos")]
pub const DEFAULT_KERNEL_CMDLINE: &str = "reboot=k panic=-1 panic_print=0 nomodule console=hvc0 \
                                          rootfstype=virtiofs rw quiet no-kvmapf";
// WHP provides the LAPIC. libkrun supplies a userspace PIT and IOAPIC, but no
// legacy PIC, so skip checks which assume a complete PC timer topology.
#[cfg(target_os = "windows")]
pub const DEFAULT_KERNEL_CMDLINE: &str = "reboot=k panic=-1 panic_print=0 nomodule console=hvc0 \
                                          rootfstype=virtiofs rw quiet no_timer_check";

/// Strongly typed data structure used to configure the boot source of the
/// microvm.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct KernelCmdlineConfig {
    pub prolog: Option<String>,
    pub krun_env: Option<String>,
    pub epilog: Option<String>,
}
