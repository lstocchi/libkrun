// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::msr::{boot_msr_entries, Error};
use windows_sys::Win32::System::Hypervisor::*;

type Result<T> = std::result::Result<T, Error>;

/// Configure MSRs via the WHP API.
pub fn setup_msrs(vcpu: &whp::WhpVcpu) -> Result<()> {
    for (index, data) in boot_msr_entries() {
        let name = WHV_REGISTER_NAME(0x00002000 + index);
        vcpu.set_reg64(name, data).map_err(Error::SetMsrsWhp)?;
    }
    Ok(())
}
