// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::{kvm_msr_entry, MsrList, Msrs};
use kvm_ioctls::{Kvm, VcpuFd};

use super::super::msr::{boot_msr_entries, msr_should_serialize, Error};

type Result<T> = std::result::Result<T, Error>;

fn create_boot_msr_entries() -> Vec<kvm_msr_entry> {
    boot_msr_entries()
        .into_iter()
        .map(|(index, data)| kvm_msr_entry {
            index,
            data,
            ..Default::default()
        })
        .collect()
}

/// Configure Model Specific Registers (MSRs) required to boot Linux for a given x86_64 vCPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn setup_msrs(vcpu: &VcpuFd) -> Result<()> {
    let entry_vec = create_boot_msr_entries();
    let msrs = Msrs::from_entries(&entry_vec).unwrap();
    vcpu.set_msrs(&msrs)
        .map_err(Error::SetModelSpecificRegisters)
        .and_then(|msrs_written| {
            if msrs_written as u32 != msrs.as_fam_struct_ref().nmsrs {
                Err(Error::SetModelSpecificRegistersCount)
            } else {
                Ok(())
            }
        })
}

/// Returns the list of supported, serializable MSRs.
///
/// # Arguments
///
/// * `kvm_fd` - Structure that holds the KVM's fd.
pub fn supported_guest_msrs(kvm_fd: &Kvm) -> Result<MsrList> {
    let mut msr_list = kvm_fd
        .get_msr_index_list()
        .map_err(Error::GetSupportedModelSpecificRegisters)?;

    msr_list.retain(|msr_index| msr_should_serialize(*msr_index));

    Ok(msr_list)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arch_gen::x86::msr_index::*;
    use kvm_ioctls::Kvm;

    #[test]
    #[allow(clippy::cast_ptr_alignment)]
    fn test_setup_msrs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        setup_msrs(&vcpu).unwrap();

        // This test will check against the last MSR entry configured (the tenth one).
        // See create_msr_entries() for details.
        let test_kvm_msrs_entry = [kvm_msr_entry {
            index: MSR_IA32_MISC_ENABLE,
            ..Default::default()
        }];
        let mut kvm_msrs_wrapper = Msrs::from_entries(&test_kvm_msrs_entry).unwrap();

        // Get_msrs() returns the number of msrs that it succeed in reading.
        // We only want to read one in this test case scenario.
        let read_nmsrs = vcpu.get_msrs(&mut kvm_msrs_wrapper).unwrap();
        // Validate it only read one.
        assert_eq!(read_nmsrs, 1);

        // Official entries that were setup when we did setup_msrs. We need to assert that the
        // tenth one (i.e the one with index MSR_IA32_MISC_ENABLE has the data we
        // expect.
        let entry_vec = create_boot_msr_entries();
        assert_eq!(entry_vec[9], kvm_msrs_wrapper.as_slice()[0]);
    }
}
