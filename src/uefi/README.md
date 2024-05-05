# uefi_hv

Barevisor as a UEFI driver for Intel and AMD processors.

![](images/demo.gif)

- [uefi\_hv](#uefi_hv)
  - [Why UEFI driver-based hypervisor](#why-uefi-driver-based-hypervisor)
  - [Building](#building)
  - [Setting up a Bochs VM](#setting-up-a-bochs-vm)
  - [Loading on the Bochs VM](#loading-on-the-bochs-vm)
  - [Setting up a VMware VM](#setting-up-a-vmware-vm)
  - [Loading on the VMware VM](#loading-on-the-vmware-vm)


## Why UEFI driver-based hypervisor

Barevisor can be compiled into both UEFI driver and Windows kernel driver. Those who are interested in virtualizing UEFI, boot loaders and early OS initialization phases should study UEFI driver-based hypervisors. It is also suitable for having a better picture of how Intel VT-x and AMD SVM, and OS agnostic designs.


## Building

1. Navigate to the `barevisor\src\uefi` directory.

    ```text
    > cd C:\Users\tanda\Desktop\RnD\GitHub\barevisor\src\uefi
    ```

2. Build Barevisor with the `xtask` command.

    ```text
    > cargo xtask build
    ```

    If successful, `target\x86_64-unknown-uefi\debug\uefi_hv.efi` should exist.

    Along with that, `check_hv_vendor.efi` is built. This is useful for confirming that Barevisor is loaded into the system (more in the below section).


## Setting up a Bochs VM

Barevisor can be partially tested with [Bochs](https://github.com/bochs-emu/Bochs), a cross-platform open-source x86_64 PC emulator. It is **extremely** helpful in an early-phase of hypervisor development as it can be used to debug the types of errors that are difficult to diagnose on VMware. Failure of the VMX instructions is the primal example.

Set up a Bochs VM with the following instructions:

- <details markdown="block"><summary>On Ubuntu</summary>

    ```
    $ sudo apt install git gcc g++ make
    $ git clone -b barevisor https://github.com/tandasat/Bochs.git
    $ cd Bochs/bochs
    $ sh .conf.linux
    $ make
    $ sudo make install
    ```

    </details>

- <details markdown="block"><summary>On Windows (WSL)</summary>

    ```
    $ sudo apt install git gcc g++ make
    $ git clone -b barevisor https://github.com/tandasat/Bochs.git
    $ cd Bochs/bochs
    $ sh .conf.linux
    $ make
    $ sudo make install
    ```

    </details>

- <details markdown="block"><summary>On macOS</summary>

    ```
    $ git clone -b barevisor https://github.com/tandasat/Bochs.git
    $ cd Bochs/bochs
    $ sh .conf.macosx
    $ make
    $ sudo make install
    ```

    </details>

## Loading on the Bochs VM

In the `uefi` directory, run either `cargo xtask bochs-amd` or `cargo xtask bochs-intel` to test on AMD and Intel processors respectively.

![](images/demo_bochs.gif)

Note that the author was unable to test booting an OS in Bochs because unable to install an OS in our Bochs configuration, where UEFI is used instead of traditional BIOS. Please let me know if you made it work.


## Setting up a VMware VM

## Loading on the VMware VM

1. Disable secure boot on the target system. It requires a change in BIOS settings, and actual steps vary depending on models.

2. Boot the system into UEFI shell.

3. Copy `uefi_hv.efi` into external storage and connect it to the VM.

4. Load Barevisor.

    ```text
    Shell> fs1:
    fs1:\> load uefi_hv.efi
    Loading uefi_hv.efi
    Image base: 0xe374000..0xe3c2000
    Loaded uefi_hv.efi
    load: Image fs1:uefi_hv.efi loaded at E374000 - Success
    ```

    If successful, serial output should appear. Additionally, you may confirm that Barevisor is active by executing `check_hv_vendor.exe`.

    ```text
    fs1:\> check_hv_vendor.efi
    Executing CPUID(0x40000000) on all logical processors
    CPU 0: Barevisor!
    CPU 1: Barevisor!
    CPU 2: Barevisor!
    CPU 3: Barevisor!
    ```
