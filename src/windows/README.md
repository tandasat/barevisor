# win_hv

Barevisor as a Windows kernel driver for Intel and AMD processors.


## Why kernel driver-based hypervisor

Barevisor can be compiled into both UEFI driver and Windows kernel driver. Those familiar with Windows kernel module development should consider the kernel driver-based hypervisor as most approachable because the hypervisor requires less code and can be debugged with the traditional kernel-debugger, Windbg.


## Building

Building Barevisor as a Windows kernel-driver requires Windows as a development environment, due to dependencies onto Enterprise WDK (eWDK).

1. Download [eWDK](https://learn.microsoft.com/en-us/legal/windows/hardware/enterprise-wdk-license-2022).

2. Mount or extract the contents of the downloaded ISO file.

3. Double click on `LaunchBuildEnv.cmd` in the top directory of the ISO file. It should start up the command prompt.

    ```text
    **********************************************************************
    ** Enterprise Windows Driver Kit (WDK) build environment
    ** Version ni_release_svc_prod1.22621.2428
    **********************************************************************
    ** Visual Studio 2022 Developer Command Prompt vError: Unknown error
    ** Copyright (c) 2022 Microsoft Corporation
    **********************************************************************
    C:\EWDK_ni_release_svc_prod1_22621_230929-1800>
    ```

4. Navigate to the `barevisor\src\windows` directory.

    ```text
    > cd C:\Users\tanda\Desktop\RnD\GitHub\barevisor\src\windows
    ```

5. Install `cargo-make`.

    ```text
    > cargo install cargo-make
    > cargo make
    ```

6. Build Barevisor.

    ```text
    > cargo make
    ```

    If you encounter an error like this, turn on the Developer Mode through Settings > System > For developers > Developer Mode.

    ```log
    [cargo-make] INFO - Execute Command: "rust-script" "target\\_cargo_make_temp\\persisted_scripts\\D4060E7434B3779E78A683E8BA00D06A5D08BE8C95BC432359E22F06CB30EF1C.rs"
    Error: IoError(Os { code: 1314, kind: Uncategorized, message: "A required privilege is not held by the client." })
    [cargo-make] ERROR - Unable to execute rust code.
    [cargo-make] WARN - Build Failed.
    ```

    If successful, `target\debug\win_hv_package\win_hv.sys` should exist.

7. Optionally, build the `check_hv_vendor` package. This is useful for confirming that Barevisor is loaded into the system (more in the below section).

    ```text
    > cargo build
    ```


## Loading

1. Disable secure boot on the target system. It requires a change in BIOS settings and actual steps vary depending on models.

2. On target Windows, start the command prompt with Administrators privileges.

3. Enable test signing.

    ```text
    > bcdedit /set testsigning on
    ```

4. Disable the serial service. This is required to view serial output from Barevisor.

    ```text
    > sc config serial start=disabled
    ```

5. Reboot Windows.

6. Copy `win_hv.sys` onto the target Windows, for example, `C:\win_hv.sys`.

7. Start the command prompt with Administrators privileges.

8. Create a service for Barevisor.

    ```text
    > sc create barevisor type= kernel binPath= C:\win_hv.sys
    ```

9.  Start Barevisor.

    ```text
    > sc start barevisor

    SERVICE_NAME: hv
            TYPE               : 1  KERNEL_DRIVER
            STATE              : 4  RUNNING
                                    (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
            WIN32_EXIT_CODE    : 0  (0x0)
            SERVICE_EXIT_CODE  : 0  (0x0)
            CHECKPOINT         : 0x0
            WAIT_HINT          : 0x0
            PID                : 0
            FLAGS              :
    ```

    If successful, serial output should appear. Additionally, you may confirm that Barevisor is active by executing `check_hv_vendor.exe`.

    ```text
    > check_hv_vendor.exe
    Executing CPUID(0x40000000) on all logical processors
    CPU 0: Barevisor!
    CPU 1: Barevisor!
    CPU 2: Barevisor!
    CPU 3: Barevisor!
    ```
