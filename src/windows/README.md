# Visor

The goal of this project is to make it look like writing hypervisors are easy.

```
**********************************************************************
** Enterprise Windows Driver Kit (WDK) build environment
** Version ni_release_svc_prod1.22621.2428
**********************************************************************
** Visual Studio 2022 Developer Command Prompt vError: Unknown error
** Copyright (c) 2022 Microsoft Corporation
**********************************************************************
D:\>cd /d C:\Users\tanda\Desktop\RnD\GitHub\visor


cargo install cargo-make
cargo make
```

```
[cargo-make] INFO - Execute Command: "rust-script" "target\\_cargo_make_temp\\persisted_scripts\\D4060E7434B3779E78A683E8BA00D06A5D08BE8C95BC432359E22F06CB30EF1C.rs"
Error: IoError(Os { code: 1314, kind: Uncategorized, message: "A required privilege is not held by the client." })
[cargo-make] ERROR - Unable to execute rust code.
[cargo-make] WARN - Build Failed.
```

System > For developers > Developer Mode = ON



---------------

sc config serial start=disabled
