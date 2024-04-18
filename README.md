# Barevisor

A bare minimum hypervisor on AMD and Intel processors for learners.


## Features

- ✅ Uses stable Rust🦀
- ✅ Covers both AMD and Intel with single code
- ✅ Compiles into UEFI and Windows drivers
- ✅ Runs on Bochs and VMware with one shortcut key
- ✅ Supports select hardware models
- ✅ Builds on 📎Windows, 🍎macOS and 🐧Ubuntu
- ✅ Comes with extensive comments


## Motivation

The primary goal of this project is to share the hypervisor implementation that is approachable to those who are new to the technology based on the stable Rust toolchain.


## Package organization

The project contains two workspaces: `src/windows/` and `src/uefi/`, building the hypervisor as a Windows kernel driver and UEFI driver, respectively.

Both workspaces depend on `src/hvcore/`, the core, OS agnostic hypervisor implementation as illustrated below:

```
    windows --\
               +-- (links) --> hvcore
    uefi -----/
```

For details of each workspace and package, and build instructions, see respective README.md files.


## Acknowledgement

[memN0ps](https://github.com/memN0ps)'s Rust hypervisor projects substantially inspired and helped me to get started with this work. I encourage you to study those projects as additional resources.
