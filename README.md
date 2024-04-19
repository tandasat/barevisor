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

The primary goal of this project is to educate how hardware-assisted virtualization technologies on x86 work and can be used to "hyperjack" Windows and UEFI.


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


## Non-goals

This project's is optimize for learning Intel VT-x and AMD SVM, and thus, a few features some might expect or think to essential are missing, for example:

- Security

    Barevisor makes no attempt to protect itself from the guest, DMA, and in some cases, even depends on the guest controlled memory.

- Useful functionality

    The only functionality Barevisor offers is reporting of a hypervisor name via the `CPUID` instruction. No features like guest inspection or hardening is provided.

- Greater compatibility

    Barevisor aims to support hyperjacking and booting UEFI and Windows on VMware, Bochs and the select hardware models, precisely. It handles edge cases only when required complexity is low.

Having written hypervisors many (many) times for teaching, I am comfortable to say that the hardest part of learning hardware-assisted virtualization technologies is getting started and understanding the foundation. As you learn the building blocks and motivated, it is easier to get started to cover the listed missing features as you need. Even, some are not interested in some or any of those features. If you are interested in more about those features, contact me for discussion and references. I offer a 4-day long training course covering some of those as well.
