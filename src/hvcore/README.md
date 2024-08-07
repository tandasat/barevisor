# hvcore

- [hvcore](#hvcore)
  - [What](#what)
  - [Why](#why)
  - [How](#how)


## What

What does this do?

This package implements a hypervisor that virtualizes the current system as-is. When this code is loaded (as win_hv.sys or uefi_hv.efi), it takes a snapshot of the current register values and starts a VM (also called a guest or vCPU) using that snapshot. This allows the system to continue to run but as a VM, under the control of the hypervisor (also called the host). This approach is widely used to inspect and harden the system and sometimes called "hyperjack"-ing.


## Why

Why do I want to study hyperjacking hypervisors?

This type of hypervisors is substantially simpler than conventional hypervisors that are capable of starting up isolated VM instances. This simplicity makes this type of hypervisor suitable for understanding how hardware-assisted virtualization technologies work.

Not just for learning, this type of hypervisor is also practical. Thanks to its simplicity, it is realistic to implement them from scratch by yourself as you need. There are numerous examples where individuals implemented their custom hypervisors with the hyperjacking architecture.


## How

How does a hypervisor hyperjack the system?

The most common way a hypervisor hyperjacks the system is by starting a VM based on the current processor state. Then, by letting the VM access all hardware resources by default, the VM can behave as if nothing were changed. The hypervisor can selectively intercept hardware resource access by the VM to protect the hypervisor and provide additional features such as protecting security-sensitive resources like Control Registers from a comprimised kernel.

The same goes for memory. The hypervisor configures memory virtualization (EPT on Intel, and NPT on AMD) to let the VM access all physical memory by default. Then, selectively restrict access as needed, for example, to hide the hypervisor and enforce the W^X policy.

Devices are also accessible from the VM by default. Since there is no other VM to share a device, there is no need to virtualize a device.

This approach, also referred to as passthrough or thin hypervisors, contributes to significantly smaller code and a simpler design, as well as minimizing a performance impact on the system. Some of the simplest implementations that are sufficient to hyperjack Windows are less than 2000 lines in C code where 30% to 50% of them are comments (see [SimpleSvm](https://github.com/tandasat/SimpleSvm) and [SimpleVisor](https://github.com/ionescu007/SimpleVisor)).

With that background knowledge, let us dive into Barevisor code!

