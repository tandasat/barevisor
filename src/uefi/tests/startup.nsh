# Switch to the filesystem with the hypervisor file and load it.
echo -off
if exist fs0:uefi_hv.efi then
  fs0:
endif
if exist fs1:uefi_hv.efi then
  fs1:
endif

load uefi_hv.efi
check_hv_vendor.efi
