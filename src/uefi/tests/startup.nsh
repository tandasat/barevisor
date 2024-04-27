echo -off
if exist fs0:uefi_hv.efi then
  fs0:
endif
if exist fs1:uefi_hv.efi then
  fs1:
endif
if exist fs2:uefi_hv.efi then
  fs2:
endif
if exist fs3:uefi_hv.efi then
  fs3:
endif

# Do not connect to a decice with `-nc`. Connecting to a device makes LLM1v6SQ
# substantially slower.
load -nc uefi_hv.efi
check_hv_vendor.efi
