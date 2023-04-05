# Known Configuration Issues

## Locked Memory

These errors often manifest as "Cannot allocate memory" errors when running
fabric-related functions. Unless your machine is really out of memory, it is
recommended to check your locked memory limit and adjust it to a reasonable
value (requires restart).

# Known Hardware Issues

## RDMA Incompatibility

Please verify that you are using the correct RDMA technology on either side.
RoCEv1 and RoCEv2 are not compatible! The following RDMA technologies are
totally incompatible with each other:

- RoCE v1
- RoCE v2
- InfiniBand
- iWARP
- Omni-Path/PSM/OPX

## RoCE networks without ECN/PFC

Older RoCE cards perform extremely poorly when PFC (RoCEv1) or ECN (RoCEv2) are
not enabled on the network and congestion is experienced. To solve this issue,
either enable ECN/PFC on your network (out of the scope of these docs), or
dedicate the link you wish to use solely for RDMA traffic.

## Older Mellanox cards (ConnectX-3)

On older Mellanox cards, such as the ConnectX-2 and -3, SR-IOV with the
in-kernel mlx4 drivers will not work properly, especially on Windows. The OFED
stack is also out of date and will often failed to install on any modern Linux
5.x+ kernel.

## QLogic/Marvell FastLinQ 41000/45000/8400 Series

Adapters from this FastLinq series that use the qede/qedr driver work well,
however special UEFI support is needed. Please ensure the following options are
enabled:

- Above 4G decoding
- PCIe ARI (Alternative Routing ID)
- 10-bit Tag Support

If your UEFI/BIOS does not support these features, it is possible that the card
initialization may fail with cryptic errors in dmesg. For instance, the error
`unknown header type 7f` is an indication that one of the above are not enabled
(or your card is defective).

Due to Libfabric probing for inline data amounts that exceed the capabilities of
the NIC, you may see `[create_qp:2752]create qp: failed on ibv_cmd_create_qp
with 22` in program output. This is normal.