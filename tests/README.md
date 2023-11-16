# TCM Test & Demo Programs

These files are for testing TCM and also serve as examples of how to use the TCM
API.

## Environment variables

Environment variables must be set before running any of the TCM test programs.
The following can be set:

### Common

`BEACON_ADDR` - Address of the beacon  
`BEACON_PORT` - Port number of the beacon  

The local beacon is bound to this address. This is required on the server, but
optional on the client, which will use dynamic UDP addressing if the environment
variable is not set.

`FABRIC_ADDR` - Fabric local bind address  
`FABRIC_PORT` - Fabric local data port  

If the fabric address is not specified, the beacon address is used here.

`TRANSPORT_NAME` - Libfabric transport name

The supported transports are `verbs;ofi_rxm` and `tcp;ofi_rxm`. Note that
`verbs;ofi_rxm` may not support loopback when the source and destination NIC
addresses are the same, depending on the NIC vendor.

The server will verify the private data sent by the client and vice versa.

### Client

`SERVER_ADDR` - Server IP address  
`SERVER_PORT` - Server port number  