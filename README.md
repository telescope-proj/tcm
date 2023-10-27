# Telescope Connection Manager

TCM is a library for RDMA connection establishment and basic memory management
built on top of Libfabric. It abstracts and manages the lifecycle of internal
fabric resources akin to those provided by RDMA-CM, but with RAII semantics.

TCM supports:
- Reliable datagram connection establishment for RDMA Verbs and TCP transports
  over IPv4 using out-of-band UDP communication
- Simple fabric create and delete functions that acquire/release resources in
  the correct order
- Managed sync/async RDMA send, receive, read, and write operations
- Hugepage memory allocation functions on supported machines
- Lifecycle-managed (RAII) allocation of plain and RDMA-enabled memory
- Connection splitting to address head-of-line blocking issues

## License

Copyright (c) 2023 Tim Dettmar  
This software is licensed under the MIT License.  
The full license text is in the file LICENSE