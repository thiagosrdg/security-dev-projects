# CIDR Toolkit

CIDR Toolkit is a small C++ command-line application that validates an IPv4
address in CIDR notation and reports its subnet details.

## Features

- Strict IPv4 and CIDR prefix validation
- Subnet mask, network, and broadcast address calculation
- First host, last host, and usable host count calculation
- RFC 3021 behavior for `/31` point-to-point links
- Single-host route behavior for `/32`
- Clear errors and non-zero exit codes for invalid input
- Standard-library-only implementation

## Requirements

- A C++17-compatible compiler
- CMake 3.16 or newer

## Build and use

Run the following commands from this directory:

```bash
cmake -S . -B build
cmake --build build
./build/cidr-toolkit 192.168.10.37/27
```

Multi-configuration generators may place the executable in a configuration
subdirectory such as `build/Debug`.

Sample output:

```text
IP address:         192.168.10.37
CIDR prefix:        /27
Subnet mask:        255.255.255.224
Network address:    192.168.10.32
Broadcast address:  192.168.10.63
First usable host:  192.168.10.33
Last usable host:   192.168.10.62
Usable hosts:       30
```

Invalid values produce an error on standard error and exit with a non-zero
status:

```bash
./build/cidr-toolkit 192.168.1.300/24
```

## Tests

```bash
ctest --test-dir build
```

The test executable uses only the C++ standard library and is registered with
CTest during configuration.

## How the calculations work

Each dotted-decimal octet is validated and combined into one 32-bit unsigned
integer. The prefix generates a mask with high-order one bits. Bitwise AND
between the address and mask yields the network address; combining that network
with the inverted mask yields the broadcast address. Normal networks exclude
those two endpoints when calculating the usable host range.

For a `/31`, both addresses are reported as usable because RFC 3021 permits this
on point-to-point links. For a `/32`, the supplied address is treated as a
single-host route, so all reported address fields identify that one host.

## Project structure

```text
cidr-toolkit/
├── include/cidr_toolkit/ipv4_network.hpp
├── src/ipv4_network.cpp
├── src/main.cpp
├── tests/test_ipv4_network.cpp
├── docs/design.md
├── CMakeLists.txt
├── README.md
└── .gitignore
```

## Known limitations

- IPv4 only; IPv6 is not supported.
- Accepts numeric addresses only and does not perform DNS resolution.
- Calculates one supplied network at a time and does not aggregate or split
  address ranges.
