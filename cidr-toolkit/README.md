# CIDR Toolkit

CIDR Toolkit is a small C++ command-line application that validates an IPv4
address in CIDR notation and reports its subnet details.

## Features

- Strict IPv4 and CIDR prefix validation
- Subnet mask, network, and broadcast address calculation
- First host, last host, and usable host count calculation
- Binary view of the address, mask, and network address
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

IP:      11000000.10101000.00001010.00100101
Mask:    11111111.11111111.11111111.11100000
Network: 11000000.10101000.00001010.00100000
```

The binary block prints the same three values bit by bit, so the boundary the
prefix draws between the network and host portions is visible directly.

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
├── CMakeLists.txt
├── README.md
└── .gitignore
```

## Design

The calculation layer stores an IPv4 address as an unsigned 32-bit integer.
The most significant byte represents the first dotted-decimal octet, and the
least significant byte represents the fourth. Parsing validates exactly four
decimal octets, then builds the integer by shifting the current value eight
bits before adding each octet. Formatting performs the reverse operation.

The subnet mask contains `prefix` high-order one bits followed by zero bits.
`/0` is handled separately so the implementation never shifts a 32-bit value
by 32 positions. The network and broadcast addresses are calculated as:

```text
network   = address AND mask
broadcast = network OR (NOT mask)
```

For prefixes `/0` through `/30`, the usable range excludes the network and
broadcast addresses. Under RFC 3021, both addresses in a `/31` may identify
endpoints on a point-to-point link. A `/32` identifies one host route, so all
reported address fields are the same address.

`IPv4Network::parse` validates CIDR text and creates the numeric
representation. The remaining `IPv4Network` methods perform the network
calculations, while `format_ipv4` converts results back to dotted-decimal
text and `format_ipv4_binary` renders the same 32 bits as four dotted octets.
`main.cpp` handles command-line validation and presentation; tests call the
calculation API directly.

## Known limitations

- IPv4 only; IPv6 is not supported.
- Accepts numeric addresses only and does not perform DNS resolution.
- Calculates one supplied network at a time and does not aggregate or split
  address ranges.
