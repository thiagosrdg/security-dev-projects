// Public interface for parsing and calculating IPv4 CIDR networks.
#ifndef CIDR_TOOLKIT_IPV4_NETWORK_HPP
#define CIDR_TOOLKIT_IPV4_NETWORK_HPP

#include <cstdint>
#include <string>
#include <string_view>

namespace cidr_toolkit {

class IPv4Network {
public:
    // Parse an address in the form "address/prefix".
    static IPv4Network parse(std::string_view cidr);

    // Return the original address and prefix supplied by the caller.
    std::uint32_t address() const noexcept;
    std::uint8_t prefix_length() const noexcept;

    // Return the derived subnet values.
    std::uint32_t subnet_mask() const noexcept;
    std::uint32_t network_address() const noexcept;
    std::uint32_t broadcast_address() const noexcept;
    std::uint32_t first_usable_host() const noexcept;
    std::uint32_t last_usable_host() const noexcept;
    std::uint64_t usable_host_count() const noexcept;

private:
    IPv4Network(std::uint32_t address, std::uint8_t prefix_length) noexcept;

    // Store the address and prefix in compact numeric form.
    std::uint32_t address_;
    std::uint8_t prefix_length_;
};

std::string format_ipv4(std::uint32_t address);

// Format an address as dotted binary, for example "11000000.10101000...".
std::string format_ipv4_binary(std::uint32_t address);

} // namespace cidr_toolkit

#endif
