#include "cidr_toolkit/ipv4_network.hpp"

#include <charconv>
#include <limits>
#include <stdexcept>
#include <system_error>

namespace cidr_toolkit {
namespace {

std::uint32_t parse_ipv4(std::string_view input) {
    std::uint32_t address = 0;
    std::size_t octet_start = 0;

    for (int octet_index = 0; octet_index < 4; ++octet_index) {
        const std::size_t separator = input.find('.', octet_start);
        const bool is_last_octet = octet_index == 3;

        if ((!is_last_octet && separator == std::string_view::npos) ||
            (is_last_octet && separator != std::string_view::npos)) {
            throw std::invalid_argument(
                "IPv4 address must contain exactly four decimal octets.");
        }

        const std::size_t octet_end =
            separator == std::string_view::npos ? input.size() : separator;
        const std::string_view octet_text =
            input.substr(octet_start, octet_end - octet_start);

        if (octet_text.empty()) {
            throw std::invalid_argument("IPv4 octets cannot be empty.");
        }

        unsigned int octet = 0;
        const auto conversion = std::from_chars(
            octet_text.data(), octet_text.data() + octet_text.size(), octet);

        if (conversion.ec == std::errc::result_out_of_range || octet > 255) {
            throw std::invalid_argument(
                "IPv4 octet is outside the valid range 0-255: " +
                std::string(octet_text));
        }
        if (conversion.ec != std::errc{} ||
            conversion.ptr != octet_text.data() + octet_text.size()) {
            throw std::invalid_argument(
                "IPv4 octets must contain decimal digits only.");
        }

        address = (address << 8U) | static_cast<std::uint32_t>(octet);
        octet_start = octet_end + 1;
    }

    return address;
}

std::uint8_t parse_prefix(std::string_view input) {
    unsigned int prefix = 0;
    const auto conversion =
        std::from_chars(input.data(), input.data() + input.size(), prefix);

    if (conversion.ec == std::errc::result_out_of_range || prefix > 32) {
        throw std::invalid_argument("CIDR prefix must be between 0 and 32.");
    }
    if (conversion.ec != std::errc{} ||
        conversion.ptr != input.data() + input.size()) {
        throw std::invalid_argument(
            "CIDR prefix must be a decimal number between 0 and 32.");
    }

    return static_cast<std::uint8_t>(prefix);
}

} // namespace

IPv4Network IPv4Network::parse(std::string_view cidr) {
    const std::size_t separator = cidr.find('/');
    if (separator == std::string_view::npos || separator == 0 ||
        separator + 1 == cidr.size() ||
        cidr.find('/', separator + 1) != std::string_view::npos) {
        throw std::invalid_argument("Expected input in the form IPv4/prefix.");
    }

    return IPv4Network(parse_ipv4(cidr.substr(0, separator)),
                       parse_prefix(cidr.substr(separator + 1)));
}

IPv4Network::IPv4Network(std::uint32_t address,
                         std::uint8_t prefix_length) noexcept
    : address_(address), prefix_length_(prefix_length) {}

std::uint32_t IPv4Network::address() const noexcept {
    return address_;
}

std::uint8_t IPv4Network::prefix_length() const noexcept {
    return prefix_length_;
}

std::uint32_t IPv4Network::subnet_mask() const noexcept {
    if (prefix_length_ == 0) {
        return 0;
    }

    return std::numeric_limits<std::uint32_t>::max()
           << (32U - prefix_length_);
}

std::uint32_t IPv4Network::network_address() const noexcept {
    return address_ & subnet_mask();
}

std::uint32_t IPv4Network::broadcast_address() const noexcept {
    return network_address() | ~subnet_mask();
}

std::uint32_t IPv4Network::first_usable_host() const noexcept {
    if (prefix_length_ >= 31) {
        return network_address();
    }

    return network_address() + 1U;
}

std::uint32_t IPv4Network::last_usable_host() const noexcept {
    if (prefix_length_ >= 31) {
        return broadcast_address();
    }

    return broadcast_address() - 1U;
}

std::uint64_t IPv4Network::usable_host_count() const noexcept {
    if (prefix_length_ == 31) {
        return 2;
    }
    if (prefix_length_ == 32) {
        return 1;
    }

    return (std::uint64_t{1} << (32U - prefix_length_)) - 2U;
}

std::string format_ipv4(std::uint32_t address) {
    return std::to_string((address >> 24U) & 0xFFU) + "." +
           std::to_string((address >> 16U) & 0xFFU) + "." +
           std::to_string((address >> 8U) & 0xFFU) + "." +
           std::to_string(address & 0xFFU);
}

} // namespace cidr_toolkit
