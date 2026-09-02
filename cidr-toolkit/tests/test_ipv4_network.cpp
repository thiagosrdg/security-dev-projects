// Basic behavior tests for IPv4 CIDR parsing and network calculations.
#include "cidr_toolkit/ipv4_network.hpp"

#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

int failures = 0;

template <typename Actual, typename Expected>
void expect_equal(const Actual& actual,
                  const Expected& expected,
                  std::string_view description) {
    // Count failures so all assertions can report before the process exits.
    if (actual != expected) {
        std::cerr << "FAIL: " << description << " (expected " << expected
                  << ", got " << actual << ")\n";
        ++failures;
    }
}

void expect_network(std::string_view cidr,
                    std::string_view mask,
                    std::string_view network_address,
                    std::string_view broadcast_address,
                    std::string_view first_host,
                    std::string_view last_host,
                    std::uint64_t host_count) {
    // Verify every derived value for one representative CIDR network.
    try {
        const cidr_toolkit::IPv4Network network =
            cidr_toolkit::IPv4Network::parse(cidr);
        const std::string context = std::string(cidr) + " ";
        const std::size_t separator = cidr.find('/');

        expect_equal(cidr_toolkit::format_ipv4(network.address()),
                     std::string(cidr.substr(0, separator)),
                     context + "input address");
        expect_equal(cidr_toolkit::format_ipv4(network.subnet_mask()),
                     std::string(mask), context + "subnet mask");
        expect_equal(cidr_toolkit::format_ipv4(network.network_address()),
                     std::string(network_address), context + "network address");
        expect_equal(cidr_toolkit::format_ipv4(network.broadcast_address()),
                     std::string(broadcast_address),
                     context + "broadcast address");
        expect_equal(cidr_toolkit::format_ipv4(network.first_usable_host()),
                     std::string(first_host), context + "first usable host");
        expect_equal(cidr_toolkit::format_ipv4(network.last_usable_host()),
                     std::string(last_host), context + "last usable host");
        expect_equal(network.usable_host_count(), host_count,
                     context + "usable host count");
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << cidr << " unexpectedly threw: " << error.what()
                  << '\n';
        ++failures;
    }
}

void expect_invalid(std::string_view cidr) {
    // Invalid CIDR text must throw std::invalid_argument.
    try {
        static_cast<void>(cidr_toolkit::IPv4Network::parse(cidr));
        std::cerr << "FAIL: expected invalid input to be rejected: " << cidr
                  << '\n';
        ++failures;
    } catch (const std::invalid_argument&) {
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << cidr << " threw the wrong exception: "
                  << error.what() << '\n';
        ++failures;
    }
}

} // namespace

int main() {
    // Cover ordinary networks, RFC 3021 /31, /32, /0, and invalid input.
    expect_network("192.168.10.37/27", "255.255.255.224", "192.168.10.32",
                   "192.168.10.63", "192.168.10.33", "192.168.10.62", 30);
    expect_network("10.0.0.1/8", "255.0.0.0", "10.0.0.0",
                   "10.255.255.255", "10.0.0.1", "10.255.255.254",
                   16777214);
    expect_network("172.16.5.200/24", "255.255.255.0", "172.16.5.0",
                   "172.16.5.255", "172.16.5.1", "172.16.5.254", 254);
    expect_network("192.168.1.10/30", "255.255.255.252", "192.168.1.8",
                   "192.168.1.11", "192.168.1.9", "192.168.1.10", 2);
    expect_network("10.0.0.0/31", "255.255.255.254", "10.0.0.0", "10.0.0.1",
                   "10.0.0.0", "10.0.0.1", 2);
    expect_network("127.0.0.1/32", "255.255.255.255", "127.0.0.1",
                   "127.0.0.1", "127.0.0.1", "127.0.0.1", 1);
    expect_network("0.0.0.0/0", "0.0.0.0", "0.0.0.0", "255.255.255.255",
                   "0.0.0.1", "255.255.255.254", 4294967294ULL);

    expect_invalid("192.168.1.300/24");
    expect_invalid("192.168.1.1/33");
    expect_invalid("192.168.1/24");
    expect_invalid("invalid");
    expect_invalid("192.168.1.1/-1");
    expect_invalid("192.168.1.1/24/1");
    expect_invalid("999999999999999999999.1.1.1/24");
    expect_invalid("192.168.1.1/999999999999999999999");

    if (failures != 0) {
        std::cerr << failures << " test assertion(s) failed.\n";
        return 1;
    }

    std::cout << "All IPv4 network tests passed.\n";
    return 0;
}
