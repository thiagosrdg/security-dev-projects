#include "cidr_toolkit/ipv4_network.hpp"

#include <exception>
#include <iomanip>
#include <iostream>
#include <string>

namespace {

void print_field(const std::string& label, const std::string& value) {
    std::cout << std::left << std::setw(20) << label << value << '\n';
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <IPv4/CIDR>\n";
        return 1;
    }

    try {
        const cidr_toolkit::IPv4Network network =
            cidr_toolkit::IPv4Network::parse(argv[1]);

        print_field("IP address:", cidr_toolkit::format_ipv4(network.address()));
        print_field("CIDR prefix:",
                    "/" + std::to_string(network.prefix_length()));
        print_field("Subnet mask:",
                    cidr_toolkit::format_ipv4(network.subnet_mask()));
        print_field("Network address:",
                    cidr_toolkit::format_ipv4(network.network_address()));
        print_field("Broadcast address:",
                    cidr_toolkit::format_ipv4(network.broadcast_address()));
        print_field("First usable host:",
                    cidr_toolkit::format_ipv4(network.first_usable_host()));
        print_field("Last usable host:",
                    cidr_toolkit::format_ipv4(network.last_usable_host()));
        print_field("Usable hosts:",
                    std::to_string(network.usable_host_count()));

        if (network.is_point_to_point()) {
            std::cout << "Note: RFC 3021 permits both /31 addresses to be used "
                         "on point-to-point links.\n";
        } else if (network.is_single_host()) {
            std::cout << "Note: A /32 represents a single-host route.\n";
        }
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
