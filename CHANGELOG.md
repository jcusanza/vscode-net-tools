# Change Log

All notable changes to the "vscode-net-tools" extension will be documented in this file.

## 1.x Initial Release

### 1.3.0

* Added icon to activity bar and relocated details and data to primary sidebar to make room for additional sections

* Improved formatting for packet details and packet bytes

* Added packet locator panel to sidebar for highlighting or filtering on a selected protocol or endpoint

* Improved coloring for users that have VSCode incorrectly configured to use a light theme

* Highlights byte data matching selected packet details

* Added new protocol parsers:
    * TLS (header identification only)
    * QUIC (header identification only)

* Fixed bugs:
    * Exception caused by truncated DNS packets 

### 1.2.0

* Updated icon

* Expanded on DNS implementation with more record types

* Optimized binary output for large files

* Added new protocol parsers:
    * PPPoE (discovery only)
    * IGMP versions 1-3
    * VXLAN

* Fixed bugs:
    * Exception handling on a per-line basis
    * Incorrect options offset for ICMPv6
    * Excess data in known protocols for IPv4 
    * Excess parenthesis in IPv6 output

### 1.1.0

* Implemented SLL2, 802.1Q VLAN, HTTP, PCAPNG Simple Packet Block

* Fixed bugs:
    * Incorrect packet length calculation when captured length < original length
    * PCAPNG packets not aligned to 4 byte boundary caused incorrect calculation
    * Handling of non-ethernet packets
    * Showing line-numbering for non-packet rows

* Added in-line comments

### 1.0.0

* Initial release of VSCode Network Tools