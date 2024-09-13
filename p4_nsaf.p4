/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV6 = 0x86DD;
const bit<16> TYPE_IPV4 = 0x0800;

const bit<8> ICMPV6 = 0x3A;
const bit<8> ICMPV6_NS = 135;
const bit<8> ICMPV6_NA = 136;

const bit<16> UDP_PORT_MDNS = 5353; // mDNS port

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<128> ip6Addr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header ipv6_t {
    bit<4> version;
    bit<8> trafficClass;
    bit<20> flowLabel;
    bit<16> payloadLen;
    bit<8> nextHdr;
    bit<8> hopLimit;
    ip6Addr_t srcAddr;
    ip6Addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header icmpv6_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
    bit<32> reserved;
}

header ns_t {
    ip6Addr_t targetAddr;
}

header na_t {
    ip6Addr_t targetAddr;
}

struct headers {
    ethernet_t ethernet;
    ipv6_t ipv6;
    ipv4_t ipv4;
    udp_t udp;
    icmpv6_t icmpv6;
    ns_t ns;
    na_t na;
}

struct metadata {
    bit<32> meter_tag;
    bit<1> should_drop;
    bit<1> flood_detected;
    bit<1> bypass_defense; // New field to indicate if defense mechanisms should be bypassed
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV6: parse_ipv6;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            ICMPV6: parse_icmpv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        transition select(hdr.icmpv6.type) {
            ICMPV6_NS: parse_ns;
            ICMPV6_NA: parse_na;
            default: accept;
        }
    }

    state parse_ns {
        packet.extract(hdr.ns);
        transition accept;
    }

    state parse_na {
        packet.extract(hdr.na);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

register<bit<32>>(1) drop_counter_reg;
register<bit<32>>(1) total_packet_counter_reg;
register<bit<32>>(1024) bloom_filter;
register<bit<32>>(1024) cms0;
register<bit<32>>(1024) cms1;
register<bit<32>>(1024) cms2;
register<bit<32>>(1024) timestamp0;
register<bit<32>>(1024) timestamp1;
register<bit<32>>(1024) timestamp2;
register<bit<32>>(1) last_packet_time; // Register to track the last packet timestamp
register<bit<32>>(1) icmpv6_counter_reg; // Register for ICMPv6 packet counter

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        bit<32> drop_counter_val;
        drop_counter_reg.read(drop_counter_val, 0);
        drop_counter_val = drop_counter_val + 1;
        drop_counter_reg.write(0, drop_counter_val);
        meta.should_drop = 1;
        mark_to_drop(standard_metadata);
    }

    action ipv6_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
    }

    action increment_cms(bit<32> hash1, bit<32> hash2, bit<32> hash3, bit<32> val1, bit<32> val2, bit<32> val3) {
        cms0.write(hash1, val1 + 1);
        cms1.write(hash2, val2 + 1);
        cms2.write(hash3, val3 + 1);
    }

    action update_timestamps(bit<32> hash1, bit<32> hash2, bit<32> hash3, bit<32> current_time) {
        timestamp0.write(hash1, current_time);
        timestamp1.write(hash2, current_time);
        timestamp2.write(hash3, current_time);
    }

    action jenkins_hash(in bit<128> key, out bit<32> hash1, out bit<32> hash2, out bit<32> hash3) {
        bit<32> h = 0;
        bit<32> temp = (bit<32>)key;

        h = h + temp;
        h = h + (h << 10);
        h = h ^ (h >> 6);
        hash1 = h % 1024;

        h = h + (h << 3);
        h = h ^ (h >> 11);
        hash2 = h % 1024;

        h = h + (h << 15);
        hash3 = h % 1024;
    }

    action increment_icmpv6_counter() {
        bit<32> icmpv6_counter_val;
        icmpv6_counter_reg.read(icmpv6_counter_val, 0);
        icmpv6_counter_val = icmpv6_counter_val + 1;
        icmpv6_counter_reg.write(0, icmpv6_counter_val);
    }

    table ipv6_lpm {
        key = {
            hdr.ipv6.dstAddr: lpm;
        }
        actions = {
            ipv6_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        bit<32> current_time = (bit<32>)standard_metadata.ingress_global_timestamp;
        bit<32> last_time;
        last_packet_time.read(last_time, 0);

        // Increment total packet counter
        bit<32> total_packet_counter_val;
        total_packet_counter_reg.read(total_packet_counter_val, 0);
        total_packet_counter_val = total_packet_counter_val + 1;
        total_packet_counter_reg.write(0, total_packet_counter_val);

        // Initialize should_drop
        meta.should_drop = 0;

        // Check if more than 100 seconds (100,000,000 microseconds) have passed since the last packet
        if (current_time - last_time > 100000000) { // 100 seconds in microseconds
            // Update last packet time and set bypass flag
            last_packet_time.write(0, current_time);
            meta.bypass_defense = 1;
        } else {
            // Update last packet time
            last_packet_time.write(0, current_time);
            meta.bypass_defense = 0;
        }

        // Drop mDNS packets
        if (hdr.ipv6.isValid() && hdr.udp.isValid() && hdr.udp.dstPort == UDP_PORT_MDNS) {
            drop();
            return;
        }

        if (hdr.ipv6.isValid() && hdr.ipv6.nextHdr == ICMPV6) {
            increment_icmpv6_counter(); // Increment ICMPv6 packet counter

            bit<32> hash1;
            bit<32> hash2;
            bit<32> hash3;
            bit<32> bf_val1;
            bit<32> bf_val2;
            bit<32> bf_val3;

            if (hdr.icmpv6.type == ICMPV6_NS) {
                jenkins_hash(hdr.ns.targetAddr, hash1, hash2, hash3);
            } else if (hdr.icmpv6.type == ICMPV6_NA) {
                jenkins_hash(hdr.na.targetAddr, hash1, hash2, hash3);
            } else {
                jenkins_hash(hdr.ipv6.dstAddr, hash1, hash2, hash3);
            }

            bloom_filter.read(bf_val1, hash1);
            bloom_filter.read(bf_val2, hash2);
            bloom_filter.read(bf_val3, hash3);

            if (bf_val1 == 0 && bf_val2 == 0 && bf_val3 == 0) {
                // First time seeing this element
                bloom_filter.write(hash1, 1);
                bloom_filter.write(hash2, 1);
                bloom_filter.write(hash3, 1);
            } else {
                // Seen before, perform further checks
                bit<32> last_time1;
                bit<32> last_time2;
                bit<32> last_time3;
                timestamp0.read(last_time1, hash1);
                timestamp1.read(last_time2, hash2);
                timestamp2.read(last_time3, hash3);

                // Check intervals between packets (60 seconds in microseconds)
                if ((current_time - last_time1) < 60000000 ||
                    (current_time - last_time2) < 60000000 ||
                    (current_time - last_time3) < 60000000) {
                    drop();
                } else {
                    update_timestamps(hash1, hash2, hash3, current_time);
                }

                bit<32> cms_val1;
                bit<32> cms_val2;
                bit<32> cms_val3;
                cms0.read(cms_val1, hash1);
                cms1.read(cms_val2, hash2);
                cms2.read(cms_val3, hash3);

                bit<32> min_val = (cms_val1 < cms_val2) ? (cms_val1 < cms_val3 ? cms_val1 : cms_val3) : (cms_val2 < cms_val3 ? cms_val2 : cms_val3);
                if (min_val > 100) { // Example threshold
                    drop();
                } else {
                    increment_cms(hash1, hash2, hash3, cms_val1, cms_val2, cms_val3);
                }
            }

            if (meta.should_drop == 1) {
                return; // Stop further processing and drop the packet
            }
        }

        if (hdr.ipv6.isValid()) {
            ipv6_lpm.apply(); // Apply the IPv6 forwarding table
        }

        if (meta.should_drop == 1) {
            drop(); // Drop the packet if should_drop is set
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.icmpv6);
        packet.emit(hdr.udp); // Make sure to emit the UDP header
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;

