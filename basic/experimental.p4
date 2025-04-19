// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<48> rolling_average = 32;
const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header interarrival_t {
    bit<48> interarrival_value;
}

header metrics_t {
    bit<48> timestamp_delta;
    bit<48> avg_delta;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<3> res;
    bit<3> ecn;
    bit<6> ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    interarrival_t interarrival;
    metrics_t metrics;
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
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition parse_interarrival;
    }

    state parse_interarrival {
        packet.extract(hdr.interarrival);
        transition accept;
    }

    state parse_metrics {
        packet.extract(hdr.metrics);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    counter(32w1024, CounterType.packets) packet_ctr;
    bit<16> flow_id;
    register<bit<48>>(65535) last_timestamp_reg;
    bit<48> interarrival_value;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action compute_flow_id(){
        hash(
            flow_id,
            HashAlgorithm.crc16,
            (bit<1>)0,
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            (bit<16>)65535
        );
    }

    action get_interarrival_time () {
        bit<48> last_timestamp;
        bit<48> current_timestamp;
        last_timestamp_reg.read(last_timestamp, (bit<32>)flow_id);
        current_timestamp = standard_metadata.ingress_global_timestamp;

        if(last_timestamp != 0){
            interarrival_value = current_timestamp - last_timestamp;
        } else {
            interarrival_value = 0;
        }
        last_timestamp_reg.write((bit<32>)flow_id, current_timestamp);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        packet_ctr.count((bit<32>) 1);
        //hdr.metrics.setValid();
        //hdr.metrics.timestamp_delta = standard_metadata.ingress_global_timestamp - 1; //difference between leaving last port and arriving at this switch
    }

    action clone_packet() {
        clone(CloneType.I2E, 100); // Clone session ID is 100
    }



    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
    if (hdr.ipv4.isValid()) {
        if(hdr.interarrival.isValid()){
            compute_flow_id();
            get_interarrival_time();
            hdr.interarrival.interarrival_value = interarrival_value;
        }
        ipv4_lpm.apply();
        
        // Clone the packet using session ID 100
        clone_packet();
    }
}

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action modify (){
        hdr.metrics.timestamp_delta = standard_metadata.ingress_global_timestamp - 1; //difference between leaving last port and arriving at this switch
        hdr.metrics.avg_delta = rolling_average;
    }
    table modify_metrics {
        actions = {
            modify;
            NoAction;
        }
        size = 1;
        default_action = modify; //always executed since no key is involved
    }
    apply { 
        modify_metrics.apply();
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.interarrival);
        //packet.emit(hdr.metrics);
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
