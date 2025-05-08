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
    bit<48> interarrival_avg;
    bit<48> num_packets;
    bit<8> malicious_packet_flag;
}

header saved_fields_t {
    bit<32> last_src_addr;
    bit<16> last_checksum;
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

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    interarrival_t interarrival;
    saved_fields_t saved_fields;
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
        transition parse_saved_fields;
    }

    state parse_saved_fields {
        packet.extract(hdr.saved_fields);
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
    bit<16> flow_id; //for each flow going through switch, in our case usually just one
    register<bit<48>>(65535) last_timestamp_reg;
    register<bit<48>>(65535) num_packets_reg;
    register<bit<48>>(65535) rolling_avg_reg;
    register<bit<32>>(65535) last_ipv4_src_reg;
    register<bit<16>>(65535) last_ipv4_hdr_checksum_reg;
    bit<32> last_src_addr;
    bit<16> last_checksum;
    bit<48> interarrival_value;
    bit<48> num_packets;
    bit<48> rolling_avg;
    bit<48> rolling_stdev;
    bit<8> malicious_flag;
    bit<48> threshold;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action compute_flow_id(){ //differentiate the flows for register tracking
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

    action get_recent_header (){
        bit<32> current_src_addr;
        bit<16> current_checksum;
        last_ipv4_src_reg.read(last_src_addr, (bit<32>)flow_id);
        last_ipv4_hdr_checksum_reg.read(last_checksum, (bit<32>)flow_id);
        current_src_addr = hdr.ipv4.srcAddr;
        current_checksum = hdr.ipv4.hdrChecksum;
        if(num_packets != 1){
            //malicious_flag = 1;
            if(current_checksum != last_checksum){
                malicious_flag = 1;
                current_src_addr = last_src_addr;
                current_checksum = last_checksum;
            }
        }
        // add other conditionals for any field you expect to stay consistent
        last_ipv4_src_reg.write((bit<32>)flow_id, current_src_addr);
        last_ipv4_hdr_checksum_reg.write((bit<32>)flow_id, current_checksum);
    } 

    action get_interarrival_time () {
        bit<48> last_timestamp;
        bit<48> current_timestamp;
        bit<48> last_avg;
        bit<48> last_stdev;
        last_timestamp_reg.read(last_timestamp, (bit<32>)flow_id);
        rolling_avg_reg.read(last_avg, (bit<32>)flow_id);
        num_packets_reg.read(num_packets, (bit<32>)flow_id);
        current_timestamp = standard_metadata.ingress_global_timestamp;

        num_packets = num_packets + 1;

        if(last_timestamp != 0){
            interarrival_value = current_timestamp - last_timestamp;
        } else {
            interarrival_value = 0;
        }
        //determine avg
        int<48> diff;
        diff = ((int<48>) interarrival_value) - ((int<48>) last_avg);
        diff = diff >> 6; //modify old avg by most only significant bits of new avg
        rolling_avg = last_avg + (bit<48>) diff;
        if(last_avg == 0){
            rolling_avg = interarrival_value;
        }
        malicious_flag = 0;
        if(num_packets > 10){
            if(interarrival_value > (rolling_avg + (rolling_avg >> 3))){ //this threshold value should be based on something more concrete
                malicious_flag = 1;
                //discount packet value from average
                rolling_avg = last_avg;
            }
        }
        last_timestamp_reg.write((bit<32>)flow_id, current_timestamp);
        num_packets_reg.write((bit<32>)flow_id, num_packets);
        rolling_avg_reg.write((bit<32>)flow_id, rolling_avg);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        packet_ctr.count((bit<32>) 1);
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
            //get_recent_header();
            hdr.interarrival.interarrival_value = interarrival_value;
            hdr.interarrival.interarrival_avg = rolling_avg;
            hdr.interarrival.num_packets = num_packets;
            hdr.interarrival.malicious_packet_flag = malicious_flag;
            hdr.saved_fields.last_src_addr = last_src_addr;
            hdr.saved_fields.last_checksum = last_checksum;
        }
        ipv4_lpm.apply();
        
        // Clone the packet using session ID 100
        //clone_packet();
    }
}

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {}
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
        packet.emit(hdr.saved_fields);
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
