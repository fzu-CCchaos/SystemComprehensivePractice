/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP=0x0806; //ARP对应的TYPE是0x0806


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
//添加的arp_t报头
header arp_t{
	bit<16> hardware_type;//硬件地址
	bit<16> protocol_type;//协议类型
	bit<8> hardware_size;//硬件地址长度
	bit<8> protocol_size;//协议长度
	bit<16> op;//操作类型，ARP 请求为 1，ARP 响应为 2
	macAddr_t sendermac;//发送方MAC地址
	ip4Addr_t senderip;//发送方IP地址
	macAddr_t targetmac;//目标MAC地址
	ip4Addr_t targetip;//目标IP地址
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    arp_t arp;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start{
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: ipv4_parser;
            TYPE_ARP:arp_parser;//发现是ARP类型，转到arp_parser状态
            default: accept;
            //如果是其他值，默认接受
        }
    }
    state ipv4_parser{//ipv4解析部分
        packet.extract(hdr.ipv4);//取出ipv4包头
        transition accept;
    }
    state arp_parser{
        packet.extract(hdr.arp);//提取headers中的arp字段
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
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
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

    action arp_reply(macAddr_t macAddr,ip4Addr_t IPAddr){
        hdr.ethernet.dstAddr=hdr.arp.sendermac;//发送方的mac地址是目的地址
        hdr.ethernet.srcAddr=macAddr;
        hdr.arp.op=2;//arp报文的类型是回应类型，对应的op值是2
        hdr.arp.targetmac=hdr.arp.sendermac;
        hdr.arp.targetip=hdr.arp.senderip;
        //因为是回应报文，目标mac和ip就是原本发送方的mac和ip
        hdr.arp.sendermac=macAddr;
        hdr.arp.senderip=IPAddr;
        //从入端口转发出去
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }
    table arp_table{
        key={
        	hdr.arp.op:exact;
        	hdr.arp.targetip:lpm;
        }
        actions={
        	arp_reply;
        	drop;
        	NoAction;
        }
        default_action=drop();
    }
    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
        else if(hdr.ethernet.etherType==TYPE_ARP){
            arp_table.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
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
        packet.emit(hdr.arp);//发送arp数据包头
        packet.emit(hdr.ipv4);
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
