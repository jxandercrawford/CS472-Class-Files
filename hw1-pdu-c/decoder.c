#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include "packet.h"
#include "nethelper.h"
#include "decoder.h"

//This is where you will be putting your captured network frames for testing.
//Before you do your own, please test with the ones that I provided as samples:
#include "testframes.h"

//You can update this array as you add and remove test cases, you can
//also comment out all but one of them to isolate your testing. This
//allows us to loop over all of the test cases.  Note MAKE_PACKET creates
//a test_packet_t element for each sample, this allows us to get and use
//the packet length, which will be helpful later.
test_packet_t TEST_CASES[] = {
    MAKE_PACKET(raw_packet_icmp_frame198),
    MAKE_PACKET(raw_packet_icmp_frame362),
    MAKE_PACKET(raw_packet_arp_frame78),
    MAKE_PACKET(raw_packet_arp_frame71133),
    MAKE_PACKET(raw_packet_arp_frame77487),
    MAKE_PACKET(raw_packet_icmp_frame89526),
    MAKE_PACKET(raw_packet_fake)
};

int main(int argc, char **argv) {
    //This code is here as a refresher on how to figure out how
    //many elements are in a statically defined C array. Note
    //that sizeof(TEST_CASES) is not 3, its the total number of 
    //bytes.  On my machine it comes back with 48, because each
    //element is of type test_packet_t which on my machine is 16 bytes.
    //Thus, with the scaffold I am providing 48/16 = 3, which is
    //the correct size.  
    int num_test_cases = sizeof(TEST_CASES) / sizeof(test_packet_t);

    printf("STARTING...");
    for (int i = 0; i < num_test_cases; i++) {
        printf("\n--------------------------------------------------\n");
        printf("TESTING A NEW PACKET\n");
        printf("--------------------------------------------------\n");
        test_packet_t test_case = TEST_CASES[i];

        decode_raw_packet(test_case.raw_packet, test_case.packet_len);
    }

    printf("\nDONE\n");
}

void decode_raw_packet(uint8_t *packet, uint64_t packet_len){

    printf("Packet length = %ld bytes\n", packet_len);

    //Everything we are doing starts with the ethernet PDU at the
    //front.  The below code projects an ethernet_pdu structure 
    //POINTER onto the front of the buffer so we can decode it.
    struct ether_pdu *p = (struct ether_pdu *)packet;
    uint16_t ft = ntohs(p->frame_type);

    printf("Detected raw frame type from ethernet header: 0x%x\n", ft);

    switch(ft) {
        case ARP_PTYPE:
            printf("Packet type = ARP\n");

            //Lets process the ARP packet, convert all of the network byte order
            //fields to host machine byte order
            arp_packet_t *arp = process_arp(packet);

            //Print the arp packet
            print_arp(arp);
            break;
        case IP4_PTYPE:
            printf("Frame type = IPv4, now lets check for ICMP...\n");

            //We know its IP, so lets type the raw packet as an IP packet
            ip_packet_t *ip = (ip_packet_t *)packet;

            //Now check the IP packet to see if its payload is an ICMP packet
            bool isICMP = check_ip_for_icmp(ip);
            if (!isICMP) {
                printf("ERROR: IP Packet is not ICMP\n");
                break;
            }

            //Now lets process the basic icmp packet, convert the network byte order 
            //fields to host byte order
            icmp_packet_t *icmp = process_icmp(ip);

            //Now lets look deeper and see if the icmp packet is actually an
            //ICMP ECHO packet?
            bool is_echo = is_icmp_echo(icmp);
            if (!is_echo) {
                printf("ERROR: We have an ICMP packet, but it is not of type echo\n");
                break;
            }

            //Now lets process the icmp_packet as an icmp_echo_packet, again processing
            //the network byte order fields
            icmp_echo_packet_t *icmp_echo_packet = process_icmp_echo(icmp);

            //The ICMP packet now has its network byte order fields
            //adjusted, lets print it
            print_icmp_echo(icmp_echo_packet);

            break;
    default:
        printf("UNKNOWN Frame type?\n");
    }
}

/********************************************************************************/
/*                       ARP PROTOCOL HANDLERS                                  */
/********************************************************************************/

/*
 *  Convert a known ARP packet from a `raw_packet_t` to a `arp_packet_t`.
 */
arp_packet_t *process_arp(raw_packet_t raw_packet) {
    
    arp_packet_t *arp_packet;
    arp_packet = (arp_packet_t *)raw_packet;

    // Convert to little endian from big endian.
    arp_packet->eth_hdr.frame_type = ntohs(arp_packet->eth_hdr.frame_type);
    arp_packet->arp_hdr.htype = ntohs(arp_packet->arp_hdr.htype);
    arp_packet->arp_hdr.op  = ntohs(arp_packet->arp_hdr.op);
    arp_packet->arp_hdr.ptype  = ntohs(arp_packet->arp_hdr.ptype);

    return arp_packet;
}

/*
 *  Print content and metadata of an ARP packet.
 */
void print_arp(arp_packet_t *arp){

    char spa[17], sha[18], tpa[17], tha[18];
    
    // Parse addresses into strings
    ip_toStr(arp->arp_hdr.spa, spa, sizeof(spa));
    ip_toStr(arp->arp_hdr.tpa, tpa, sizeof(tpa));
    mac_toStr(arp->arp_hdr.sha, sha, sizeof(sha));
    mac_toStr(arp->arp_hdr.tha, tha, sizeof(tha));

    printf("#--------------- ARP PACKET DETAILS ---------------#\n");
    printf("htype:        0x%04x\n", arp->arp_hdr.htype);
    printf("ptype:        0x%04x\n", arp->arp_hdr.ptype);
    printf("hlen:         %d\n", arp->arp_hdr.hlen);
    printf("plen:         %d\n", arp->arp_hdr.plen);
    printf("op:           %d ", arp->arp_hdr.op);
    
    // Print packet type
    if (arp->arp_hdr.op == ARP_REQ_OP)
        printf("(ARP REQUEST)");
    else if (arp->arp_hdr.op == ARP_RSP_OP)
        printf("(ARP RESPONSE)");
    printf("\n");
    printf("spa:          %s\n", spa);
    printf("sha:          %s\n", sha);
    printf("tpa:          %s\n", tpa);
    printf("tha:          %s\n", tha);
    printf("#--------------------------------------------------#\n");
}

/********************************************************************************/
/*                       ICMP PROTOCOL HANDLERS                                  */
/********************************************************************************/

/*
 *  Return true if `ip_packet_t` is a valid `icmp_packet_t`.
 */
bool check_ip_for_icmp(ip_packet_t *ip){
    return ip->ip_hdr.protocol == ICMP_PTYPE;
}

/*
 *  Convert a known `ip_packet_t` to a `icmp_packet_t`.
 */
icmp_packet_t *process_icmp(ip_packet_t *ip){
        
    icmp_packet_t *icmp_packet;
    icmp_packet = (icmp_packet_t *)ip;

    // Convert to little endian from big endian
    icmp_packet->icmp_hdr.checksum = ntohs(icmp_packet->icmp_hdr.checksum);
    icmp_packet->ip.eth_hdr.frame_type = ntohs(icmp_packet->ip.eth_hdr.frame_type);
    icmp_packet->ip.ip_hdr.flags_and_fragment_offset = ntohs(icmp_packet->ip.ip_hdr.flags_and_fragment_offset);
    icmp_packet->ip.ip_hdr.header_checksum = ntohs(icmp_packet->ip.ip_hdr.header_checksum);
    icmp_packet->ip.ip_hdr.identification = ntohs(icmp_packet->ip.ip_hdr.identification);
    icmp_packet->ip.ip_hdr.total_length = ntohs(icmp_packet->ip.ip_hdr.total_length);

    return icmp_packet;
}

/*
 *  Return true if `icmp_packet_t` is a valid `icmp_echo_packet_t`.
 */
bool is_icmp_echo(icmp_packet_t *icmp) {    
    return icmp->icmp_hdr.type == ICMP_ECHO_REQUEST | icmp->icmp_hdr.type == ICMP_ECHO_RESPONSE;
}

/*
 * Convert a known ICMP echo packet from an `icmp_packet_t` to an `icmp_echo_packet_t`.
 */
icmp_echo_packet_t *process_icmp_echo(icmp_packet_t *icmp){
    
    icmp_echo_packet_t *echo_packet;
    echo_packet = (icmp_echo_packet_t *)icmp;
    
    // Convert to little endian from big endian.
    echo_packet->icmp_echo_hdr.timestamp = ntohl(echo_packet->icmp_echo_hdr.timestamp);
    echo_packet->icmp_echo_hdr.timestamp_ms = ntohl(echo_packet->icmp_echo_hdr.timestamp_ms);
    echo_packet->ip.eth_hdr.frame_type = ntohs(echo_packet->ip.eth_hdr.frame_type);
    echo_packet->ip.ip_hdr.flags_and_fragment_offset = ntohs(echo_packet->ip.ip_hdr.flags_and_fragment_offset);
    echo_packet->ip.ip_hdr.header_checksum = ntohs(echo_packet->ip.ip_hdr.header_checksum);
    echo_packet->ip.ip_hdr.identification = ntohs(echo_packet->ip.ip_hdr.identification);
    echo_packet->ip.ip_hdr.total_length = ntohs(echo_packet->ip.ip_hdr.total_length);
    
    return echo_packet;
}

/*
 * Print content and metadata of an ICMP echo packet.
 */
void print_icmp_echo(icmp_echo_packet_t *icmp_packet){

    uint16_t payload_size = ICMP_Payload_Size(icmp_packet);

    printf("#------------ ICMP ECHO PACKET DETAILS ------------#\n");
    printf("type:        0x%02x\n", icmp_packet->icmp_echo_hdr.icmp_hdr.type);
    printf("checksum:    0x%04x\n", icmp_packet->icmp_echo_hdr.icmp_hdr.checksum);
    printf("id:          0x%04x\n", icmp_packet->icmp_echo_hdr.id);
    printf("sequence:    0x%04x\n", icmp_packet->icmp_echo_hdr.sequence);
    printf("timestamp:   0x%lx%lx\n", icmp_packet->icmp_echo_hdr.timestamp, icmp_packet->icmp_echo_hdr.timestamp_ms);
    printf("payload:     %d bytes\n", payload_size);
    printf("ECHO Timestamp: TS = %s\n\n", get_ts_formatted(icmp_packet->icmp_echo_hdr.timestamp, icmp_packet->icmp_echo_hdr.timestamp_ms));
    print_icmp_payload(icmp_packet->icmp_payload, payload_size);
    printf("#--------------------------------------------------#\n");
}


/*
 * Hexdump a payload. Will print payload in hexadecimal values in rows of 8.
 */
void print_icmp_payload(uint8_t *payload, uint16_t payload_size) {
    uint8_t line_len;
    uint16_t i;

    line_len = 8;
    i = 0;

    // Loop over payload
    while (i < payload_size) {

        // Add new line if at line_len
        if (i > 0 && i % line_len == 0)
            printf("\n");

        printf("0x%02x ", payload[i++]);
    }
    printf("\n");
}
