//Include the maths library
//#LINKFLAGS=-lm

/*
 * Copyright  (C) Matthew P. Grosvenor, 2012, All Rights Reserved
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <signal.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <ifaddrs.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>

#include "camio/istreams/camio_istream_log.h"
#include "camio/ostreams/camio_ostream_log.h"
#include "camio/istreams/camio_istream_netmap.h"
#include "camio/ostreams/camio_ostream_netmap.h"
#include "camio/options/camio_options.h"
#include "camio/camio_types.h"
#include "camio/camio_util.h"
#include "camio/camio_errors.h"

#include "qj_control.h"
#include "arp.h"


struct packet_gen_opt_t{
    char* iface;
    uint64_t len;
    uint64_t src_ip;
    uint64_t dst_ip;
    uint64_t dst_mac;
    uint64_t init_seq;
    int64_t num;
    int use_seq;
    double short_delay;
    double long_delay;
    char* clock;
    char* listener;
    char* selector;
    uint64_t burst;
    int64_t pid;
    uint64_t offset;
    int qj;
    uint64_t host;
    char* schedmode;
    size_t schedmode_e;
    uint64_t stop;
    int verbose;
    uint64_t timeout;
} options ;


//A single packed structure containing an entire packet laid out in memory
typedef struct{
    union{
        struct{
            uint64_t value[6];
        } __attribute__((__packed__)) raw;

        struct{
            uint8_t  dst_mac_raw[6];
            uint8_t  src_mac_raw[6];
            uint16_t eth_type;
            uint8_t  ihl        : 4;
            uint8_t  ver        : 4;
            uint8_t  ecn        : 2;
            uint8_t  dscp       : 6;
            uint16_t total_len;
            uint16_t id;
            uint16_t frag_off_flags;
            uint8_t  ttl;
            uint8_t  protocol;
            uint16_t hdr_csum;
            union{
                uint8_t src_ip_raw[4];
                uint32_t src_ip;
            };
            union{
                uint8_t dst_ip_raw[4];
                uint32_t dst_ip;
            };
            uint16_t src_port;
            uint16_t dst_port;
            uint16_t udp_len;
            uint16_t udp_csum;

        } __attribute__((__packed__)) unpack;

    };
} __attribute__((__packed__)) eth_ip_udp_head_t ;


arp_packet_t arp_packet;
uint64_t src_mac;

int source_hwaddr(const char *ifname, uint64_t* mac)
{
    struct ifaddrs *ifaphead, *ifap;
    int l = sizeof(ifap->ifa_name);

    if (getifaddrs(&ifaphead) != 0) {
        eprintf_exit_simple( "getifaddrs %s failed", ifname);
        return (-1);
    }

    for (ifap = ifaphead; ifap; ifap = ifap->ifa_next) {
        struct sockaddr_ll *sll = (struct sockaddr_ll *)ifap->ifa_addr;

        if (!sll || sll->sll_family != AF_PACKET){
            continue;
        }

        if (strncmp(ifap->ifa_name, ifname, l) != 0){
            continue;
        }

        memcpy(mac, sll->sll_addr, sizeof(uint64_t));
        char buf[256];
        sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", ((uint8_t*)mac)[0], ((uint8_t*)mac)[1], ((uint8_t*)mac)[2], ((uint8_t*)mac)[3], ((uint8_t*)mac)[4], ((uint8_t*)mac)[5]);
        printf("Source MAC address: %s\n",buf);
        break;
    }

    freeifaddrs(ifaphead);
    return ifap ? 0 : 1;
}

/* Compute the checksum of the given ip header. */
static uint16_t checksum(const void *data, uint16_t len, uint32_t sum)
{
    const uint8_t *addr = data;
    uint32_t i;

    /* Checksum all the pairs of bytes first... */
    for (i = 0; i < (len & ~1U); i += 2) {
        sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }
    /*
     * If there's a single byte left over, checksum it, too.
     * Network byte order is big-endian, so the remaining byte is
     * the high byte.
     */
    if (i < len) {
        sum += addr[i] << 8;
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }
    return sum;
}

static u_int16_t
wrapsum(u_int32_t sum)
{
    sum = ~sum & 0xFFFF;
    return (htons(sum));
}


void prepare_packet(char* iface, eth_ip_udp_head_t* packet, size_t len){
    //Get the source mac address
    uint64_t src_mac;
    source_hwaddr(iface,&src_mac);
    uint64_t dst_mac = options.dst_mac;
    uint64_t dst_mac_be =  (((dst_mac >> 0 * 8) & 0xFF) << (5 * 8)) +
            (((dst_mac >> 1 * 8) & 0xFF) << (4 * 8)) +
            (((dst_mac >> 2 * 8) & 0xFF) << (3 * 8)) +
            (((dst_mac >> 3 * 8) & 0xFF) << (2 * 8)) +
            (((dst_mac >> 4 * 8) & 0xFF) << (1 * 8)) +
            (((dst_mac >> 5 * 8) & 0xFF) << (0 * 8)) ;

    memcpy(packet->unpack.src_mac_raw,&src_mac,6);
    memcpy(packet->unpack.dst_mac_raw,&dst_mac_be,6);
    packet->unpack.eth_type         = htons(ETHERTYPE_IP);
    packet->unpack.ihl              = 5;
    packet->unpack.ver              = IPVERSION;
    packet->unpack.ecn              = 0;
    packet->unpack.dscp             = 0;
    packet->unpack.total_len        = htons(len - 14);
    packet->unpack.id               = 0;
    packet->unpack.frag_off_flags   = htons(IP_DF);
    packet->unpack.ttl              = MAXTTL;
    packet->unpack.protocol         = IPPROTO_UDP;
    packet->unpack.hdr_csum         = 0;
    packet->unpack.src_ip           = htonl(0x0A0A0000UL + options.src_ip);  //eg 10.10.0.x, x = 106
    packet->unpack.dst_ip           = htonl(0x0A0A0000UL + options.dst_ip);
    packet->unpack.hdr_csum         = wrapsum(checksum(&packet->unpack.eth_type + 1, 20, 0));
    packet->unpack.src_port         = htons(2000);
    packet->unpack.dst_port         = htons(2000);
    packet->unpack.udp_len          = htons(len - 14 - 20);
    packet->unpack.udp_csum         = 0x0000;
    printf("UDP Packet len=%lu\n", len - 14 - 20);
    printf("IP Packet len=%lu\n", len - 14);

    bzero(&packet->unpack.udp_csum + 1,len - 14 - 20);
    *((uint64_t*)(&packet->unpack.udp_csum + 1)) = options.init_seq;

}

uint64_t pppcount = 0;
uint64_t total_count = 0; 
void update_packet(eth_ip_udp_head_t* packet){
    if(likely(options.use_seq)){
        *((uint64_t*)(&packet->unpack.udp_csum + 1)) = pppcount;
    }
}


qj_packet go_packet;
struct timeval start, tic, toc, res;
camio_ostream_t* out = NULL;
camio_istream_t* listener = NULL;
camio_istream_t* qj = NULL;
size_t packet_len = 0;
void flush_and_close_netmap(){
    if(out){
        gettimeofday(&toc, NULL);
        timersub(&toc, &tic, &res);
        const uint64_t us = res.tv_sec * 1000 * 1000 + res.tv_usec;
        const double pps  = (double)pppcount / (double)us;
        const double gbps  = (double)pppcount * packet_len * 8 / (double)us;
        printf("Status: %08luus, %08lu packets, %lfMpps, %lfMbps\n", us, pppcount, pps, gbps );
        out->delete(out);
    }

}


void term(int signum){
    printf("Terminating...\n");
    flush_and_close_netmap();
    if(listener) { listener->delete(listener); }
    if(qj)     { qj->delete(qj); }
    exit(0);
}

static inline void delay(const uint64_t cycles ){
    uint64_t i = 0;
    for(; i < cycles; i++){
        __asm__ __volatile__("nop");
    }
}

static inline double get_delay_estimate(){
    return 0.8;

    //Spin for 1B cycles to get an idea of our cycles per-second (~bogomips)i
    const uint64_t test_cycles = 100 * 1000; 
    gettimeofday(&tic, NULL);
    delay( test_cycles );
    gettimeofday(&toc, NULL);

    //How fast?
    timersub(&toc, &tic, &res);
    const uint64_t ns = (res.tv_sec * 1000 * 1000 + res.tv_usec) * 1000;
    const double bogoipns = (test_cycles) / (double)ns;
    //printf("CPU is spinning at %lf cyles per nanosecond\n", bogoipns );
    return bogoipns;
}

//use with caution, this is very unsafe
void listen_for_cmnds(){
    printf("Listening for commands...\n");
    if(options.pid < 0){
        eprintf_exit_simple("Error, pid is not set.\n");
    }

    const size_t pid = options.pid;
    uint8_t* cmd_data = NULL;
    size_t len = 0;
    len = listener->start_read(listener,&cmd_data);
    printf("Processing now...\n");
    if(len == strlen("term") && strcmp((char*)cmd_data,"term") == 0){
        printf("Received the term command, exiting now");
        term(0);
    }

    //The list of commands in order that we want to listen to
    const size_t opts_count = 6;
    const size_t max_senders = 25; 
    uint64_t options_vals[opts_count * max_senders];
    options_vals[0 + opts_count * pid] = options.num;
    options_vals[1 + opts_count * pid] = options.len;
    options_vals[2 + opts_count * pid] = options.burst;
    options_vals[3 + opts_count * pid] = (uint64_t)options.short_delay;
    options_vals[4 + opts_count * pid] = (uint64_t)options.long_delay;
    options_vals[5 + opts_count * pid] = (uint64_t)options.offset;

    size_t i = 0;
    size_t opt_num = 0; 
    uint64_t* curr_opt = options_vals;
    curr_opt[opt_num] = 0; 
    for(; i < len && opt_num < opts_count * max_senders; i++){
        if(cmd_data[i] == ','){
            //printf("Option %lu decoded = %lu\n", opt_num,  curr_opt[opt_num]);
            opt_num++;
            curr_opt[opt_num] = 0;
            continue;
        }

        if(cmd_data[i] == '\0' || cmd_data[i] == '\n' || cmd_data[i] == '\r'){
            //printf("Option %lu decoded = %lu\n", opt_num,  curr_opt[opt_num]);
            break;
        }

        curr_opt[opt_num] *= 10;
        curr_opt[opt_num] += cmd_data[i] - '0';
    }

    listener->end_read(listener, NULL);

    printf("New options from listener:\n");

    options.num = options_vals[0 + opts_count * pid];
    printf("options.num=%lu\n", options.num);

    options.len = options_vals[1 + opts_count * pid];
    printf("options.len=%lu\n", options.len);

    options.burst = options_vals[2 + opts_count * pid];
    printf("options.burst=%lu\n", options.burst);

    options.short_delay = options_vals[3 + opts_count * pid];
    printf("options.short_delay=%lf\n", options.short_delay);

    options.long_delay = options_vals[4 + opts_count * pid];
    printf("options.long_delay=%lf\n", options.long_delay);

    options.offset = options_vals[5 + opts_count * pid];
    printf("options.offset=%lu\n", options.offset);

}


static inline void wait_for_phys(){
    //Wait for PHYS to reinit after the netmap attach
    printf("Waiting for PHYs...\n");
    fflush(stdout);
    size_t i = 0;
    for(i = 0; i < 6; i++){
        sleep(1);
        printf(".");
        fflush(stdout);
    }

}




void init_arp_reply() {

    int i = 0;
    for(; i < 6; i++){
        arp_packet.dst_mac[i] = ~0; //Send to the broadcast MAC
        arp_packet.tha[i]     = ~0; //((uint8_t *)&src_mac)[i];
        arp_packet.sha[i]     = ((uint8_t *)&src_mac)[i];
        arp_packet.src_mac[i]  = ((uint8_t *)&src_mac)[i];
    }

    //Set the ethtype field
    arp_packet.eth_type = htons(0x0806);

    arp_packet.htype = htons(1); //Ethernet
    arp_packet.ptype = htons(0x0800); //Ethernet
    arp_packet.plen  = 4;
    arp_packet.hlen  = 6;
    arp_packet.oper  = htons(2); //1 = request, 2 = response
    arp_packet.spa   = htonl(0x0A0A0000UL + options.src_ip);  //eg 10.10.0.x, x = 106
    arp_packet.tpa   = htonl(0x0A0A0000UL + options.src_ip);  //eg 10.10.0.x, x = 106

}

void init_go_packet() {

    int i = 0;
    for(; i < 6; i++){
        go_packet.dst_mac[i] = ~0; //Send to the broadcast MAC
        go_packet.src_mac[i] = ((uint8_t *)&src_mac)[i];
    }

    //Set the ethtype field
    go_packet.ether_type = htons(0xFEED);
    go_packet.host_id    = options.host + 1; //Pass authority on to the next host.
    go_packet.seq        = 0; 

}



static inline void sync_to_clock(){
    struct timeval time_now;
    printf("Waiting for PHYs...");
    size_t i = 0;
    for(i = 0; i < 4; i++){
        sleep(1);
        printf(".");
        fflush(stdout);
    }
    printf("\n");

    //Tell the switch that we're here
    printf("Announcing our presence to the switch...");
    for(i = 0; i < 50; i++){
        init_arp_reply();
        out->assign_write(out,(uint8_t*)&arp_packet,sizeof(arp_packet_t));
        out->end_write(out,sizeof(arp_packet_t));
        out->flush(out);
        printf(".");
        fflush(stdout);
        usleep(10 * 1000);
    }
    printf("\n");


    printf("Syncronising...\n");
    while(1){
        gettimeofday(&time_now, NULL);
        const uint64_t ms = (time_now.tv_sec * 1000 * 1000 + time_now.tv_usec) / 1000;
        //printf("ms=%lu\n",ms);
        if(ms % (6 * 1000) == 0){
            break;
        }
    }
}



static inline int read_qj(int qj_stop){
    //size_t qj_len;
    uint8_t* qj_data;

    //qj_len = 
    qj->start_read(qj,&qj_data);
    //printf("Read message of %lu\n", qj_len);
    const qj_packet* go_stop = (qj_packet*)qj_data;
    if(go_stop->ether_type == htons(0xFEED)){
        if(go_stop->host_id == options.host){
            if(options.verbose) printf("Starting...[%lu == %lu]\n", go_stop->host_id, options.host );
            qj_stop = 0;
        }
        else{
            if(options.verbose) printf("Stopping...[%lu != %lu]\n", go_stop->host_id, options.host );
            qj_stop = 1;
        }
    }
    qj->end_read(qj,NULL);

    return qj_stop;
}



enum { C3PO_SCHED_NONE = 0, C3PO_SCHED_TDMA, C3PO_SCHED_YIELD, C3PO_SCHED_MAXMIN, };

int main(int argc, char** argv){

    signal(SIGTERM, term);
    signal(SIGINT, term);

    camio_options_short_description("packet_gen");
    camio_options_add(CAMIO_OPTION_REQUIRED, 'i', "interface", "Interface name to generate packets on eg eth0", CAMIO_STRING, &options.iface, "");
    camio_options_add(CAMIO_OPTION_REQUIRED, 's', "src",       "Source trailing IP number eg 106 for 10.10.0.106 ", CAMIO_UINT64, &options.src_ip, 0);
    camio_options_add(CAMIO_OPTION_REQUIRED, 'm', "mac",       "Destination MAC address number as a hex string eg 0x90E2BA27FBE0", CAMIO_UINT64, &options.dst_mac, 0);
    camio_options_add(CAMIO_OPTION_REQUIRED, 'd', "dst",       "Destination trailing IP number eg 112 for 10.10.0.102", CAMIO_UINT64, &options.dst_ip, 0);
    camio_options_add(CAMIO_OPTION_OPTIONAL, 'n', "num-pkts",  "Number of packets to send before stopping. -1=inf [-1]", CAMIO_INT64, &options.num, -1);
    camio_options_add(CAMIO_OPTION_OPTIONAL, 'I', "init-seq",  "Initial sequence number to use [0]", CAMIO_UINT64, &options.init_seq, 0);
    camio_options_add(CAMIO_OPTION_OPTIONAL, 'D', "delay",     "How long to delay in between sending individual packets. [0]", CAMIO_DOUBLE, &options.short_delay, 0 );
    camio_options_add(CAMIO_OPTION_OPTIONAL, 'W', "wait",      "How long to delay in nanoseconds. between sending bursts [0]", CAMIO_DOUBLE, &options.long_delay, 0 );
    camio_options_add(CAMIO_OPTION_OPTIONAL, 'l', "length",    "Length of the entire packet in bytes [1514]", CAMIO_UINT64, &options.len, 1514 );
    camio_options_add(CAMIO_OPTION_OPTIONAL, 'L', "listener",  "Description of a command lister eg udp:192.168.0.1:2000 [NULL]", CAMIO_STRING, &options.listener, "" );
    camio_options_add(CAMIO_OPTION_OPTIONAL, 'p', "pid",       "Packet generator ID. Which messages to listen to.", CAMIO_INT64, &options.pid, -1);
    camio_options_add(CAMIO_OPTION_OPTIONAL, 'u', "use-seq",   "Use sequence numbers in packets [true]", CAMIO_BOOL, &options.use_seq, 1);
    camio_options_add(CAMIO_OPTION_OPTIONAL, 'b', "burst",     "How many packets to send in each burst [0]", CAMIO_UINT64, &options.burst, 0 );
    camio_options_add(CAMIO_OPTION_OPTIONAL, 'o', "offset",    "How long in microseconds to sleep before beginning to send", CAMIO_UINT64, &options.offset, 0 );
    camio_options_add(CAMIO_OPTION_FLAG,     'R', "qj",      "R2D2 mode. Listen for R2D2 halt messages", CAMIO_BOOL, &options.qj, 0 );
    camio_options_add(CAMIO_OPTION_FLAG,     'V', "verbose",   "Verbose output messages", CAMIO_BOOL, &options.verbose, 0 );
    camio_options_add(CAMIO_OPTION_OPTIONAL, 'H', "host-id",   "R2D2 host id when in R2D2 mode", CAMIO_UINT64, &options.host, 0 );
    camio_options_add(CAMIO_OPTION_OPTIONAL, 'M', "schedmode", "R2D2 scheduling mode when in R2D2 mode; options {none, tdma, yield, maxmin} [tdma]", CAMIO_STRING, &options.schedmode, "none" );
    camio_options_add(CAMIO_OPTION_OPTIONAL, 't', "timeout",   "time to run for [60s]", CAMIO_UINT64, &options.timeout, 3* 60 * 1000 * 1000 * 1000ULL );
    camio_options_add(CAMIO_OPTION_OPTIONAL, 'S', "stop",      "How many packets to send before stopping for a break [0]", CAMIO_UINT64, &options.stop, 0 );

    camio_options_long_description("Generates packets using netmap at up to linerate for all packet sizes.");
    camio_options_parse(argc, argv);
    source_hwaddr(options.iface,&src_mac);


    printf(" **************************************************************\n" ); 
    printf(" ********************** Host ID == %lu **************************\n", options.host); 
    printf(" **************************************************************\n" ); 

    if(strcmp(options.schedmode, "none") == 0){
        options.schedmode_e = C3PO_SCHED_NONE;
    }
    else if(strcmp(options.schedmode, "tmda") == 0){
        options.schedmode_e = C3PO_SCHED_TDMA;
    }
    else if(strcmp(options.schedmode, "yield") == 0) {
        options.schedmode_e = C3PO_SCHED_YIELD;
    }
    else if(strcmp(options.schedmode, "minmax") == 0) {
        options.schedmode_e = C3PO_SCHED_MAXMIN;
    }
    printf("Setting sched mode to %s (%lu)\n", options.schedmode, options.schedmode_e);



    if(*options.listener != '\0'){
        listener = camio_istream_new(options.listener,NULL);
    }


    while(1){
        //Listen for remote commands if this is enabled
        if(*options.listener != '\0'){
            listen_for_cmnds();
        }

        if(options.num == 0){
            continue;
        }

        //Ready the output stream
        char nm_str[256];
        sprintf(nm_str,"nmap:%s",options.iface);
        camio_ostream_netmap_params_t params = {
                .nm_mem = NULL,
                .nm_mem_size = 0,
                .burst_size = options.burst,
        };
        out = camio_ostream_new(nm_str, &params);

        if(options.qj){
            camio_ostream_netmap_t* priv = out->priv;
            camio_istream_netmap_params_t i_params = {
                    .nm_mem       = priv->nm_mem,
                    .nm_mem_size  = priv->mem_size,
                    .fd           = out->fd,
            };
            qj = camio_istream_new(nm_str,&i_params);
        }

        //Prepare an intial packet
        uint8_t pbuff[2 * 1024];
        const size_t buff_len = 2 * 1024; //2kB
        eth_ip_udp_head_t* packet = (eth_ip_udp_head_t*)pbuff;
        bzero(pbuff, buff_len);
        packet_len = options.len; 
        packet_len = packet_len < 60 ? 60 : packet_len;
        packet_len = packet_len > 1514 ? 1514 : packet_len;
        prepare_packet(options.iface, packet,packet_len);

        init_go_packet();
        //        //Figure out the delay parameters
        double ipns = 0.8; //Instructions per nano second

        sync_to_clock();

        const size_t long_delay_cycles = llround(ipns * options.long_delay);
        printf("Long delaying for %lu cyles per packet (%lf nanos x %lf cycles/ns)\n", long_delay_cycles, options.long_delay, ipns);
        const size_t short_delay_cycles = llround(ipns * options.short_delay);
        printf("Short delaying for %lu cyles per packet (%lf nanos x %lf cycles/ns)\n", short_delay_cycles, options.short_delay, ipns);

        pppcount = 0;
        printf("\nNow generating %lu packets with len=%luB in burst size=%lu. Short delay=%lu, long delay=%lu, offset delay=%lu\n", options.num, packet_len, options.burst, short_delay_cycles, long_delay_cycles, options.offset );


        //Apply the offset
        if(options.offset){
            usleep(options.offset);
        }

        int qj_stop = 1;
        size_t bytes = 0;

        //Rock and roll,fast path begins here
        gettimeofday(&tic, NULL);
        gettimeofday(&start, NULL);
        while(1){
            if(unlikely(qj != NULL)){
                //printf("Waiting for go authority 1...\n");
                if(unlikely( qj->ready(qj) )){
                    qj_stop = read_qj(qj_stop);
                }
            }

            while(unlikely(qj && qj_stop)){
                //printf("Waiting for go authority...\n");
                qj_stop = read_qj(qj_stop);
            }
            //printf("Have auth to send...\n");


            if(unlikely(pppcount && pppcount % (5 * 1000 * 1000 ) == 0)){
                gettimeofday(&toc, NULL);
                timersub(&toc, &tic, &res);
                const uint64_t us = res.tv_sec * 1000 * 1000 + res.tv_usec;
                const double pps  = (double)pppcount / (double)us;
                const double gbps  = (double)bytes * 8 / (double)us;
                timersub(&toc, &start, &res);
                const uint64_t runtime = res.tv_sec * 1000 * 1000 + res.tv_usec;
                printf("Status: %08lums, %08luus, %08lu packets, %lfMpps, %lfMbps\n", runtime / 1000, us, total_count, pps, gbps );
                pppcount = 0;
                bytes    = 0;
                gettimeofday(&tic, NULL);
                if(options.timeout && (runtime > options.timeout)){
                    printf("Time limit exceeded.\n");
                    break;
                }

            }

            out->assign_write(out,(uint8_t*)packet, buff_len);
            out->end_write(out,packet_len);
            bytes += packet_len;

            if(options.stop && pppcount && (pppcount % options.stop == 0)){
                // Yield the slot as we've finished if we're in cooperative yielding mode
                if(options.schedmode_e == C3PO_SCHED_YIELD || options.schedmode_e == C3PO_SCHED_MAXMIN ){
                    printf("Sending stop message\n");
                    go_packet.seq++;  
                    out->assign_write(out, (uint8_t*)&go_packet, sizeof(go_packet));
                    out->end_write(out, sizeof(go_packet));
                    out->flush(out); //We're done so send this immediately
                    qj_stop = 1; 
                    printf("Sent %lu messages, stopping now\n", pppcount);
                    //        continue;
                }
            }

            if(options.burst && pppcount && (pppcount % options.burst == 0)){
                //Delay until we send again
                delay(long_delay_cycles);
            }

            pppcount++;
            total_count++;
            update_packet(packet);
            delay(short_delay_cycles);

            if(unlikely(options.num != -1 && pppcount >= options.num)){
                printf("Done outputting %lu packets\n", pppcount);
                break;
            }


        }

        if(options.listener == '\0'){
            term(0);
        }

        flush_and_close_netmap();
        out = NULL;
    }


    //Unreachable
    return 0;
}
