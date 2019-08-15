/* Copyright (c) 2019 Baidu, Inc. All Rights Reserved.

* Bce-ttm is free software; you can redistribute it and/or modify it under the terms of 
* the GNU General Public License as published by the Free Software Foundation; 
* either version 2 of the License, or (at your option) any later version.

* Bce-ttm is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
* without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
* See the GNU General Public License for more details.

* You should have received a copy of the GNU General Public License along with bce-ttm; 
* if not, see <http://www.gnu.org/licenses/>.

* Authors: Yi,Xiayu
*/


/* Simple TCP test                                      */
/*compile: gcc ttm_test.c -o ttm_test -lpcap            */
/* Run as root!                                         */

#include <netinet/ip.h>  
#define __FAVOR_BSD           /* Using BSD TCP header   */ 
#include <netinet/tcp.h>  
#include <pcap.h>         /* libpcap*/ 
#include <string.h>       
#include <stdlib.h>       
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define TCPTTM_LEN (8)
#define ETH_LEN (14)
#define MAX_CAPTURE_SIZE_BYTES (2048)
#define TCPOPT_TTM (254)

/* Pseudoheader (Used to compute TCP checksum. Check RFC 793) */
typedef struct pseudoheader {
    u_int32_t src;
    u_int32_t dst;
    u_char zero;
    u_char protocol;
    u_int16_t tcplen;
} tcp_phdr_t;

struct ttm_data {
    u_char opcode;
    u_char opsize;
    u_int16_t port;
    u_int32_t ip;
};

typedef unsigned short u_int16;
typedef unsigned long u_int32;


int ttm_packet_send(u_int32 seq, u_int32 ack_seq, int flags, u_int16 src_portt, u_int16 ip_id);
u_int16 ttm_check_sum(u_int16 *data,u_int32 len);

u_int16 g_dst_port = 80;
u_int32 g_send_packet_count = 0;
u_char g_verbose = 0;
u_char g_tcpopt_ttm = TCPOPT_TTM;
u_char g_src_addr[1024];
u_char g_dst_addr[1024];

int ttm_packet_send(u_int32 seq, u_int32 ack_seq, int flags, u_int16 src_port, u_int16 ip_id)
{
    u_int32 src_ip = inet_addr(g_src_addr);
    u_int32 dst_ip = inet_addr(g_dst_addr);
    u_int16 dst_port = ntohs(g_dst_port);
    int on=1; /* this variable for the setsockopt call */ 

    /* Raw socket file descriptor */ 
    int rawsocket=0;  

    /* Buffer for the TCP/IP SYN Packets */
    char packet[ sizeof(struct tcphdr) + sizeof(struct ip) + TCPTTM_LEN];   

    /* It will point to start of the packet buffer */  
    struct ip *ipheader = (struct ip *)packet;   

    /* It will point to the end of the IP header in packet buffer */  
    struct tcphdr *tcpheader = (struct tcphdr *) (packet + sizeof(struct ip)); 

    /* TPC Pseudoheader (used in checksum)    */
    tcp_phdr_t pseudohdr;            

    /* TCP Pseudoheader + TCP actual header used for computing the checksum */
    char tcpcsumblock[sizeof(tcp_phdr_t) + sizeof(struct ip) + TCPTTM_LEN];

    /* Although we are creating our own IP packet with the destination address */
    /* on it, the sendto() system call requires the sockaddr_in structure */
    struct sockaddr_in dstaddr;  

    memset(&pseudohdr,0,sizeof(tcp_phdr_t));
    memset(&packet, 0, sizeof(packet));
    memset(&dstaddr, 0, sizeof(dstaddr));   
    memset(tcpcsumblock, 0, sizeof(tcpcsumblock)); 

    src_port = ntohs(src_port);

    dstaddr.sin_family = AF_INET;     /* Address family: Internet protocols */
    dstaddr.sin_port = dst_port;      /* Leave it empty */
    dstaddr.sin_addr.s_addr = dst_ip; /* Destination IP */

    /* Get a raw socket to send TCP packets */   
    if ((rawsocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror("ttm_packet_send():socket()"); 
        exit(1);
    }

    /* We need to tell the kernel that we'll be adding our own IP header */
    /* Otherwise the kernel will create its own. The ugly "on" variable */
    /* is a bit obscure but R.Stevens says we have to do it this way ;-) */
    if (setsockopt(rawsocket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("ttm_packet_send():setsockopt()"); 
        exit(1);
    }

    /* IP Header */
    ipheader->ip_hl = 5;     /* Header lenght in octects                       */
    ipheader->ip_v = 4;      /* Ip protocol version (IPv4)                     */
    ipheader->ip_tos = 0;    /* Type of Service (Usually zero)                 */
    ipheader->ip_off = 0;    /* Fragment offset. We'll not use this            */
    ipheader->ip_ttl = 64;   /* Time to live: 64 in Linux, 128 in Windows...   */
    ipheader->ip_p = 6;      /* Transport layer prot. TCP=6, UDP=17, ICMP=1... */
    ipheader->ip_sum = 0;    /* Checksum. It has to be zero for the moment     */
    ipheader->ip_id = htons(ip_id); 
    ipheader->ip_src.s_addr = src_ip;  /* Source IP address                    */
    ipheader->ip_dst.s_addr = dst_ip;  /* Destination IP address               */

    /* TCP Header */   
    tcpheader->th_seq = htonl(seq);        /* Sequence Number                         */
    tcpheader->th_ack = htonl(ack_seq);   /* Acknowledgement Number                  */
    tcpheader->th_x2 = 0;           /* Variable in 4 byte blocks. (Deprecated) */
    tcpheader->th_flags = flags;
    tcpheader->th_win = htons(65535) ;/* Window size               */
    tcpheader->th_urp = 0;          /* Urgent pointer.                         */
    tcpheader->th_sport = src_port;  /* Source Port                             */
    tcpheader->th_dport = dst_port;  /* Destination Port                        */
    tcpheader->th_sum=0;            /* Checksum. (Zero until computed)         */

    if (flags & TH_ACK) {
        struct ttm_data ttm;
        struct ttm_data *pttm = (struct ttm_data *)(packet + sizeof(struct tcphdr) + sizeof(struct ip));
        ttm.opcode = g_tcpopt_ttm;
        ttm.opsize = TCPTTM_LEN;
        ttm.ip = inet_addr("192.168.16.19");
        ttm.port = htons(8055);
        memcpy(pttm, &ttm, sizeof(struct ttm_data));
        ipheader->ip_len = htons(sizeof (struct ip) + sizeof (struct tcphdr) + TCPTTM_LEN);  
        tcpheader->th_off = 7;      /* Segment offset (Lenght of the header)   */
        pseudohdr.tcplen = htons(sizeof(struct tcphdr) + TCPTTM_LEN);
        memcpy(tcpcsumblock+sizeof(tcp_phdr_t),tcpheader, sizeof(struct tcphdr) + TCPTTM_LEN);
    } else {
        ipheader->ip_len = htons(sizeof (struct ip) + sizeof (struct tcphdr));  
        tcpheader->th_off = 5;      /* Segment offset (Lenght of the header)   */
        pseudohdr.tcplen = htons(sizeof(struct tcphdr));
        memcpy(tcpcsumblock+sizeof(tcp_phdr_t),tcpheader, sizeof(struct tcphdr));
    }

    /* Fill the pseudoheader so we can compute the TCP checksum*/
    pseudohdr.src = ipheader->ip_src.s_addr;
    pseudohdr.dst = ipheader->ip_dst.s_addr;
    pseudohdr.zero = 0;
    pseudohdr.protocol = ipheader->ip_p;

    /* Copy header and pseudoheader to a buffer to compute the checksum */  
    memcpy(tcpcsumblock, &pseudohdr, sizeof(tcp_phdr_t));   
        
    /* Compute the TCP checksum as the standard says (RFC 793) */
    tcpheader->th_sum = ttm_check_sum((unsigned short *)(tcpcsumblock), sizeof(tcpcsumblock));   

    /* Compute the IP checksum as the standard says (RFC 791) */
    ipheader->ip_sum = ttm_check_sum((unsigned short *)ipheader, sizeof(struct ip));

    /* Send it through the raw socket */    
    if (sendto(rawsocket, packet, ntohs(ipheader->ip_len), 0,
                    (struct sockaddr *) &dstaddr, sizeof (dstaddr)) < 0) {   
        return -1;                     
    }

    g_send_packet_count++;

    if (g_verbose) {
        printf("+-------------------------+\n");
        printf("Send %u Packets:\n", g_send_packet_count);
        printf("src: %s:%d\n", inet_ntoa(ipheader->ip_src), ntohs(tcpheader->th_sport));
        printf("dst: %s:%d\n", inet_ntoa(ipheader->ip_dst), ntohs(tcpheader->th_dport));
        printf("seq: %u\n", ntohl(tcpheader->th_seq));
        printf("ack seq: %u\n", ntohl(tcpheader->th_ack));
        printf("+-------------------------+\n\n");
    }

    close(rawsocket);

    return 0;  
  
} /* End of IP_Id_send() */


u_int16 ttm_check_sum(u_int16 *data, u_int32 len)
{
    u_int32 sum=0;
    u_int32 odd = len & 0x01;

    while ( len & 0xfffe) {
        sum += *data;
        data = (u_int16 *)((u_char *)data + 2);
        len -=2;
    }

    if (odd) {
        u_int16 tmp = ((*data)<<8)&0xff00;
        sum += tmp;
    }
    sum = (sum >>16) + (sum & 0xffff);
    sum += (sum >>16) ;

    return ~sum;
}


/* main(): Main function. Opens network interface for capture. Tells the kernel*/
/* to deliver packets with the ACK or SYN flags set. Prints information    */

int main(int argc, char *argv[] )
{
    bpf_u_int32 netaddr=0;            /* To Store network address               */ 
    bpf_u_int32	mask=0;               /* To Store network netmask               */ 
    struct bpf_program filter;        /* Place to store the BPF filter program  */ 
    char errbuf[PCAP_ERRBUF_SIZE];    /* Error buffer                           */ 
    pcap_t *pcap_handle = NULL;             /* Network interface handler              */ 
    struct pcap_pkthdr pkthdr;        /* Packet information (timestamp,size...) */ 
    const unsigned char *packet=NULL; /* Received raw data                      */ 
    struct ip *iphdr = NULL;          /* IPv4 Header                            */
    struct tcphdr *tcphdr = NULL;     /* TCP Header                             */
    char *argcmd = "vhs:d:p:t:e:";
    char device[256] = {0};
    char filter_type[2048] = {0};
    u_int32 isn = 0;
    u_int32 seq_rcv = 0;
    int opt = 0;
    int recv_packet_count=0;
    u_int16 src_port = 0;
    u_int16 ip_id = 0;
    char src_addr_valid = 0;
    char dst_addr_valid = 0;
    char device_valid = 0;

    srand(time(NULL));
    memset(errbuf,0,PCAP_ERRBUF_SIZE);

    if (argc < 2) {
        fprintf(stderr, "Please enter the correct parameters, such as -e eth0 -s xxx.xxx.xxx.xxx -d xxx.xxx.xxx.xxx\n");
        exit(1);
    }

    while ((opt = getopt(argc, argv, argcmd))!= -1) {
        switch (opt) {
        case 'h':
            printf("+-------------------------+\n");
            printf("./ttm_test -e eth0 -s xxx.xxx.xxx.xxx -d xxx.xxx.xxx.xxx -p 80 -t 254\n");
            printf("-e: the network device\n");
            printf("-s: the source ip address\n");			
            printf("-d: the destination ip address\n");
            printf("-p: the destination port number, the default value is 80\n");
            printf("-t: tcp option kind type of ttm, the default value is 254\n");
            printf("-v: print send or receive packet details\n");
            printf("+-------------------------+\n");
            exit(0);
        case 's':
            strncpy(g_src_addr, optarg, 512);
            src_addr_valid =1;
            break;
        case 'd':
            strncpy(g_dst_addr, optarg, 512);
            dst_addr_valid = 1;
            break;  
        case 'p':
            g_dst_port = (u_int16)atoi(optarg);  
            break;
        case 't': 		
            g_tcpopt_ttm = (u_char)atoi(optarg);
            break; 
        case 'e':
            strncpy(device, optarg, 128);
            device_valid = 1;
            break;
        case 'v':
            g_verbose = 1;
        default:
            break;
        }

    } 

    if (dst_addr_valid == 0 || src_addr_valid == 0 || device_valid == 0) {
        printf("please input valid address, such as -e eth0 -s xxx.xxx.xxx.xxx -d xxx.xxx.xxx.xxx\n");
        exit(1);
    }

    printf("+-------------------------+\n");
    printf("source ip address is %s\n", g_src_addr);
    printf("destination ip address is %s\n", g_dst_addr);     
    printf("destination port number is %d\n", g_dst_port);
    printf("the ttm tcp option kind value is %d\n", g_tcpopt_ttm);
    printf("+-------------------------+\n\n");

    /* Open network device for packet capture */ 
    pcap_handle = pcap_open_live(device, MAX_CAPTURE_SIZE_BYTES, 1,  512, errbuf);
    if (pcap_handle==NULL) {
        fprintf(stderr, "pcap_open_live(): %s \n", errbuf);
        exit(1);
    }

    /* Look up info from the capture device. */ 
    if (pcap_lookupnet(device , &netaddr, &mask, errbuf) == -1 ) { 
        fprintf(stderr, "ERROR: pcap_lookupnet(): %s\n", errbuf );
        exit(1);
    }

    sprintf(filter_type,"(src host %s)", g_dst_addr);
    //printf("filter type is %s\n", filter_type);
    /* Compiles the filter expression into a BPF filter program */
    if (pcap_compile(pcap_handle, &filter, filter_type, 1, mask) == -1) {
        fprintf(stderr, "Error in pcap_compile(): %s\n", pcap_geterr(pcap_handle) );
        exit(1);
    }

    /* Load the filter program into the packet capture device. */ 
    if (pcap_setfilter(pcap_handle,&filter) == -1 ) {
        fprintf(stderr, "Error in pcap_setfilter(): %s\n", pcap_geterr(pcap_handle));
        exit(1);
    }

    isn = rand();
    src_port = rand() % 65535;
    ip_id = rand() % 65535;
    g_send_packet_count = 0;

    ttm_packet_send(isn, 0, TH_SYN, src_port, ip_id);

    /* Get one packet */
    if ((packet = pcap_next(pcap_handle,&pkthdr)) == NULL) {
        fprintf(stderr, "Error in pcap_next()\n", errbuf);
        exit(1);
    }

    iphdr = (struct ip *)(packet + ETH_LEN);
    tcphdr = (struct tcphdr *)(packet+ETH_LEN+sizeof(struct ip));

    if (g_verbose) {
        
        printf("+-------------------------+\n");		
        printf("Received %d Packets:\n", ++recv_packet_count);
        printf("src: %s:%d\n", inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport));
        printf("dst: %s:%d\n", inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport));
        printf("sequence: %u\n", ntohl(tcphdr->th_seq));
        printf("ack sequence: %ld\n", ntohl(tcphdr->th_ack)); 
        printf("+-------------------------+\n\n");
    }

    seq_rcv=ntohl(tcphdr->th_seq);

    ttm_packet_send(isn + 1, seq_rcv+1, TH_ACK, src_port, ip_id + g_send_packet_count);
    usleep(100000);
    ttm_packet_send(isn + 1, 0, TH_RST, src_port, ip_id + g_send_packet_count);

    pcap_close(pcap_handle);

    return 0;

    }

