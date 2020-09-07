#ifndef PROTOCOL_H
#define PROTOCOL_H

#endif // PROTOCOL_H
#include <arpa/inet.h>
#define ETHER_ADDR_LEN	6

/* Ethernet header */
   struct sniff_ethernet {
       u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
       u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
       u_short ether_type; /* IP? ARP? RARP? etc */
   };

   /* IP header */
   struct sniff_ip {
       u_int8_t ip_hl:4; /* header length */
       u_int8_t ip_v:4;       /* version */
       u_char ip_tos;		/* type of service */
       u_int16_t ip_len;		/* total length */
       u_short ip_id;		/* identification */
       u_short ip_off;		/* fragment offset field */
   #define IP_RF 0x8000		/* reserved fragment flag */
   #define IP_DF 0x4000		/* dont fragment flag */
   #define IP_MF 0x2000		/* more fragments flag */
   #define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
       u_char ip_ttl;		/* time to live */
       u_char ip_p;		/* protocol */
       u_short ip_sum;		/* checksum */
       in_addr ip_src,ip_dst; /* source and dest address */
   };

   /* TCP header */
   typedef u_int tcp_seq;

   struct sniff_tcp {
       u_short th_sport;	/* source port */
       u_short th_dport;	/* destination port */
       tcp_seq th_seq;		/* sequence number */
       tcp_seq th_ack;		/* acknowledgement number */
       u_char th_off:4;	/* data offset */
       u_char th_rsvd:4;
       u_char th_flags;
   #define TH_FIN 0x01
   #define TH_SYN 0x02
   #define TH_RST 0x04
   #define TH_PUSH 0x08
   #define TH_ACK 0x10
   #define TH_URG 0x20
   #define TH_ECE 0x40
   #define TH_CWR 0x80
   #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
       u_short th_win;		/* window */
       u_short th_sum;		/* checksum */
       u_short th_urp;		/* urgent pointer */
};

   /* UDP header */
struct sniff_udp {
        u_short udp_sport;               /* source port */
        u_short udp_dport;               /* destination port */
        u_short udp_hlen;		/* Udp header length*/
        u_short udp_chksum;		/* Udp Checksum */
    };

struct pcapList{
    in_addr addrA;
    u_short portA;
    in_addr addrB;
    u_short portB;
    int bytes;
    int packets;
    int packetsAtoB;
    int bytesAtoB;
    int packetsBtoA;
    int bytesBtoA;
    struct pcapList *link;
};

struct ListHeader{
    int length;
    pcapList *head;
    pcapList *tail;
};
