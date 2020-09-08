#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "protocol.h"
#define eth_len 14 /* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

void init(ListHeader *list);
void TCP_analysis(const u_char* packet, ListHeader *tlist);
void UDP_analysis(const u_char* packet, ListHeader *ulist);
void printPackets(ListHeader plist);

void usage() {
    printf("syntax: pcap-analysis <pcapfile>\n");
    printf("sample: pcap-analysis file.pcap\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(dev,errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_offline(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }
    ListHeader tlist;
    ListHeader ulist;
    init(&tlist);
    init(&ulist);
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            // printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        struct sniff_ethernet *eth;
        struct sniff_ip *ip;
        eth = (struct sniff_ethernet *)packet;
        ip = (struct sniff_ip *)(packet+eth_len);
        if(ip->ip_p==6){
            TCP_analysis(packet,&tlist);
        }
        else if(ip->ip_p==17){
            UDP_analysis(packet,&ulist);
        }
    }
    printf("===========TCP===========\n");
    printPackets(tlist);
    printf("===========UDP===========\n");
    printPackets(ulist);


    pcap_close(handle);
}


void init(ListHeader *list){
    list->length=0;
    list->head=list->tail=NULL;
}
void TCP_analysis(const u_char* packet, ListHeader *tlist){
    struct sniff_ethernet *eth;
    struct sniff_ip *ip;
    struct sniff_tcp *tcp;
    eth = (struct sniff_ethernet *)packet;
    ip = (struct sniff_ip *)(packet+eth_len);
    int ip_size=ip->ip_hl*4;
    tcp= (struct sniff_tcp *)(packet+eth_len+ip_size);

    pcapList *p=tlist->head;
    bool is_in_list=false;
    while(p!=NULL){
        if((p->addrA.s_addr==ip->ip_src.s_addr)&&(p->addrB.s_addr==ip->ip_dst.s_addr)&&(p->portA==tcp->th_sport)&&(p->portB==tcp->th_dport)){
            p->packetsAtoB++;
            p->bytesAtoB+=ntohs(ip->ip_len)+eth_len;
            is_in_list=true;
            break;
        }
        if((p->addrB.s_addr==ip->ip_src.s_addr)&&(p->addrA.s_addr==ip->ip_dst.s_addr)&&(p->portB==tcp->th_sport)&&(p->portA==tcp->th_dport)){
            p->packetsBtoA++;
            p->bytesBtoA+=ntohs(ip->ip_len)+eth_len;
            is_in_list=true;
            break;
        }
        else{
            p=p->link;
        }
    }
    if(is_in_list){
        p->bytes=p->bytesAtoB+p->bytesBtoA;
        p->packets=p->packetsAtoB+p->packetsBtoA;
    }
    else{
        pcapList *temp=(pcapList *)malloc(sizeof(pcapList));
        temp->addrA=ip->ip_src;
        temp->addrB=ip->ip_dst;
        temp->portA=tcp->th_sport;
        temp->portB=tcp->th_dport;
        temp->packets=1;
        temp->bytesAtoB=ntohs(ip->ip_len)+eth_len;
        temp->bytes=temp->bytesAtoB;
        temp->packetsAtoB=1;
        temp->bytesBtoA=0;
        temp->packetsBtoA=0;
        if(tlist->tail==NULL){
            tlist->head=tlist->tail=temp;
        }
        else{
            tlist->tail->link=temp;
            tlist->tail=temp;
        }
        tlist->length++;
    }
}

void UDP_analysis(const u_char* packet, ListHeader *ulist){
    struct sniff_ethernet *eth;
    struct sniff_ip *ip;
    struct sniff_udp *udp;
    eth = (struct sniff_ethernet *)packet;
    ip = (struct sniff_ip *)(packet+eth_len);
    int ip_size=ip->ip_hl*4;
    udp= (struct sniff_udp *)(packet+eth_len+ip_size);

    pcapList *p=ulist->head;
    bool is_in_list=false;
    while(p!=NULL){
        if((p->addrA.s_addr==ip->ip_src.s_addr)&&(p->addrB.s_addr==ip->ip_dst.s_addr)&&(p->portA==udp->udp_sport)&&(p->portB==udp->udp_dport)){
            p->packetsAtoB++;
            p->bytesAtoB+=ntohs(ip->ip_len)+eth_len;
            is_in_list=true;
            break;
        }
        if((p->addrB.s_addr==ip->ip_src.s_addr)&&(p->addrA.s_addr==ip->ip_dst.s_addr)&&(p->portB==udp->udp_sport)&&(p->portA==udp->udp_dport)){
            p->packetsBtoA++;
            p->bytesBtoA+=ntohs(ip->ip_len)+eth_len;
            is_in_list=true;
            break;
        }
        else{
            p=p->link;
        }
    }
    if(is_in_list){
        p->bytes=p->bytesAtoB+p->bytesBtoA;
        p->packets=p->packetsAtoB+p->packetsBtoA;
    }
    else{
        pcapList *temp=(pcapList *)malloc(sizeof(pcapList));
        temp->addrA=ip->ip_src;
        temp->addrB=ip->ip_dst;
        temp->portA=udp->udp_sport;
        temp->portB=udp->udp_dport;
        temp->packets=1;
        temp->bytesAtoB=ntohs(ip->ip_len)+eth_len;
        temp->bytes=temp->bytesAtoB;
        temp->packetsAtoB=1;
        temp->bytesBtoA=0;
        temp->packetsBtoA=0;
        if(ulist->tail==NULL){
            ulist->head=ulist->tail=temp;
        }
        else{
            ulist->tail->link=temp;
            ulist->tail=temp;
        }
        ulist->length++;
        free(temp);
    }
}

void printPackets(ListHeader plist){
    pcapList *p=plist.head;
    while(p!=NULL){
        printf("Address A: %s\n", inet_ntoa(p->addrA));
        printf("Port A: %d\n", ntohs(p->portA));
        printf("Address B: %s\n",inet_ntoa(p->addrB));
        printf("Port B: %d\n",ntohs(p->portB));
        printf("Packets: %d\n", p->packets);
        printf("Bytes: %d\n", p->bytes);
        printf("Packets A->B: %d\n",p->packetsAtoB);
        printf("Bytes A->B: %d\n",p->bytesAtoB);
        printf("Packets B->A: %d\n",p->packetsBtoA);
        printf("Bytes B->A: %d\n\n",p->bytesBtoA);

        p=p->link;
    }
}



