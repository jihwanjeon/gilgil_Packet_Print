


#include <pcap.h>
#include <stdio.h>
#include <iostream>
#define SIZE_ETHERNET 14

static uint8_t ip_typecheck_1 = 12;
static uint8_t ip_typecheck_2 = 13;
static uint8_t tcp_typecheck = 23;

void print_mac(const u_char* mac) {
    printf("Src_mac : %02x:%02x:%02x:%02x:%02x:%02x\n", mac[6],mac[7],mac[8],mac[9],mac[10],mac[11]);
    printf("Des_mac : %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void print_ip(const u_char* ip) {
    printf("Src_ip : %d.%d.%d.%.d\n", ip[0],ip[1],ip[2],ip[3]);
    printf("Des_ip : %d.%d.%d.%.d\n", ip[4],ip[5],ip[6],ip[7]);
}

void print_port(const u_char* tcp) {

    uint16_t src = (tcp[0] << 8) + tcp[1];
    uint16_t des = (tcp[2] << 8) + tcp[3];
    printf("Src_port : %d\n",src);
    printf("Des_port : %d\n", des);
}

void print_tcp_data(const u_char* offset, uint32_t data_size) {

    printf("TCP_Data : ");

    if( data_size <= 10 )
        for( int i = 0 ; i < data_size; i++)
            printf("%02x ", offset[i]);

    else {
        for( int i = 0 ; i < 10; i++)
            printf("%02x ", offset[i]);
    }
    printf("\n");
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }


  char track[] = "컨설팅";
  char name[] = "전지환";
  printf("[bob8][%s]pcap_test[%s]\n", track, name);



  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }



 while (1)
  {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
     if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //printf("%u bytes captured\n", header->caplen);
    uint32_t i;
    uint32_t ip_headerlen = 0;
    uint32_t tcp_headerlen = 0;
    uint32_t data_size = 0;

    //IPv4 Check
    if(packet[ip_typecheck_1] == 0x08 && packet[ip_typecheck_2] == 0x00)
    {
        //TCP Check
        if(packet[tcp_typecheck] == 0x06)
        {
            /*
            //패킷내용 확인
            for (i=0; i < header->len; i++) {
                if (i%16 == 0 && i > 0)
                    printf("\n");
                printf("%02x ", packet[i]);
            }
            printf("\n\n");
            */

            ip_headerlen = ((packet[SIZE_ETHERNET]) & 0x0fU)*4;
            //printf("%d\n", ip_headerlen);
           tcp_headerlen = (((packet[SIZE_ETHERNET+ip_headerlen+12]) & 0xf0U) >> 4)*4;
            // printf("%d\n", tcp_headerlen);
            data_size = header->len - ( SIZE_ETHERNET + ip_headerlen + tcp_headerlen );

            print_mac(&packet[0]);
            printf("IPv4 Type Check : %02x%02x\n", packet[ip_typecheck_1], packet[ip_typecheck_2]);
            printf("----------------------------------------------\n");

            print_ip(&packet[SIZE_ETHERNET+12]);
            printf("TCP Protocol Check : %02x\n", packet[tcp_typecheck]);
            printf("----------------------------------------------\n");

            print_port(&packet[SIZE_ETHERNET+ip_headerlen]);
            if( data_size > 0 )
                print_tcp_data(&packet[SIZE_ETHERNET + ip_headerlen + tcp_headerlen], data_size);
            printf("*********************************************\n");
            printf("*********************************************\n");
            printf("*********************************************\n");

        }
        else
            continue;
    }
    else
        continue;
  }

  pcap_close(handle);
  return 0;
}


