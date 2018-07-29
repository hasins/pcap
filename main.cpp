#include <pcap.h>
#include <stdio.h>
#include <libnet.h>


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

struct eth_header {
	u_char dmac[6];
	u_char smac[6];
    u_int8_t e_type[2];
};


int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    struct eth_header* eths;
    struct libnet_ipv4_hdr* ip_hdr;
    struct libnet_tcp_hdr* tcp_hdr;
   
   const u_char* packet; 
    int res = pcap_next_ex(handle, &header, &packet);
    eths = (struct eth_header *)packet;

    if (res == 0) continue;
    if (res == -1 || res == -2) break;
//    printf("%u bytes captured\n", header->caplen);

    printf("=====Eth=====\n");
    printf("Eth_D_mac : ");
	for(int i=0; i<6; i++){
        printf("%02x", eths->dmac[i]);
	}
    printf("\n");
    printf("Eth_S_mac : ");
    for(int i=6; i<12; i++){
        printf("%02x", eths->smac[i]);
    }
    printf("\n");
    printf("Eth_Type : ");
        printf("%02x%02x\n",eths->e_type[0], eths->e_type[1]);
        u_char e_num1 = eths->e_type[0];
        u_char e_num2 = eths->e_type[1];

        if(e_num1 == 0x08 && e_num2 == 00){
            char ipaddr[20];
            packet+=sizeof(struct eth_header);
            ip_hdr = (struct libnet_ipv4_hdr *)packet;
            printf("=====IP=====\n");
            inet_ntop(AF_INET, &ip_hdr->ip_src,ipaddr,sizeof(ipaddr));
            printf("S_IP : %s \n",ipaddr);
            inet_ntop(AF_INET, &ip_hdr->ip_dst,ipaddr,sizeof(ipaddr));
            printf("D_IP : %s \n", ipaddr);
            //printf("IP_pt : %02x \n",iphd->ip_p);
            if(ip_hdr->ip_p == 0x06)
            {
                printf("=====TCP=====\n");
                packet += sizeof(struct libnet_ipv4_hdr);
                tcp_hdr = (struct libnet_tcp_hdr *)packet;
                printf("TCP S_PORT : %d\n", ntohs(tcp_hdr->th_sport));
                printf("TCP D_PORT : %d\n", ntohs(tcp_hdr->th_dport));

                packet += sizeof(tcp_hdr->th_off*4);
                printf("=====DATA=====\n");
                for(int i=0; i<16; i++)
                {
                    printf("%02x",packet[i]);
                }


            }
	  
 //           if(e_num2 == 0x00){
 //           }
        }
    printf("\n");

  }

  pcap_close(handle);
  return 0;
}
