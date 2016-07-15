#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0


struct ip *iph;

struct tcphdr *tcph;


void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, 
                const u_char *packet)
{
    static int count = 1;
    struct ether_header *ep;
    unsigned short ether_type;    
    int chcnt =0;
    int length=pkthdr->len;
	int cnt=0;
    ep = (struct ether_header *)packet;

  
    packet += sizeof(struct ether_header);
    ether_type = ntohs(ep->ether_type);

    if (ether_type == ETHERTYPE_IP)
    {

        iph = (struct ip *)packet;
        
        if (iph->ip_p == IPPROTO_TCP)
		{
		tcph = (struct tcp *)(packet + iph->ip_hl * 4);
		printf("IP 패킷\n");
		printf("Source MAC Address : ");
				for(cnt=0; cnt <6; cnt++){
				printf("%02x", ep->ether_shost[cnt]);
					if(cnt!=5) printf(":");
		
		}printf("\n");
		printf("Destination MAC Address : ");
				for(cnt=0; cnt <6; cnt++){
				printf("%02x", ep->ether_dhost[cnt]);
					if(cnt!=5) printf(":");
		
		}printf("\n");

		printf("Source IP Address : %s\n", inet_ntoa(iph->ip_src));
		printf("Destination IP Address : %s\n", inet_ntoa(iph->ip_dst));
           
		
            printf("Source Port : %d\n" , ntohs(tcph->source));
            printf("Destination Port : %d\n" , ntohs(tcph->dest));

        }
	else printf("No TCP Data\n");

     
    }
    else
    {
        printf("NO IP Packet\n");
    }
    printf("---------------------------------------\n");
}    

int main(int argc, char **argv)
{
    char *dev;
    char *net;
    char *mask;

    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    struct pcap_pkthdr hdr;
    struct in_addr net_addr, mask_addr;
    struct ether_header *eptr;
    const u_char *packet;

    struct bpf_program fp;     

    pcap_t *pcd;  
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("DEV : %s\n", dev);
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if (ret == -1)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    pcd = pcap_open_live(dev, BUFSIZ,  NONPROMISCUOUS, -1, errbuf);
    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }    


    if (pcap_compile(pcd, &fp, argv[2], 0, netp) == -1)
    {
        printf("compile error\n");    
        exit(1);
    }

    if (pcap_setfilter(pcd, &fp) == -1)
    {
        printf("setfilter error\n");
        exit(0);    
    }


    pcap_loop(pcd, atoi(argv[1]), callback, NULL);
}

