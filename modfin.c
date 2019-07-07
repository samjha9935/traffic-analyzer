#include <pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

//List lengths
int lenSYN_l=0, lenSYNACK_l=0;

// A linked list node with all req. data values and flags
//The flags are :- TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR
struct Node
{ 	int pkt_no;
    char timestamp[22];
	long long int time;
	char from_ip[15];
	char to_ip[15];
	int src_port;
	int dst_port;
	uint32_t seq_no;
	uint32_t ack_no;
    int FIN, SYN, RST, PUSH, ACK, URG, ECE, CWR;
    struct Node *next;
};

/* Given a reference (pointer to pointer) to the head of a list
   and an int, inserts a new node on the front of the list. */
void push(struct Node** head_ref, int pkt_no, char from_ip[], char to_ip[], int src_port,
	int dst_port, uint32_t seq_no, uint32_t ack_no, long long int time, char timestamp[], int FIN, int SYN, int RST, int PUSH, int ACK, int URG, int ECE, int CWR)
{
    struct Node* new_node = (struct Node*) malloc(sizeof(struct Node));
    new_node->pkt_no  = pkt_no;
	new_node->src_port  = src_port;
	new_node->dst_port  = dst_port;
	new_node->seq_no = seq_no;
	new_node->ack_no = ack_no;
	new_node->FIN  = FIN;
	new_node->SYN  = SYN;
	new_node->RST  = RST;
	new_node->PUSH = PUSH;
	new_node->ACK  = ACK;
	new_node->URG  = URG;
	new_node->ECE  = ECE;
	new_node->CWR  = CWR;
	new_node->time = time;
    strcpy(new_node->timestamp,timestamp);
	strcpy(new_node->from_ip,from_ip);
	strcpy(new_node->to_ip,to_ip);
    new_node->next = (*head_ref);
    (*head_ref)    = new_node;
}

void deleteKey(struct Node **head_ref, int key) 
{ 
    // Store head node 
    struct Node* temp = *head_ref, *prev; 
  
    // If head node itself holds the key or multiple occurrences of key 
    while (temp != NULL && temp->time == key) 
    { 
        *head_ref = temp->next;   // Changed head 
        free(temp);               // free old head 
        temp = *head_ref;         // Change Temp 
    } 
  
    // Delete occurrences other than head 
    while (temp != NULL) 
    { 
        // Search for the key to be deleted, keep track of the 
        // previous node as we need to change 'prev->next' 
        while (temp != NULL && temp->time != key) 
        { 
            prev = temp; 
            temp = temp->next; 
        } 
  
        // If key was not present in linked list 
        if (temp == NULL) return; 
  
        // Unlink the node from linked list 
        prev->next = temp->next; 
  
        free(temp);  // Free memory 
  
        //Update Temp for next iteration of outer loop 
        temp = prev->next; 
    } 
} 

// This function prints contents of linked list starting from
// the given node
// to print int pkt_no, char from_ip[15], char to_ip[15], int src_port,
// and int dst_port, int FIN, int SYN, int RST, int ACK, int URG, int ECE, int CWR)

void printList(struct Node *node)
{
    while (node != NULL)
    {
        printf("\nPacket no: %d\n ", node->pkt_no);
		printf("\nTime of capture: %s\n",node->timestamp);
		printf("IP\nFrom: %s\t", node->from_ip);
		printf("To: %s\n ", node->to_ip);
		printf("Ports\nSource: %d\tDestination: %d\nID\nSequence no.: %"PRIu32"\tAcknowledgement no: %"PRIu32"\n", node->src_port, node->dst_port, node->seq_no, node->ack_no);
		printf("Flags\n FIN:%d SYN:%d RST:%d PUSH:%d ACK:%d URG:%d ECE:%d CWR: %d \n\n",
		node->FIN, node->SYN, node->RST, node->PUSH, node->ACK, node->URG, node->ECE, node->CWR);
        node = node->next;
    }
}


struct Node* storage_buffer = NULL;
struct Node* write_buffer = NULL;

//ack,syn_ack,syn

void check(struct Node *pa, struct Node *psa, struct Node *ps, char a[])
{
	long long int t;
	struct Node *t_pa = pa;
	struct Node *t_psa = psa;
	struct Node *t_ps = ps;
    struct Node *temp_pa = NULL;
    struct Node *temp_psa = NULL;
	int flag = 0;
    while (pa != NULL)
    {   
        while(psa != NULL){
		if(pa->ack_no == (psa->seq_no)+1){
				if (pa->src_port == psa->dst_port && pa->dst_port == psa->src_port && strcmp(pa->from_ip,psa->to_ip)==0 && strcmp(pa->to_ip,psa->from_ip)==0)
				{
					while(ps != NULL){
						if(psa->ack_no == (ps->seq_no)+1){
				if (ps->src_port == psa->dst_port && ps->dst_port == psa->src_port && strcmp(ps->from_ip,psa->to_ip)==0 && strcmp(ps->to_ip,psa->from_ip)==0)
        {

			push(&storage_buffer, ps->pkt_no, ps->from_ip, ps->to_ip, ps->src_port, ps->dst_port, ps->seq_no, ps->ack_no, ps->time, ps->timestamp
	, ps->FIN, ps->SYN, ps->RST, ps->PUSH, ps->ACK, ps->URG, ps->ECE, ps->CWR);
			push(&storage_buffer, psa->pkt_no, psa->from_ip, psa->to_ip, psa->src_port, psa->dst_port, psa->seq_no, psa->ack_no, psa->time, psa->timestamp
	, psa->FIN, psa->SYN, psa->RST, psa->PUSH, psa->ACK, psa->URG, psa->ECE, psa->CWR);
            push(&storage_buffer, pa->pkt_no, pa->from_ip, pa->to_ip, pa->src_port, pa->dst_port, pa->seq_no, pa->ack_no, pa->time, pa->timestamp
	, pa->FIN, pa->SYN, pa->RST, pa->PUSH, pa->ACK, pa->URG, pa->ECE, pa->CWR);
    temp_pa = pa;
    while(temp_pa != NULL){
        if(psa->time - temp_pa->time <= 300){
                break;
            }
        else{
			if(psa->ack_no == (temp_pa->seq_no)+1){
				if (temp_pa->src_port == psa->dst_port && temp_pa->dst_port == psa->src_port && strcmp(temp_pa->from_ip,psa->to_ip)==0 && strcmp(temp_pa->to_ip,psa->from_ip)==0)
        {
           push(&storage_buffer, temp_pa->pkt_no, temp_pa->from_ip, temp_pa->to_ip, temp_pa->src_port, temp_pa->dst_port, temp_pa->seq_no, temp_pa->ack_no, temp_pa->time, temp_pa->timestamp
	, temp_pa->FIN, temp_pa->SYN, temp_pa->RST, temp_pa->PUSH, temp_pa->ACK, temp_pa->URG, temp_pa->ECE, temp_pa->CWR);
   // t = temp_pa->time;
   // deleteKey(&temp_pa,t);
        }
        }
        }
        temp_pa = temp_pa->next;
        }
   // t = pa->time;
   // deleteKey(&pa,t);

          /* fprintf(pktcap,"\n{\"Match_Package\":\n{\n\"Packet_no\" :%d,\n ", pa->pkt_no);
		  fprintf(pktcap,"\n\"Time\" : \"%s\",\n",pa->timestamp);
		fprintf(pktcap,"\"IP\":{\n\"From\": \"%s\",\n\"To\": \"%s\"\n},\n\n", pa->from_ip, pa->to_ip);
		fprintf(pktcap,"\"Ports\":{\n\"Source\": %d,\n\"Destination\": %d},\n\n\"ID\":{\n\"Sequence_no.\": %"PRIu32",\n\"Acknowledgement_no\": %"PRIu32"\n},\n\n", pa->src_port, pa->dst_port, pa->seq_no, pa->ack_no);
		fprintf(pktcap,"\"Flags\":{\n \"FIN\": %d,\n \"SYN\": %d,\n \"RST\": %d,\n \"PUSH\": %d,\n \"ACK\": %d,\n \"URG\": %d,\n \"ECE\": %d,\n \"CWR\": %d, \n}\n},\n\n" , pa->FIN, pa->SYN, pa->RST, pa->PUSH, pa->ACK, pa->URG, pa->ECE, pa->CWR);

			fprintf(pktcap,"\n{\n\"Packet_no\" :%d,\n ", psa->pkt_no);
		  fprintf(pktcap,"\n\"Time\" : \"%s\",\n",psa->timestamp);
		fprintf(pktcap,"\"IP\":{\n\"From\": \"%s\",\n\"To\": \"%s\"\n},\n\n", psa->from_ip, psa->to_ip);
		fprintf(pktcap,"\"Ports\":{\n\"Source\": %d,\n\"Destination\": %d},\n\n\"ID\":{\n\"Sequence_no.\": %"PRIu32",\n\"Acknowledgement_no\": %"PRIu32"\n},\n\n", psa->src_port, psa->dst_port, psa->seq_no, psa->ack_no);
		fprintf(pktcap,"\"Flags\":{\n \"FIN\": %d,\n \"SYN\": %d,\n \"RST\": %d,\n \"PUSH\": %d,\n \"ACK\": %d,\n \"URG\": %d,\n \"ECE\": %d,\n \"CWR\": %d \n}\n},\n\n" , psa->FIN, psa->SYN, psa->RST, psa->PUSH, psa->ACK, psa->URG, psa->ECE, psa->CWR);

			fprintf(pktcap,"\n{\n\"Packet_no\" :%d,\n ", ps->pkt_no);
		  fprintf(pktcap,"\n\"Time\" : \"%s\",\n",ps->timestamp);
		fprintf(pktcap,"\"IP\":{\n\"From\": \"%s\",\n\"To\": \"%s\"\n},\n\n", ps->from_ip, ps->to_ip);
		fprintf(pktcap,"\"Ports\":{\n\"Source\": %d,\n\"Destination\": %d},\n\n\"ID\":{\n\"Sequence_no.\": %"PRIu32",\n\"Acknowledgement_no\": %"PRIu32"\n},\n\n", ps->src_port, ps->dst_port, ps->seq_no, ps->ack_no);
		fprintf(pktcap,"\"Flags\":{\n \"FIN\": %d,\n \"SYN\": %d,\n \"RST\": %d,\n \"PUSH\": %d,\n \"ACK\": %d,\n \"URG\": %d,\n \"ECE\": %d,\n \"CWR\": %d \n}\n},\n\n" , ps->FIN, ps->SYN, ps->RST, ps->PUSH, ps->ACK, ps->URG, ps->ECE, ps->CWR);

		fprintf(pktcap,"},\n\n");*/
                    /*del(ps)
                    flag = 1;*/
                    //break;
				}
				}
					ps = ps->next;
				}
				ps = t_ps;
			
			if(flag==1){
                /*del(psa);
                flag=0;
                break;*/
                }

				}
			}
		psa = psa->next;
		}
		psa = t_psa;
        pa = pa->next;
    }
	pa = t_pa;
}


struct Node* ack = NULL;
struct Node* push_ack = NULL;
struct Node* fin_ack = NULL;
struct Node* rst_ack = NULL;
struct Node* syn = NULL;
struct Node* syn_ack = NULL;


int semaphore = 1;  //to control write_buffer append and file writing

void* wbuff_append(void *args){
    while(1){
        sleep(5);
        struct Node *t_store = storage_buffer;
        struct Node *t_;
        time_t timer;
        timer = time(NULL);
        if(semaphore == 1){
            while(t_store != NULL){
                if(timer - t_store->time >=300){
                    push(&storage_buffer, t_store->pkt_no, t_store->from_ip, t_store->to_ip, t_store->src_port, t_store->dst_port, t_store->seq_no, t_store->ack_no, t_store->time, t_store->timestamp
	, t_store->FIN, t_store->SYN, t_store->RST, t_store->PUSH, t_store->ACK, t_store->URG, t_store->ECE, t_store->CWR);
                }
                t_store = t_store->next;
            }
            semaphore=0;
        }

    }
}
void* writer(void *args){
    FILE* pktcap;
	pktcap = fopen("pktcapture.json","a+");
    if(pktcap == NULL)
    {
      printf("Error!");   
      exit(1);             
    }
    long long int t = 0;
    while(1){
        sleep(5);
         struct Node *t_store = storage_buffer;
        if(semaphore == 0){
            while(t_store != NULL){
                fprintf(pktcap,"\n{\n\"Packet_no\" :%d,\n ", t_store->pkt_no);
		        fprintf(pktcap,"\n\"Time\" : \"%s\",\n",t_store->timestamp);
		        fprintf(pktcap,"\"IP\":{\n\"From\": \"%s\",\n\"To\": \"%s\"\n},\n\n", t_store->from_ip, t_store->to_ip);
		        fprintf(pktcap,"\"Ports\":{\n\"Source\": %d,\n\"Destination\": %d},\n\n\"ID\":{\n\"Sequence_no.\": %"PRIu32",\n\"Acknowledgement_no\": %"PRIu32"\n},\n\n", t_store->src_port, t_store->dst_port, t_store->seq_no, t_store->ack_no);
		        fprintf(pktcap,"\"Flags\":{\n \"FIN\": %d,\n \"SYN\": %d,\n \"RST\": %d,\n \"PUSH\": %d,\n \"ACK\": %d,\n \"URG\": %d,\n \"ECE\": %d,\n \"CWR\": %d \n}\n},\n\n\n" , t_store->FIN, t_store->SYN, t_store->RST, t_store->PUSH, t_store->ACK, t_store->URG, t_store->ECE, t_store->CWR);
                t = t_store->time;
                deleteKey(&t_store,t);
                t_store = t_store->next;
            }
            semaphore = 1;
        }
    }
}

void *delpkt(void *arguments){
    struct arg_struct *args = (struct arg_struct *)arguments;
    while(1){
    sleep(10);
	struct Node* tsyn = syn;
	struct Node* tsyn_ack = syn_ack;
    int i=0,j=0;
    time_t ts;
    ts = time(NULL);
    int templenSYN_l=0;
    while(i<lenSYN_l){
        if((ts - tsyn->time)<60){
			templenSYN_l++;
            syn = tsyn->next;
        }
        else{
            long long int t = tsyn->time;
            deleteKey(&tsyn,t);
        }
    }
    lenSYN_l = templenSYN_l;

    int templenSYNACK_l=0;
    while(i<lenSYNACK_l){
        if((ts - tsyn_ack->time)<60){
            syn_ack = tsyn_ack->next;
            templenSYNACK_l++;
        }
        else{
            long long int t = tsyn_ack->time;
            deleteKey(&tsyn_ack,t);
        }
    }
    lenSYNACK_l = templenSYNACK_l;
}}



struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/*void
print_payload(const u_char *payload, int len);*/

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);

/*
 * app name/banner
 */
void
print_app_banner(void)
{

	printf("\nThis is Sniffer and Analyzer program\n---- -- ------- --- -------- -------\n\n");

return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: sniff [interface]\n");
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}


//packet counters

int c_ack = 0 ;
int c_syn = 0 ;
int c_rst = 0 ;
int c_fin = 0 ;
int c_push = 0 ;



/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	time_t t;
    time(&t);
	char timei[9];
	memcpy( timei, &ctime(&t)[11], 8 );
	timei[8] = '\0';


	time_t timer;
    timer = time(NULL);

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	count++;

	char src[16];
	strcpy(src,inet_ntoa(ip->ip_src));
	char dst[16];
	strcpy(dst,inet_ntoa(ip->ip_dst));

	/* determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			/* print source and destination IP addresses */
            printf("\nCaptured at %s", time);
			printf("\nPacket number %d:\n", count);
			printf("  From: %s\n", src);
			printf("  To: %s\n", dst);
			printf("  Protocol: TCP\n");
			break;
		default:
			//printf("   Protocol: unknown\n");
			return;
	}

	/*
	 *  OK, this packet is TCP.
	 */

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	printf("   Seq num.: %"PRIu32"\n", ntohl(tcp->th_seq));
	printf("   Ack num.: %"PRIu32"\n", ntohl(tcp->th_ack));



	//Assigning flag values

	int FIN=0; int SYN=0; int RST=0; int ACK=0; int URG=0; int ECE=0; int CWR=0; int PUSH=0;
	if (tcp->th_flags & TH_FIN){
        printf("   Flag: TH_FIN\n\n");
		FIN=1;
    }
	if (tcp->th_flags & TH_SYN){
        printf("   Flag: TH_SYN\n\n");
		SYN=1;
    }
	if (tcp->th_flags & TH_RST){
        printf("   Flag: TH_RST\n\n");
		RST =1;
    }
	if (tcp->th_flags & TH_PUSH){
        printf("   Flag: TH_PUSH\n\n");
		PUSH=1;
    }
    if (tcp->th_flags & TH_ACK){
        printf("   Flag: TH_ACK\n\n");
		ACK=1;
    }

	if (tcp->th_flags & TH_ECE){
        printf("   Flag: TH_ECE\n\n");
		ECE=1;
    }
	if (tcp->th_flags & TH_CWR){
        printf("   Flag: TH_CWR\n\n");
		CWR=1;
    }

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	/*
	 * Print payload data; it might be binary, so we don't just
	 * treat it as a string.
	 */
	/*if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}*/

	/*we will call the push function here to start populating the flagged lists
	void push(struct Node** head_ref, int pkt_no, char from_ip[15], char to_ip[15], int src_port,
	int dst_port, int FIN, int SYN, int RST, int PUSH, int ACK, int URG, int ECE, int CWR)*/

    if(src == NULL || src == "" || dst == "" || dst == NULL || ntohs(tcp->th_sport) == 0 || ntohs(tcp->th_dport) == 0){

    }

    else{
	if(FIN==0 && SYN==0 && RST==0 && PUSH==0 && ACK==1){
    push(&ack, count, src, dst, ntohs(tcp->th_sport), ntohs(tcp->th_dport), ntohl(tcp->th_seq), ntohl(tcp->th_ack), timer, ctime(&t)
	, FIN, SYN, RST, PUSH, ACK, URG, ECE, CWR);
	c_ack++;
	}
    else if(FIN==0 && SYN==0 && RST==0 && PUSH==1 && ACK==1){
    push(&push_ack, count, src, dst, ntohs(tcp->th_sport), ntohs(tcp->th_dport), ntohl(tcp->th_seq), ntohl(tcp->th_ack), timer, ctime(&t)
	, FIN, SYN, RST, PUSH, ACK, URG, ECE, CWR);
	c_push++;
	}
	else if(FIN==1 && SYN==0 && RST==0 && PUSH==0 && ACK==1){
    push(&fin_ack, count, src, dst, ntohs(tcp->th_sport), ntohs(tcp->th_dport), ntohl(tcp->th_seq), ntohl(tcp->th_ack), timer, ctime(&t)
	, FIN, SYN, RST, PUSH, ACK, URG, ECE, CWR);
	c_fin++;
	}
	else if(FIN==0 && SYN==0 && RST==1 && PUSH==0 && ACK==1){
    push(&rst_ack, count, src, dst, ntohs(tcp->th_sport), ntohs(tcp->th_dport), ntohl(tcp->th_seq), ntohl(tcp->th_ack), timer, ctime(&t)
	, FIN, SYN, RST, PUSH, ACK, URG, ECE, CWR);
	c_rst++;
	}
	else if(FIN==0 && SYN==1 && RST==0 && PUSH==0 && ACK==0){
    push(&syn, count, src, dst, ntohs(tcp->th_sport), ntohs(tcp->th_dport), ntohl(tcp->th_seq), ntohl(tcp->th_ack), timer, ctime(&t)
	, FIN, SYN, RST, PUSH, ACK, URG, ECE, CWR);
    lenSYN_l++;
	c_syn++;
	}
	else if(FIN==0 && SYN==1 && RST==0 && PUSH==0 && ACK==1){
    push(&syn_ack, count, src, dst, ntohs(tcp->th_sport), ntohs(tcp->th_dport), ntohl(tcp->th_seq), ntohl(tcp->th_ack), timer, ctime(&t)
	, FIN, SYN, RST, PUSH, ACK, URG, ECE, CWR);
    lenSYNACK_l++;
	}
    }
	/*
    //Opening a file to store the values
    FILE *outfile;
    outfile = fopen ("sniff.pcap","wb");
    if (outfile == NULL)
     {
      fprintf(stderr, "\nError opening accounts.dat\n\n");
      exit (1);
     }

     fwrite (&head, sizeof(struct Node), 1, outfile);
	*/
return;
}

char* cleaner(char line[]){
	int i,j;
	for(i = 0; line[i] != '\0'; ++i)
    {
        while (!( (line[i] >= 'a' && line[i] <= 'z') || (line[i] >= '0' && line[i] <= '9') || (line[i] >= 'A' && line[i] <= 'Z') || (line[i]==' ') || (line[i]==':') || line[i] == '\0') )
        {
            for(j = i; line[j] != '\0'; ++j)
            {
                line[j] = line[j+1];
            }
            line[j] = '\0';
        }
    }

	return line;
}
     
void *logger(void *log){
	time_t logtime;
	while(1){
		sleep(20);
		time(&logtime);
	fprintf(log,"%s :Status->\nack: %d\nfin: %d\nrst: %d\npush: %d\nsyn: %d\nsynAck: %d\n\n",ctime(&logtime),c_ack,c_fin,c_rst,c_push,c_syn,lenSYNACK_l);
	}
}

void *checker(void *arg){
    while(1){
    sleep(5);
	check(ack,syn_ack,syn,"Ack Matches");	//ACK Matches List
	check(fin_ack,syn_ack,syn,"FinAck Matches");	//FinACK Matches List
	check(rst_ack,syn_ack,syn,"RstAck Matches");	//RstACK Matches List
	check(push_ack,syn_ack,syn,"PushAck List");		//PushACK Matches List
    }
}


struct arg_struct {
    struct Node* synl;
    struct Node* synackl;
};

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */
	time_t curtime; 
    time(&curtime);
	FILE* log;
	char name[40];
	strcpy(strcat(name,".log"),cleaner(ctime(&curtime)));
	log = fopen(name,"a+");
	char filter_exp[] = "tcp";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = -1;			/* number of packets to capture (-1 or 0 for infinte)*/ 
	print_app_banner();

	/* check for capture device name on command-line as an argument*/
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 3) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		fprintf(log,"%s :error: unrecognized command-line options\n\n",ctime(&curtime));
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			fprintf(log,"%s :Couldn't find default device: %s\n\n",ctime(&curtime),errbuf);
			exit(EXIT_FAILURE);
		}
	}

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		fprintf(log,"%s :Couldn't get netmask for device %s: %s\n",ctime(&curtime),
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	fprintf(log,"%s :Device->%s \t Filter_Expression->%s\n",ctime(&curtime),dev,filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		fprintf(log,"%s :Couldn't open device %s: %s\n",ctime(&curtime), dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		fprintf(log,"%s :%s in not an Ethernet(sniffing not supported)",ctime(&curtime),dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		fprintf(log,"%s :Couldn't parse filter %s: %s\n", ctime(&curtime),
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		fprintf(log, "%s :Couldn't install filter %s: %s\n", ctime(&curtime),
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

    struct arg_struct args;
    args.synl = syn;
    args.synackl = syn_ack;

	pthread_t log_thread, check_thread, delete_thread, writer_thread, writebuff_thread;
	pthread_create(&log_thread,NULL,logger,(void*) log);
    pthread_create(&check_thread,NULL,checker,NULL);
    pthread_create(&writer_thread,NULL,writer,NULL);
    pthread_create(&writebuff_thread,NULL,wbuff_append,NULL);
    pthread_create(&delete_thread,NULL,delpkt,(void*)&args);

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	//Finalizing the run
	printf("\nCapture complete.\n");


	/*Printing the data stored in the Master Linked list*/
	printf("\n\nThe data stored in the linked list :=->\n\n\n");

	printf("\n\nThis is the list for ACK_L");
	printList(ack);

	printf("\n\nThis is the list for PUSHACK_L");
	printList(push_ack);

	printf("\n\nThis is the list for FINACK_L");
	printList(fin_ack);

	printf("\n\nThis is the list for RSTACK_L");
	printList(rst_ack);

	printf("\n\nThis is the list for SYNACK_L");
	printList(syn_ack);

	printf("\n\nThis is the list for SYN_L");
	printList(syn);

    printf("\nExecution complete and sniffed data is written to sniff.pcap\n\n");

	printf("There were:\nack: %d\nfin: %d\nrst: %d\npush: %d\nsyn: %d\nsynAck: %d",c_ack,c_fin,c_rst,c_push,c_syn,lenSYNACK_l);

return 0;
}



/*

Tlsch
-- --
1. implement the splitter
2. write to pcap file
3. implement threads for core processess
4. implement the deleter

*/
