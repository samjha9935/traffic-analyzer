//Including required header files 
#include<stdio.h>
#include<stdlib.h>
#include<pthread.h>
//#include<pcap.h>
#include<time.h>
#include<unistd.h>
#include<netinet/in.h>
#include<netinet/if_ether.h>
#include<net/ethernet.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<arpa/inet.h>

//defining Constants for TCP FLAG values
#define S 2
#define A 16
#define SA 18
#define FA 17
#define PA 24
#define RA 20
#define UA 36

//Function Declaration
void *checkack(void *vargp);
void *checkfack(void *vargp);
void *checkrstack(void *vargp);
void *checkpack(void *vargp);
void *delpkt(void *vargp);
void append_list();
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet); 

/*
//Implementing queue to store the packet data into them
struct QNode 
{ 
    int key; 
    struct QNode *next; 
}; 
  
// The queue, front stores the front node of LL and rear stores the 
// last node of LL 
struct Queue 
{ 
    struct QNode *front, *rear; 
}; 
  
// A utility function to create a new linked list node. 
struct QNode* newNode(int k) 
{ 
    struct QNode *temp = (struct QNode*)malloc(sizeof(struct QNode)); 
    temp->key = k; 
    temp->next = NULL; 
    return temp;  
} 
  
// A utility function to create an empty queue 
struct Queue *createQueue() 
{ 
    struct Queue *q = (struct Queue*)malloc(sizeof(struct Queue)); 
    q->front = q->rear = NULL; 
    return q; 
} 
  
// The function to add a key k to q 
void enQueue(struct Queue *q, int k) 
{ 
    // Create a new LL node 
    struct QNode *temp = newNode(k); 
  
    // If queue is empty, then new node is front and rear both 
    if (q->rear == NULL) 
    { 
       q->front = q->rear = temp; 
       return; 
    } 
  
    // Add the new node at the end of queue and change rear 
    q->rear->next = temp; 
    q->rear = temp; 
} 
  
// Function to remove a key from given queue q 
struct QNode *deQueue(struct Queue *q) 
{ 
    // If queue is empty, return NULL. 
    if (q->front == NULL) 
       return NULL; 
  
    // Store previous front and move front one node ahead 
    struct QNode *temp = q->front; 
    q->front = q->front->next; 
  
    // If front becomes NULL, then change rear also as NULL 
    if (q->front == NULL) 
       q->rear = NULL; 
    return temp; 
} 
  
*/


//main
int main(){
	pcap_t *descr;
  	char errbuf[PCAP_ERRBUF_SIZE];

	//struct Queue *q = createQueue(); 
	//Implementation of the queues to store packets according to their tcp flags and check functions

	  // open capture file for offline processing
	  descr = pcap_open_offline("http.cap", errbuf);
	  if (descr == NULL) {
	      printf("pcap_open_live() failed: %s\n",errbuf);
	      return 1;
	  }
	
	  // start packet processing loop, just like live capture
	  if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
	      printf("pcap_loop() failed: %s",pcap_geterr(descr));
	      return 1;
	  }

	  printf("capture finished");

	//sniff(iface='enp2s0', filter = 'tcp', store = 0, count = 100, prn = append_list) BASICALLY PREPOPULATING BEFORE CHECKING BEGINS
	pthread_t thread_id1,thread_id2,thread_id3,thread_id4,thread_id5;
	pthread_create(&thread_id1, NULL, checkack, NULL);
	pthread_create(&thread_id2, NULL, checkfack, NULL);
	pthread_create(&thread_id3, NULL, checkpack, NULL);
	pthread_create(&thread_id4, NULL, checkrstack, NULL);
	pthread_create(&thread_id5, NULL, delpkt, NULL);
	pthread_join(thread_id1,NULL);
	pthread_join(thread_id2,NULL);
	pthread_join(thread_id3,NULL);
	pthread_join(thread_id4,NULL);
	pthread_join(thread_id5,NULL);

	//sniff(iface='enp2s0', filter = 'tcp', store = 0, prn = append_list)
	return 0;
}


int k=0;

//FUNCITON DEFINITIONS

//check for acknowledgement A
void *checkack(void *vargp1){
	pthread_t thread_id1;
	pthread_create(&thread_id1, NULL, checkack, NULL);
	printf("%d\n",k++);
	//sleep(6);
}

//check for FIN ACK
void *checkfack(void *vargp2){
	pthread_t thread_id2;
	pthread_create(&thread_id2, NULL, checkfack, NULL);
	sleep(6);
	printf("chkfack\n");
}

//check for reset RA
void *checkrstack(void *vargp3){
	pthread_t thread_id3;
	pthread_create(&thread_id3, NULL, checkrstack, NULL);
	sleep(6);
	printf("chkrstack\n");
}

//chech for Push ACK
void *checkpack(void *vargp){
	pthread_t thread_id4;
	pthread_create(&thread_id4, NULL, checkpack, NULL);
	sleep(6);
	printf("chkpack\n");
}

//delete packet
void *delpkt(void *vargp){
	pthread_t thread_id5;
	pthread_create(&thread_id5, NULL, checkack, NULL);
	sleep(4);
	printf("delete\n");
}

/*segragating the incoming packets 
according to their types
also this is called with the sniffing fn main(driver)
py excrept: sniff(iface='enp2s0', filter = 'tcp', store = 0, count = 100, prn = append_list)*/
void append_list(){

}



void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  const struct ether_header* ethernetHeader;
  const struct ip* ipHeader;
  const struct tcphdr* tcpHeader;
  char sourceIp[INET_ADDRSTRLEN];
  char destIp[INET_ADDRSTRLEN];
  u_int sourcePort, destPort;
  u_char *data;
  int dataLength = 0;
  string dataStr = "";

  ethernetHeader = (struct ether_header*)packet;
  if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
      ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
      inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

      if (ipHeader->ip_p == IPPROTO_TCP) {
          tcpHeader = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
          sourcePort = ntohs(tcpHeader->source);
          destPort = ntohs(tcpHeader->dest);
          data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
          dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

          // convert non-printable characters, other than carriage return, line feed,
          // or tab into periods when displayed.
          for (int i = 0; i < dataLength; i++) {
              if ((data[i] >= 32 && data[i] <= 126) || data[i] == 10 || data[i] == 11 || data[i] == 13) {
                  dataStr += (char)data[i];
              } else {
                  dataStr += ".";
              }
          }
	// print the results
	  printf("%s:%d -> %s:%d\n\n",sourceIp,&sourcePort,destIp,&destPort);
          if (dataLength > 0) {
              printf("%s\n",dataStr);
          }
      }
  }
}

