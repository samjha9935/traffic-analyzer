//Including required header files 
#include<stdio.h>
#include<stdlib.h>
#include<pthread.h>
//#include<pcap.h>
#include<time.h>
#include<unistd.h>

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


//main
int main(){
	//sniff(iface='enp2s0', filter = 'tcp', store = 0, count = 100, prn = append_list) BASICALLY PREPOPULATING BEFORE CHECKING BEGINS

	pthread_t thread_id1,thread_id2,thread_id3,thread_id4,thread_id5;
	pthread_create(&thread_id1, NULL, checkack, NULL);
	pthread_create(&thread_id2, NULL, checkfack, NULL);
	pthread_create(&thread_id3, NULL, checkpack, NULL);
	pthread_create(&thread_id4, NULL, chcekrstack, NULL);
	pthread_create(&thread_id5, NULL, delpkt, NULL);

	//sniff(iface='enp2s0', filter = 'tcp', store = 0, prn = append_list)
	return 0;
}




//FUNCITON DEFINITIONS

//check for acknowledgement A
void *checkack(void *vargp1){
	sleep(6);
}

//check for FIN ACK
void *checkfack(void *vargp2){
	sleep(6);
}

//check for reset RA
void *checkrstack(void *vargp3){
	sleep(6);
}

//chech for Push ACK
void *checkpack(void *vargp){
	sleep(6);
}

//delete packet
void *delpkt(void *vargp){
	sleep(4);
}

/*segragating the incoming packets 
according to their types
also this is called with the sniffing fn main(driver)
py excrept: sniff(iface='enp2s0', filter = 'tcp', store = 0, count = 100, prn = append_list)*/
void append_list(){

}
