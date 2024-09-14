#include <stdio.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include "simpleReadPacketApplication.h"

int main(int argc, char *argV[])
{
    //declare handle
    pcap_t *handle=NULL;
    //file name and buffer
    char *file_Name, errbuf[PCAP_ERRBUF_SIZE];
    int count=0;
    struct bpf_program fp;
    bpf_u_int32 net=inet_addr("10.0.2.1");
    char filter_exp[]="udp port 5060";

    //parse the supplied arguments
    file_Name=argV[1];

    if(file_Name==NULL)
    {
        fprintf(stderr,"Could not Find File: %s\n",errbuf);
        return (2);
    }
    else
        printf("File Exported : %s\n", file_Name);

    
    //pass the file to handler open the session  
    handle= pcap_open_offline(file_Name,errbuf);
    if (handle ==NULL)
    {
        fprintf(stderr,"Failed to open File: %s\n",errbuf);
    }

    //filter the packets
    if (pcap_compile(handle,&fp,filter_exp,0,net) == -1)
    {
        fprintf(stderr, "Couldnt Parse Filter %s: %s \n ", filter_exp, pcap_geterr(handle));
        return 2;
    }
    //filter te packets 
    if(pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldnt Install filter %s: %s \n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    //loop through the file and retrive packets
    if(pcap_loop(handle,-1,processPacket,(u_char *)&count)==-1)
    {
        fprintf(stderr,"Failed to read the packet: %s\n",errbuf);
        return 2;
    }
    else 
        printf("Packets Read from the file Completed \n");
    return 0;
}



void processPacket( u_char *arg, const struct pcap_pkthdr* pkthdr,
                    const u_char * packet )
                    {
                        u_int32_t i=0;
                        int  *counter= (int *) arg;
                        
                        printf("Packet Count : %d \n", ++(*counter));
                        printf("Received Packet Size: %d \n",pkthdr->len);
                        printf("Payload: \n");
                        for (i=0;i<pkthdr->len;i++)
                        {
                            if( isprint(packet[i]))
                                printf("%c",packet[i]);
                            else
                                printf("...");
                            
                            if((i%16==0 && i!=0) || i==pkthdr->len-1)
                                printf("\n");
                        }
                        return;
                    }