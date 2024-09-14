#include <stdio.h>
#include <ctype.h>
#include <pcap/pcap.h>
#include "simpleReadPacketApplication.h"

int main(int argc, char *argV[])
{
    //declare handle
    pcap_t *handle=NULL;
    //file name and buffer
    char *file_Name, errbuf[PCAP_ERRBUF_SIZE];
    int count=0;

    file_Name=argV[1];
    if(file_Name==NULL)
    {
        fprintf(stderr,"Could not Find File: %s\n",errbuf);
        return (2);
    }
    else
        printf("File Exported : %s\n", file_Name);

    //pass the file to handler
    handle= pcap_open_offline(file_Name,errbuf);
    if (handle ==NULL)
    {
        fprintf(stderr,"Failed to open File: %s\n",errbuf);
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