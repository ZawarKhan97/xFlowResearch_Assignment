#include <stdio.h>
#include <ctype.h>
#include <iostream>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <string>
#include <vector>
#include "simpleReadPacketApplication.h"
#include <string.h>

using namespace std;


int count=0;

int main(int argc, char *argV[])
{
    //declare handle
    pcap_t *handle=NULL;
    //handler to write to dump file
    pcap_dumper_t *dump;

    //file name and buffer
    char *file_Name, errbuf[PCAP_ERRBUF_SIZE];
    char *output_FileName="ModifiedFile.pcap";
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

    dump=pcap_dump_open(handle,output_FileName);

    //loop through the file and retrive packets
    if(pcap_loop(handle,-1,processPacket,(u_char *)dump)==-1)
    {
        fprintf(stderr,"Failed to read the packet: %s\n",errbuf);
        return 2;
    }
    else 
        printf("Sip Packets Read from the file Completed \n");
    
  
    // printFields();
    // modifyField();
    // printFields();
    return 0;
}


void processPacket( u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet )
{
                        
    int payload_Size=pkthdr->len-(SIZE_IP_HEADER+SIZE_UDP_HEADER);
    u_char *payload=(u_char *)(packet+ SIZE_ETHERNET+SIZE_IP_HEADER+SIZE_UDP_HEADER);
    
    // int  *counter= (int *) arg;
    int *counter=&count;

    string pkttoText;
    print_Payload(payload,payload_Size,++(*counter));
    // printf("Packet Count : %d \n", ++(*counter));
    // printf("Received Packet Size: %d \n",pkthdr->len);
                        printf("Payload: \n");
                        for( u_int i=0;i<pkthdr->len;i++)
                        {
                            if( isprint(packet[i]))
                            {
                                // printf("%d index %c character",i,packet[i]);
                                pkttoText+=packet[i];
                                
                            }
                            
                            if((i%16==0 && i!=0) || i==pkthdr->len-1)
                                continue;
                        }

                        modifyField();
                        cout<<endl<<pkttoText<<endl;
                        
                        string newpkt=pkttoText.substr(0,pkttoText.find(Field1))+ dataFields[*counter-1].From
                                    + dataFields[*counter-1].To+dataFields[*counter-1].CallerID+
                                        pkttoText.substr(pkttoText.find(Field4));
                        cout<< endl<< "new Packet: "<<endl<<newpkt<<endl;
                        u_char *newPktHdr=new u_char[newpkt.size()];
                        memcpy((u_char *)newPktHdr,&newpkt[0],newpkt.size());

                        pcap_dumper_t *dump=(pcap_dumper_t *)arg;          
                        pcap_dump(arg, pkthdr,newPktHdr);
                        return;
                    }


void parsePacket(string fields, u_char count)
{
    sip_Fields sip_entry;
    sip_entry.PacketCount=count;
    sip_entry.From=fields.substr(fields.find(Field1),(fields.find(Field2)-fields.find(Field1)));
    sip_entry.To=fields.substr(fields.find(Field2),(fields.find(Field3)-fields.find(Field2)));
    sip_entry.CallerID=fields.substr(fields.find(Field3),(fields.find(Field4)-fields.find(Field3)));
    dataFields.push_back(sip_entry);

}

void print_Payload( u_char *payload, int len, u_char count)
                    {
                        string text;
                        printf("Payload Size: %d \n",len);
                        for (int i=0;i<len;i++)
                        {
                            if( isprint(payload[i]))
                            {
                                // printf("%c",payload[i]);
                                text+=(payload[i]);
                            }
                            
                            if((i%16==0 && i!=0) || i==len-1)
                                continue;
                        }
                    
                        parsePacket(text,count);
                        return;
                    }

void printFields()
{
        for (size_t i=0; i<dataFields.size();i++)
    {
        cout<< "Packet Number: "<<dataFields[i].PacketCount<<endl;
        cout<<dataFields[i].From<<endl;
        cout<< dataFields[i].To<<endl;
        cout<< dataFields[i].CallerID<<endl<<endl;
    }
}

void modifyField()
{
    string dummy;
    for (size_t i=0; i<dataFields.size();i++)
    {
        dummy=dataFields[i].From;
        dataFields[i].From=dummy.substr(0,6) +" "+ my_name + " "+ dummy.substr(6);
        
    }
}