#include "PacketProcessLib.h"
#include <iostream>
#include <stdlib.h>
#include <string.h>

processPKT::PacketProcessLib(char * Filename,char * DbFilename) :PcapFile(Filename),dBFile(DbFilename)
{
    count=0;
    my_name="Zawar";
};

bool processPKT::checkFile()
{
  if(PcapFile==NULL)
    {
        cerr<<"Could not Find File: "<<errbuf<<endl;
        return false;
    }
   else 
        cout<<"File found: "<<PcapFile<<endl;
 return true;
}

bool processPKT::loadFile()
{
     //pass the file to handler open the session  
    handle= pcap_open_offline(PcapFile,errbuf);
    if (handle ==NULL)
    {
        memcpy(errbuf,errbuf,sizeof(errbuf));
        return false;
    }
    else 
       cout<<"Pcap FIle Successfully loaded"<<endl;
    return true;
}

processPKT::~PacketProcessLib()
{
    
}


 //filter the packets
 bool processPKT::filterApply(char * network,char * port)
 {
    net=inet_addr(network);//network mask
    char filter_exp[]="udp port 5060";

    //compile filter 
    if (pcap_compile(handle,&fp,filter_exp,0,net) == -1)
    {
        memcpy(errbuf,pcap_geterr(handle),sizeof(pcap_geterr(handle)));
        return false;
    }
    //set Filter 
    //filter te packets 
    if(pcap_setfilter(handle, &fp) == -1)
    {
        memcpy(errbuf,pcap_geterr(handle),sizeof(pcap_geterr(handle)));
        return false;
    }
    cout<<"Filter Applied Successfully"<<endl;
    return true;
 }
    
bool processPKT::readPackets()
 {
    
    //loop through the file and retrive packets
    if(pcap_loop(handle,-1,processPKT::printPacket,(u_char*)&count)==-1)
    {
        cout<<"herer";
        memcpy(errbuf,errbuf,sizeof(errbuf));
        return false;
    }
    else 
        cout<<"Sip Packets Read from the file Completed \n";
    
    return true;

 }   

void processPKT::printPacket( u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet )
{
    int  *counter= (int *) arg;
    cout<<"Packet Count :"<< ++(*counter)<<endl;
    cout<<"Received Packet Size: "<< pkthdr->len<<endl;
    cout<<"Payload: "<<endl;
    for( u_int i=0;i<pkthdr->len;i++)
     {
                            if( isprint(packet[i]))
                            {
                                cout<<packet[i];
                                                               
                            }
                            
                            if((i%16==0 && i!=0) || i==pkthdr->len-1)
                            {
                                cout<<endl;
                                continue;
                            }
                                
    }
}
          
bool processPKT::modifyPKT()
  {
    dump=pcap_dump_open(handle,"output.pcap");
    if(dump==NULL)
    {
        cout<<"Eror in opening pcapfile"<<endl;
        return false;
    }
    //loop through the file and retrive packets
    if(pcap_loop(handle,-1,modifyPacket,(u_char *)dump)==-1)
    {
        cerr<<"Failed to modify the packet: "<<endl;
        return 2;
    }
    else 
        cout<<("Sip Packets Read from the file Completed \n");
    return true;
  }

void processPKT::modifyPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet )
{
                        
    payload_Size=pkthdr->len-(SIZE_IP_HEADER+SIZE_UDP_HEADER);
    payload=(u_char *)(packet+ SIZE_ETHERNET+SIZE_IP_HEADER+SIZE_UDP_HEADER);
    
    int  *counter= (int *) arg;
    string pkttoText;
    // Extract Fields from the Payload
    parsePayload(payload,payload_Size,++(*counter));

    //read and modify the packet
    for( u_int i=0;i<pkthdr->len;i++)
       {
           pkttoText+=packet[i];
           if((i%16==0 && i!=0) || i==pkthdr->len-1)
              continue;
        }

        modifyField();

        //adjust the packet for new header
        string newpkt=pkttoText.substr(0,pkttoText.find(Field1))+ dataFields[*counter-1].From
                                    + dataFields[*counter-1].To+dataFields[*counter-1].CallerID+
                                        pkttoText.substr(pkttoText.find(Field4));
        cout<< endl<< "new Packet: "<<endl<<newpkt<<endl;
        //newpkt Hdr
        u_char *newPktHdr=new u_char[newpkt.size()];
        memcpy((u_char *)newPktHdr,&newpkt[0],newpkt.size());
        //store the packet
        pcap_dump(arg, pkthdr,newPktHdr);
        
        return;
}

void processPKT::modifyField()
{
    string dummy;
    for (size_t i=0; i<dataFields.size();i++)
    {
        dummy=dataFields[i].From;
        dataFields[i].From=dummy.substr(0,6) +" "+ my_name + " "+ dummy.substr(6);
        
    }
}

void processPKT::parsePayload( u_char *payload, int len, u_char count)
{
    string text;
    printf("Payload Size: %d \n",len);
   for (int i=0;i<len;i++)
        {
            if( isprint(payload[i]))
                {
                     text+=(payload[i]);
                }
                            
            if((i%16==0 && i!=0) || i==len-1)
                continue;
        }
                  
    extractFields(count,text);
    
    return;
}

void processPKT::printFields()
{
    for (size_t i=0; i<dataFields.size();i++)
    {
        cout<< "Packet Number: "<<dataFields[i].PacketCount<<endl;
        cout<<dataFields[i].From<<endl;
        cout<< dataFields[i].To<<endl;
        cout<< dataFields[i].CallerID<<endl<<endl;
    }
}

inline void PacketProcessLib::extractFields(u_char count,string fields)
{
    sip_Fields sip_entry;
    sip_entry.PacketCount=count;
    sip_entry.From=fields.substr(fields.find(Field1),(fields.find(Field2)-fields.find(Field1)));
    sip_entry.To=fields.substr(fields.find(Field2),(fields.find(Field3)-fields.find(Field2)));
    sip_entry.CallerID=fields.substr(fields.find(Field3),(fields.find(Field4)-fields.find(Field3)));
    dataFields.push_back(sip_entry);
}
 

