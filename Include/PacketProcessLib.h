#ifndef PACKET_PROCESS_LIB_H
#define PACKET_PROCESS_LIB_H

#include "pcap/pcap.h"
#include <string.h>
#include <arpa/inet.h>
#include <vector>
#include <string.h>

using namespace std;

#define MACBYTES2CAPTURE 2048
#define SIZE_ETHERNET 14
#define SIZE_IP_HEADER 20
#define SIZE_UDP_HEADER 8
#define Field1 "From:"
#define Field2 "To:"
#define Field3  "Call-ID"
#define Field4 "CSeq"

int tmp=0;


typedef class PacketProcessLib
{
private:
    char * PcapFile;
    char * dBFile;
    int count ;
    
    //declare handle
    pcap_t *handle=NULL;
    //handler to write to dump file
    pcap_dumper_t *dump;

    struct bpf_program fp;
    bpf_u_int32 net;
    static void printPacket( u_char *, const struct pcap_pkthdr* , const u_char * );
    static void modifyPacket(u_char *, const struct pcap_pkthdr* , const u_char * );
    
public:
    char  errbuf[1024];
        

    //function Prototypes
    PacketProcessLib(char * ,char *);
    bool checkFile();
    bool loadFile();
    bool filterApply(char * ,char * );
    bool readPackets();
    bool modifyPKT();
    
    
    
    static void parsePayload( u_char *, int, u_char );
    
     ~PacketProcessLib();
} processPKT;




#endif