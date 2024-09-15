#ifndef SIMPLEAPPLICATION
#define SIMPLEAPPLICATION

#include "pcap/pcap.h"

using namespace std;

#define MACBYTES2CAPTURE 2048
#define SIZE_ETHERNET 14
#define SIZE_IP_HEADER 20
#define SIZE_UDP_HEADER 8
#define Field1 "From:"
#define Field2 "To:"
#define Field3  "Call-ID"
#define Field4 "CSeq"

extern const string my_name="Zawar";
//structure for fields
struct sip_Fields
    {
        u_char PacketCount;
        string From;
        string To;
        string CallerID;
    };

vector<sip_Fields> dataFields;

//function protoypes
void storeinDb(char * file_Name);
void modifyField();
void printFields();
void processPacket( u_char *arg, const struct pcap_pkthdr* pkthdr,
                    const u_char * packet );

void print_Payload( u_char *payload, int len, u_char count);
void parsePacket(string , u_char);


#endif