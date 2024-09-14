#ifndef SIMPLEAPPLICATION
#define SIMPLEAPPLICATION

#include "pcap/pcap.h"

// struct pcap_pkthdr{
//     struct timeval ts; //timestamp
//     bpf_u_int32 caplen;// number of bytes
//     bpf_u_int32 len;
// };
#define MACBYTES2CAPTURE 2048

void processPacket( u_char *arg, const struct pcap_pkthdr* pkthdr,
                    const u_char * packet );
#endif