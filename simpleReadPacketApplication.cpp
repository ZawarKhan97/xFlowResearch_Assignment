#include <stdio.h>
#include <pcap/pcap.h>


int main(int argc, char *argV[])
{
    char *file_Name, errbuf[PCAP_ERRBUF_SIZE];
    file_Name=argV[1];
    printf("File Exported : %s\n", file_Name);
    if(file_Name==NULL)
    {
        fprintf(stderr,"Could not Find File: %s\n",errbuf);
        return (2);
    }
    return 0;
}
