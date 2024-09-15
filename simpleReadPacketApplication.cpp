#include <stdio.h>
#include <ctype.h>
#include <iostream>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <vector>
#include "simpleReadPacketApplication.h"
#include <string.h>
#include <sqlite3.h>

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
    storeinDb(file_Name);
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
                            pkttoText+=packet[i];
                            // if( isprint(packet[i]))
                            // {
                            //     // printf("%d index %c character",i,packet[i]);
                            //     pkttoText+=packet[i];
                                
                            // }
                            
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
void storeinDb(char * file_Name)
{
    sqlite3 *db;
    sqlite3_stmt* stmt;
   
    char *errBuf=0;
    char *sql;
    if (sqlite3_open("x_Flow_DB.db" ,&db))
    {
        fprintf(stderr, "Cant Open File : $s \n",sqlite3_errmsg(db));
        return;
    }
    else 
     cout<<" Data Base Opened"<<endl;

    //create table and populate it with fields
    sql="CREATE TABLE IF NOT EXISTS SIP("
    "ID INT PRIMARY KEY NOT NULL,"
    "PACKET INT NOT NULL,"
    "FromField TEXT NOT NULL,"
    "ToField TEXT NOT NULL,"
    "CALLerID TEXT NOT NULL);";

    if (sqlite3_exec(db,sql,NULL,NULL,&errBuf)!=SQLITE_OK)
    {
        cerr<<"Failed to Create Table: "<<errBuf<<endl;
    }
    
    //insert fields into the table
    // for (size_t i=0; i<dataFields.size();i++)
    // {
    //     sql="INSERT INTO SIP(ID,PACKET,FromField,ToField,CALLerID)"
    //     "VALUES ("+ i + ","+ dataFields[i].PacketCount + ","+ dataFields[i].From + ","
    //     + dataFields[i].To+ "," + dataFields[i].CallerID+ ");";
    //      if (sqlite3_exec(db,sql,NULL,NULL,&errBuf)!=SQLITE_OK)
    //     {
    //         cerr<<"Failed to insert Table: "<<errBuf<<endl;
    //     }
    // }
    sql="INSERT INTO SIP (ID, PACKET, FromField, ToField, CALLerID) VALUES (?, ?, ?, ?, ?);";
       // Prepare the SQL statement
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << endl;
        return;
    }
    // Loop through dataFields and bind values
    for (size_t i = 0; i < dataFields.size(); ++i) {

        // Bind values to placeholders
        sqlite3_bind_int(stmt, 1, static_cast<int>(i)); // ID as integer
        sqlite3_bind_int(stmt, 2, dataFields[i].PacketCount);   // PACKET as integer
        sqlite3_bind_text(stmt, 3, dataFields[i].From.c_str(), -1, SQLITE_STATIC); // FromField as text
        sqlite3_bind_text(stmt, 4, dataFields[i].To.c_str(), -1, SQLITE_STATIC);   // ToField as text
        sqlite3_bind_text(stmt, 5, dataFields[i].CallerID.c_str(), -1, SQLITE_STATIC); // CALLerID as text

        // Execute the statement
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            cerr << "Failed to insert row: " << sqlite3_errmsg(db) << endl;
        }

        // Reset the statement for the next iteration
        sqlite3_reset(stmt);
    }
    cout<<"Populated the Database"<<endl;
}