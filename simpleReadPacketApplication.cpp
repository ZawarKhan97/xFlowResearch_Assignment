#include <stdio.h>
#include <ctype.h>
#include <iostream>

#include "simpleReadPacketApplication.h"

using namespace std;

vector<sip_Fields> dataFields;
int count=0;

int main(int argc, char *argV[])
{
    char netMask[]="10.0.2.1";
    char PORTNumber[] = "5060";//for sip
    
    //create class object and pass file name as argument
    processPKT PKT(argV[1],argV[2]);
    if(!PKT.checkFile())
    {
        return 2;
    }
    
    if (!PKT.loadFile())
    {

        cerr<<"Failed to load pcap File : "<<PKT.errbuf<<endl;
        return (2);
    }
    
   //filter SIP Packets
    if (!PKT.filterApply(netMask,PORTNumber))
    {
        cerr<<" Failed to apply Filter : "<<PKT.errbuf<<endl;
        return (2);
    }

    //display filtered packets adn write to the file as well
    if(!PKT.readPackets())
    {
        cerr<<"Failed to ead Sip packets or No SIP packets Found: "<<PKT.errbuf<<endl;
        return 2;
    }

    //Display and store modfied pkt
    if(!PKT.modifyPKT())
    {
        cerr<<"Failed to store Or modify Fields: " <<PKT.errbuf<<endl;
        return 2;
    }
    

    //Print Fields
    printFields();

    //Store Field In a Database
    storeFieldsindB(argV[2]);

    cout<<"ALl Tasks Successfully Completed"<<endl;
    
    return 0;
}



void storeFieldsindB(char * file_Name)
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


void extractFields(u_char count,string fields)
{
    sip_Fields sip_entry;
    sip_entry.PacketCount=count;
    sip_entry.From=fields.substr(fields.find(Field1),(fields.find(Field2)-fields.find(Field1)));
    sip_entry.To=fields.substr(fields.find(Field2),(fields.find(Field3)-fields.find(Field2)));
    sip_entry.CallerID=fields.substr(fields.find(Field3),(fields.find(Field4)-fields.find(Field3)));
    dataFields.push_back(sip_entry);
    cout<<sip_entry.From<<endl;
    cout<< sip_entry.To<<endl;
    cout<< sip_entry.CallerID<<endl<<endl;
}

void modifyField()
{
    string dummy;
    for (size_t i=0; i<dataFields.size();i++)
    {
        dummy=dataFields[i].From;
        dataFields[i].From=dummy.substr(0,6) +" "+ "Zawar" + " "+ dummy.substr(6);
        
    }
}
string editPKT(string pkttoText,int counter)
{
    return pkttoText.substr(0,pkttoText.find(Field1))+ dataFields[counter-1].From
                                    + dataFields[counter-1].To+dataFields[counter-1].CallerID+
                                        pkttoText.substr(pkttoText.find(Field4));
}

void printFields()
{
    cout<<"The Fields Extracted are:"<<endl;
    for (size_t i=0; i<dataFields.size();i++)
    {
        cout<< "Packet Number: "<<dataFields[i].PacketCount<<endl;
        cout<<dataFields[i].From<<endl;
        cout<< dataFields[i].To<<endl;
        cout<< dataFields[i].CallerID<<endl<<endl;
    }
}
