#include <stdio.h>
#include <ctype.h>
#include <iostream>

#include "simpleReadPacketApplication.h"

using namespace std;


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
        cerr<<"Failed to rad read Sip packets or No SIP packets Found: "<<PKT.errbuf<<endl;
        return 2;
    }

    //Display and store modfied pkt
    if(!PKT.modifyPKT())
    {
        cerr<<"Failed to store Or modify Fields: " <<PKT.errbuf<<endl;
        return 2;
    }

    //Print Fields
    PKT.printFields();

    //Store Field In a Database
    storeFieldsindB(&PKT,argV[2]);

    cout<<"ALl Tasks Successfully Completed"<<endl;
    
    return 0;
}



void storeFieldsindB(processPKT * PKT,char * file_Name)
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
    for (size_t i = 0; i < PKT->dataFields.size(); ++i) {

        // Bind values to placeholders
        sqlite3_bind_int(stmt, 1, static_cast<int>(i)); // ID as integer
        sqlite3_bind_int(stmt, 2, PKT->dataFields[i].PacketCount);   // PACKET as integer
        sqlite3_bind_text(stmt, 3, PKT->dataFields[i].From.c_str(), -1, SQLITE_STATIC); // FromField as text
        sqlite3_bind_text(stmt, 4, PKT->dataFields[i].To.c_str(), -1, SQLITE_STATIC);   // ToField as text
        sqlite3_bind_text(stmt, 5, PKT->dataFields[i].CallerID.c_str(), -1, SQLITE_STATIC); // CALLerID as text

        // Execute the statement
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            cerr << "Failed to insert row: " << sqlite3_errmsg(db) << endl;
        }

        // Reset the statement for the next iteration
        sqlite3_reset(stmt);
    }
    cout<<"Populated the Database"<<endl;
}