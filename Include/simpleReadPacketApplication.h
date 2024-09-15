#ifndef SIMPLEAPPLICATION
#define SIMPLEAPPLICATION
#pragma once

#include <string.h>
#include <sqlite3.h>
#include "PacketProcessLib.h"

using namespace std;

//structure for fields
struct sip_Fields
{
    u_char PacketCount;
    string From;
    string To;
    string CallerID;
};




//function protoypes
void storeFieldsindB(char * file_Name);
void extractFields(u_char count , string);
void modifyField();
string editPKT(string pkttoText,int counter);
void printFields();

#endif