# xFlowResearch_Assignment
Assignment Task for xFlowResearch private repository

# Task 0
Creation of git repo and git init on local VS code synchrnoised with GitHub account profile

# Step 1
clone the libpcap rep.
    wget https://www.tcpdump.org/release/libpcap-1.10.5.tar.xz
    tar -xvf libpcap-1.10.5.tar.xz 

Required Depdencies
    sudo apt-get install flex bison 
Build and compile the libpcap
    cd libpcap-1.10.5
    ./configure
    make
    sudo make install

# Step 2
Build your application
    cd ..
    make clean
    make
# Step 3
Run your application with argument of the filename
    ./x_F_R_AssignmentApp filename
    
 
