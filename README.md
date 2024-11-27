# Implementation-of-Lightweight-Group-Authentication-for-Edge-computing-applications
Implementation and verification of the scheme presented in the IEEE 2023 paper titled Lightweight Group Authentication Scheme With Key Agreement for Edge Computing Applications.

Here S1 simulates the Group leader, S2 simulates the edge layer , S3 simulates the Authetication server.
All the actions performed in each of these S1,S2,S3 files are done according to the algorithm described in the reasearch paper.

We have 3 clients c1,c2,c3.

Since all of the .cpp files use ssl libraries command to run : g++ file.cpp -o file.out -lssl -lcrypto  , ./file.out

Sequence of simulation is:
1.Run the S3.cpp
2.Run S2.cpp
3.To send set of all pairs from Authentication server to groupleaders type "Send " in S3
4.After S2 receives the message run S1
5.Run S1 
5.S2 directly send info from AS to GL ie S1
6.Run c1,c2,c3
7.Type "Send 1" in S1 to send info from S2 to clients
8.Type "Send 2" in S1 to broadcast the list of randomly selected clients to publically share their share
9.After S1 receievs the info from all the clients it sends the info to S2 and S2 send to S3 which authenticates the group


Verification of security of the protocol is done using verifpal.
