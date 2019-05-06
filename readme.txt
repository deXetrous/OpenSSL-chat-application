For question 2 and 3 we have two pcap files named: ques2.pcap and ques3.pcap
For viewing the packets: please enter this constraint
(ip.src == 192.168.43.88 or ip.src == 192.168.43.109) and (ip.dst == 192.168.43.88 or ip.dst == 192.168.43.109)


The passphrase for all the key files is 12345678

3)

TO run:


Peer 1 (should contain enduserEE1.pem, enduserEE1.key, eechain.pem in the code directory)
g++ peer.cpp -o peer -lssl -lcrypto -lpthread
./peer


1 for Server, 2 for Receiver
1
Enter Port No :3000
Enter certificate(enduser) to send :enduserEE1.pem
Enter private key(enduser) path :enduserEE1.key
Enter certificate to verify with :eechain.pem
Enter PEM pass phrase: 12345678






Peer 2 (should contain enduserEE.pem, enduserEE.key, eechain.pem in the code directory)
g++ peer.cpp -o peer -lssl -lcrypto -lpthread
./peer


1 for Server, 2 for Receiver
2
Enter serverIP: 127.0.0.1
Enter Port No :3000
Enter certificate(enduser) to send :enduserEE.pem
Enter private key(enduser) path :enduserEE.key
Enter certificate to verify with :eechain.pem
Enter PEM pass phrase: 12345678


