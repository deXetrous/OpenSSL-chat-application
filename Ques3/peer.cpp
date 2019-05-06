#include "clientSSL.cpp"
#include "serverSSL.cpp"
int main()
{
    int choice;
    cout << "Enter your choice : \n1 for Server, 2 for Client"<<endl;
    cin>>choice;

    if(choice == 1)
    {
        string verifyCert,cert,privateKey;
        int pNo;
        cout << "Enter Port No :";
        cin >> pNo;
        cout << "Enter certificate(enduser) to send :"; //"enduser.pem"
        cin>>cert;
        cout << "Enter private key(enduser) path :";   //"enduser.key"
        cin>>privateKey;
        cout << "Enter certificate to verify with :";  //"root.pem"
        cin>>verifyCert;
        mainServer(pNo, cert, privateKey,verifyCert);
    }
    else
    {
        string verifyCert,cert,privateKey,ip;
        cout << "Enter serverIP: ";
        cin >> ip;
        int pNo;
        cout << "Enter Port No :";
        cin >> pNo;
        cout << "Enter certificate(client) to send :"; //"intermediate.pem"
        cin>>cert;
        cout << "Enter private key(enduser) path :";   //"intermediate.key"
        cin>>privateKey;
        cout << "Enter certificate to verify with :";  // "chain.pem"
        cin>>verifyCert;
        mainClient(ip, pNo, cert, privateKey,verifyCert);
    }
    

}
