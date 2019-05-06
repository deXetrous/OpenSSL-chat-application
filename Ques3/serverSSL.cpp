#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <thread>

using namespace std;

void readingS(SSL *ssl)
{
	while(true)
	{
		char bufferRead[255];
		bzero(bufferRead,255);
		SSL_read(ssl,bufferRead,sizeof(bufferRead));
    cout << "   " << bufferRead << endl;
		if(strncmp("exit", bufferRead,4) == 0)
			break;

	}
}

void writingS(SSL *ssl)
{
  cout << "Start chatting:" << endl;
	while(true)
	{
		char buffer[255];
		bzero(buffer,255);
    //cout << "Send Message : ";
		fgets(buffer,255,stdin);

		SSL_write(ssl,buffer,sizeof(buffer));
		if(strncmp("exit", buffer,4) == 0)
			break;

	}
}

void SSLConnectionsServer(SSL *ssl)
{
  
  if(SSL_accept(ssl) == 0)
      exit(EXIT_FAILURE);
  else
  {
      cout << "Certificate validation completed :" << endl;
      thread thRead(readingS, ssl);
      thread thWrite(writingS, ssl);
      thRead.join();
      thWrite.join();
  }
  
}

void mainServer(int port, string cert,string privateKey, string verifyCert)
{
  
  SSL_library_init();


  const SSL_METHOD *method;
  SSL_CTX *ctx;
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  method = SSLv23_server_method();
  ctx = SSL_CTX_new(method);
  if (!ctx)
  {
	  perror("Unable to create SSL context");
	  ERR_print_errors_fp(stderr);
	  exit(EXIT_FAILURE);
  }
  int mode = SSL_VERIFY_PEER;
  SSL_CTX_set_verify(ctx, mode, verify_callback);
  int temp = SSL_CTX_load_verify_locations(ctx, verifyCert.c_str() , NULL);

  //CertificateLoader(ctx,"enduser.pem","enduser.key");
  if (SSL_CTX_use_certificate_file(ctx, cert.c_str(), SSL_FILETYPE_PEM) <= 0)
  {
    ERR_print_errors_fp(stderr);
  }
  if(SSL_CTX_use_PrivateKey_file(ctx, privateKey.c_str(), SSL_FILETYPE_PEM) <= 0)
  {
    ERR_print_errors_fp(stderr);
  }
  if(!SSL_CTX_check_private_key(ctx))
  {
    cout << "No matching between private key and certificate" << endl;
  }

  int socketID;
  struct sockaddr_in serverAddr;
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(port);
  serverAddr.sin_addr.s_addr = htons(INADDR_ANY);
  //inet_pton(AF_INET, "127.0.0.1", &serverAddr);
  socketID = socket(AF_INET, SOCK_STREAM,0);
  if(socketID == 0)
  {
    exit(EXIT_FAILURE);
  }
  int t=1;
  if(setsockopt(socketID, SOL_SOCKET, SO_REUSEADDR, (char *)&t, sizeof(t)) < 0)
  {
    exit(EXIT_FAILURE);
  }

  if(bind(socketID, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
  {
    exit(EXIT_FAILURE);
  }

  if(listen(socketID,5))
  {
    exit(EXIT_FAILURE);
  }


  socklen_t len = sizeof(serverAddr);
  SSL *ssl;
  int client = accept(socketID, (struct sockaddr*)&serverAddr,&len);
  cout << client << endl;
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl,client);
  SSLConnectionsServer(ssl);
  
  close(socketID);
  SSL_CTX_free(ctx);

}


