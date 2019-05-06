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


void readingC(SSL *ssl)
{
	while(true)
	{
		char bufferRead[255];
		bzero(bufferRead,255);
		SSL_read(ssl,bufferRead,sizeof(bufferRead));
    cout << "  " << bufferRead << endl;
		//printf("Received msg: %s",bufferRead);
		if(strncmp("exit", bufferRead,4) == 0)
			break;

	}
}

void writingC(SSL *ssl)
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

void SSLConnectionsClient(SSL *ssl)
{
  
  if(SSL_connect(ssl) <= 0)
  {
    ERR_print_errors_fp(stderr);
    
    exit(EXIT_FAILURE);
  }
  else
  {
    cout << "Certificate validation completed :" << endl;
    thread thRead(readingC, ssl);
    thread thWrite(writingC, ssl);
    thRead.join();
    thWrite.join();

    
  }
  

} 

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
    
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
    
    // print_cn_name("Issuer (cn)", iname);
    // print_cn_name("Subject (cn)", sname);
    
    if(depth == 0) {
        /* If depth is 0, its the server's certificate. Print the SANs too */
        // print_san_name("Subject (san)", cert);
    }

    return preverify;
}


void mainClient(string ip, int port, string cert,string privateKey, string verifyCert)
{
  
  SSL_library_init();
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  method = SSLv23_client_method();
  ctx = SSL_CTX_new(method);
  if (!ctx)
  {
	  perror("Unable to create SSL context");
	  ERR_print_errors_fp(stderr);
	  exit(EXIT_FAILURE);
  }
  int mode = SSL_VERIFY_PEER;
  SSL_CTX_set_verify(ctx, mode, verify_callback);
  int temp = SSL_CTX_load_verify_locations(ctx, verifyCert.c_str(), NULL);

  if (SSL_CTX_use_certificate_file(ctx, cert.c_str() , SSL_FILETYPE_PEM) <= 0)
  {
    ERR_print_errors_fp(stderr);
  }
  if(SSL_CTX_use_PrivateKey_file(ctx, privateKey.c_str() , SSL_FILETYPE_PEM) <= 0)
  {
    ERR_print_errors_fp(stderr);
  }
  if(!SSL_CTX_check_private_key(ctx))
  {
    cout << "No matching between private key and certificate" << endl;
  }


  int socketID;
  struct sockaddr_in servAddr,clientAddr;
  inet_pton(AF_INET, ip.c_str(), &servAddr.sin_addr);
  servAddr.sin_family = AF_INET;
  servAddr.sin_port = htons(port);
  socketID = socket(AF_INET, SOCK_STREAM,0);

  if(socketID == 0)
  {
    exit(EXIT_FAILURE);
  }

  

  if(connect(socketID,(struct sockaddr*)&servAddr, sizeof(servAddr)) < 0)
  {
    exit(EXIT_FAILURE);
  }
  cout << "connected" << endl;
  SSL *ssl;
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl,socketID);
  SSLConnectionsClient(ssl);
  close(socketID);
  SSL_CTX_free(ctx);

}


