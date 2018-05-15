
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>


#include<stdlib.h>



#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "client_ca" 

#define BUFF_SIZE 2000
#define PORT_NUMBER 55555
#define SERVER_IP "127.0.0.1" 
struct sockaddr_in peerAddr;

int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);       

   return tunfd;

   
}

SSL* setupTLSClient(const char* hostname)
{
    // Step 0: OpenSSL library initialization 
   // This step is no longer needed as of version 1.1.0.
   SSL_library_init();
   SSL_load_error_strings();
   SSLeay_add_ssl_algorithms();

   SSL_METHOD *meth;
   SSL_CTX* ctx;
   SSL* ssl;

   meth = (SSL_METHOD *)TLSv1_2_method();
   ctx = SSL_CTX_new(meth);

   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
   if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1){
printf("Error setting the verify locations. \n");
exit(0);
   }
   ssl = SSL_new (ctx);

   //enable host name check 
   X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
   X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

   return ssl;
}

int setupTCPClient(const char* hostname, int port)
{
  //char c[15];

    //strncpy(c, hostname, 15);

    //c[14] = '\0';
   //for(int i=0;i<sizeof(hostname);i++)
    //printf("%s\n",c);

   //struct addrinfo hints, *result;

   // Get the IP address from hostname
   struct hostent* hp = gethostbyname(hostname);
   //hints.ai_family=AF_UNSPEC;
   //int error=getaddrinfo(c,NULL,&hints,&result);
   //if(error){
   // fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
   // exit(1);
  // }
   //struct sockaddr_in* ip=(struct sockaddr_in *) result->ai_addr;



   // Create a TCP socket
   int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

   // Fill in the destination information (IP, port #, and family)
   memset (&peerAddr, '\0', sizeof(peerAddr));
   memcpy(&(peerAddr.sin_addr.s_addr), hp->h_addr, hp->h_length);
   //memcpy(&(peerAddr.sin_addr.s_addr), (char *) inet_ntoa(ip->sin_addr), 11);
 //   peerAddr.sin_addr.s_addr = inet_addr ("10.0.2.14"); 
   peerAddr.sin_port   = htons (port);
   peerAddr.sin_family = AF_INET;

   // Connect to the destination
   connect(sockfd, (struct sockaddr*) &peerAddr,
           sizeof(peerAddr));
   
   return sockfd;
/*
char c[15];

  strncpy(c, hostname, 7);

  c[6] = '\0';


   struct addrinfo hints, *result;

 // Get the IP address from hostname
  //struct hostent* hp = gethostbyname(hostname);
  hints.ai_family=AF_UNSPEC;
  int error=getaddrinfo(c,NULL,&hints,&result);
  if(error){
   fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
   exit(1);
   }
  struct sockaddr_in* ip=(struct sockaddr_in *) result->ai_addr;

   // Create a TCP socket
   int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

   // Fill in the destination information (IP, port #, and family)
   memset (&peerAddr, '\0', sizeof(peerAddr));
  //memcpy(&(peerAddr.sin_addr.s_addr), hp->h_addr, hp->h_length);
  memcpy(&(peerAddr.sin_addr.s_addr), (char *) inet_ntoa(ip->sin_addr), 11);
 //   peerAddr.sin_addr.s_addr = inet_addr ("10.0.2.14"); 
   peerAddr.sin_port   = htons (port);
   peerAddr.sin_family = AF_INET;

   // Connect to the destination
   connect(sockfd, (struct sockaddr*) &peerAddr,
           sizeof(peerAddr));
   
   return sockfd;*/
}



void tunSelected(int tunfd, SSL* ssl, int sockfd){
    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    SSL_write(ssl, buff, len);
    //SSL_shutdown(ssl);  SSL_free(ssl);
    //sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr,
                   // sizeof(peerAddr));
}

void socketSelected (int tunfd, SSL* ssl, int sockfd){

  int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from the tunnel\n");

    bzero(buff, BUFF_SIZE);
    len = SSL_read(ssl, buff, BUFF_SIZE);
    if(len == 0){
  //SSL_shutdown(ssl);//close ssl
      close(sockfd);//close tcp socket
      sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        while(connect(sockfd, (struct sockaddr*) &peerAddr, sizeof(peerAddr)) < 0){
          sleep(1);        
        }
  
    SSL_set_fd(ssl, sockfd);
    int err = SSL_connect(ssl); CHK_SSL(err);
    char user[40]; char pwdbuff[100];
    char *pwd;
    printf("Please input username: \n");
    fgets(user, 40, stdin);
    pwd = getpass("Please input password: \n");
    strncpy(pwdbuff, pwd, 20);
    if(user[strlen(user)-1] == '\n') user[strlen(user)-1] = '\0';
    if(pwdbuff[strlen(pwdbuff)-1] == '\n') pwdbuff[strlen(pwdbuff)-1] = '\0';
    err = SSL_write(ssl, user, strlen(user)); CHK_SSL(err);
    err = SSL_write(ssl, pwdbuff, strlen(pwdbuff)); CHK_SSL(err);
       
    }
    write(tunfd, buff, len);
/*
int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from the tunnel\n");

    bzero(buff, BUFF_SIZE);
    len = SSL_read (ssl, buff, BUFF_SIZE);
    write(tunfd, buff, len);

*/
}

void usrAndpwd(char* usr, char* pwd)
{
  printf("    User(most 60 characters): ");
  fgets(usr, 60, stdin);
  printf("Passward(most 80 characters): ");
  fgets(pwd, 80, stdin);

  // exclude the '\n' from user input
  if (usr[strlen(usr)-1] == '\n')
    usr[strlen(usr)-1] = '\0';
  if (pwd[strlen(pwd)-1] == '\n')
    pwd[strlen(pwd)-1] = '\0';
}



int main (int argc, char * argv[]) {

char *hostname = "yahoo.com";
int port = 443;

  int tunfd  = createTunDevice();

    if (argc > 1) hostname = argv[1];
    if (argc > 2) port = atoi(argv[2]);

    /*----------------TLS initialization ----------------*/
    SSL *ssl   = setupTLSClient(hostname);

    /*----------------Create a TCP connection ---------------*/
    int sockfd = setupTCPClient(hostname, port);
     
    /*----------------TLS handshake ---------------------*/
    
    SSL_set_fd(ssl, sockfd);
    int err = SSL_connect(ssl); CHK_SSL(err);
    printf("SSL connection is successful\n");
    printf ("SSL connection using %s\n", SSL_get_cipher(ssl));

    char usr[60];
    char *pwd;
    char buf [2000];
    char hpwd[200];

      //char hpwd[200];
    size_t i;
     //usrAndpwd(usr, pwd);
    printf("    User(most 60 characters): ");
    fgets(usr, 60, stdin);
    //printf();
    pwd=getpass("Passward(most 80 characters): ");
    strncpy(hpwd, pwd, 15);
    // exclude the '\n' from user input
    if (usr[strlen(usr)-1] == '\n')
      usr[strlen(usr)-1] = '\0';
    if (hpwd[strlen(hpwd)-1] == '\n')
      hpwd[strlen(hpwd)-1] = '\0';
    //printf("Input     User: %s\nInput Password: %s\n", usr, pwd);
      
    err = SSL_write (ssl, usr, strlen(usr));   CHK_SSL(err);
        
    err = SSL_write (ssl, hpwd, strlen(hpwd));   CHK_SSL(err);




    
   // Enter the main loop
   while (1) {

     fd_set readFDSet;

     FD_ZERO(&readFDSet);
     FD_SET(sockfd, &readFDSet);
     FD_SET(tunfd, &readFDSet);
     select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

     if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, ssl,sockfd);
     if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, ssl,sockfd);
  }
}

