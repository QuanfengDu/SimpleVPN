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
#include <shadow.h>
#include <crypt.h>

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
//#define PORT_NUMBER 55555
#define BUFF_SIZE 2000

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

int setupTCPServer()
{
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset (&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons (4433);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}

void tunSelected(int tunfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    //sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr,
      //              sizeof(peerAddr));
    SSL_write(ssl, buff, len);//strlen(buff) cannot ping
    
}

void socketSelected (int tunfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from the tunnel\n");

    bzero(buff, BUFF_SIZE);
    len = SSL_read(ssl, buff, BUFF_SIZE);
    //buff[len] = '\0';
    write(tunfd, buff, len);

}
int login(char *user, char *passwd){
    struct spwd *pw;
    char *epasswd;
    pw = getspnam(user);
    if(pw == NULL) return -1;
    
    printf("Login name: %s\n", pw->sp_namp);
    epasswd = crypt(passwd, pw->sp_pwdp);

    if(strcmp(epasswd, pw->sp_pwdp)){
         return -1;
    }

    return 1;


}
int main (int argc, char * argv[]) {
   int tunfd, sockfd;

   tunfd  = createTunDevice();
  SSL_METHOD *meth;
  SSL_CTX* ctx;
  SSL *ssl;
  int err;

  // Step 0: OpenSSL library initialization 
  // This step is no longer needed as of version 1.1.0.
  SSL_library_init();
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();

  // Step 1: SSL context initialization
  meth = (SSL_METHOD *)TLSv1_2_method();
  ctx = SSL_CTX_new(meth);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

  
  // Step 2: Set up the server certificate and private key
  SSL_CTX_use_certificate_file(ctx, "./server_cert/server-cert.pem", SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx, "./server_cert/server-key.pem", SSL_FILETYPE_PEM);


  // Step 3: Create a new SSL structure for a connection
  ssl = SSL_new (ctx);
/*------TCP connection----*/
  struct sockaddr_in sa_client;
  size_t client_len;
  int listen_sock = setupTCPServer();
  sockfd = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);

/*------TLS handshake-----*/
  SSL_set_fd(ssl, sockfd);
  err = SSL_accept(ssl);
  CHK_SSL(err);
  printf ("SSL connection established!\n");

/*-----get client username and pwd-----*/
  int isAuth  = 0;
  char user[40]; char pwd[100];
  err = SSL_read(ssl, user, sizeof(user)-1); CHK_SSL(err);
  user[err] = '\0';
  printf("Receive Client username: %s\n", user);
  err = SSL_read(ssl, pwd, sizeof(pwd)-1); CHK_SSL(err);
  pwd[err] = '\0';

  isAuth  = login(user, pwd);
  if(isAuth  == -1){
  printf("Client cannot be authticated. Break the connection!");  
  return 0;
  } 

   // Enter the main loop
   while (1) {
     fd_set readFDSet;

     FD_ZERO(&readFDSet);
     FD_SET(sockfd, &readFDSet);
     FD_SET(tunfd, &readFDSet);
     select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

     if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, ssl);
     if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, ssl);
  }
}
 