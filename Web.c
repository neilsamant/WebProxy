/*
Subject to code: TO develop a blocking proxy program, considering the requirements and constraints, as posted on NJIT moodle by prof. Kumar Mani.
Course: Internet and Higher Level Protocols, CS 656.
Code submitted by: Neil Samant.

Code Version: 1.8

Working and testing of the code:
The code has to be  compiles and runs on NJIT AFS.

SOP:
Navigate to the directory in which the code is saved.
Open the Terminal and compile using:
gcc web.c -o web

If the integrity of the code is intact, it should ideally compile without any errors or warnings.
Proceed to run the code: ./web 18999
Note: "18999" is the port number on which you want the program to execute.
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <netdb.h>

#define TRUE   1
#define FALSE  0
#define size32 32
#define size256 256
#define size1024 1024

int on = TRUE;
int port, client_socket[size32], max_cli = size32;
int master_socket, new_socket, activity, i, valread, sd, max_sd, prx_cli;
int dns_cli;
char *ip_address, *host_addr;
//char response[size1024*2];
char *resp_out[size1024 * 2];// = response;
struct sockaddr_in address;
int addrlen = sizeof(address);
//set of socket descriptors
fd_set readfds;

struct Data {
    char req[size1024];
    char domain[size1024];
    char port[size32];
} d;

struct Data parse(char req_in[size1024]) {
    int i;
    char temp[size256];
    char *p, *q, *l, *m, *x;
    char cmp1[size32] = "Host:";
    char cmp3[size32] = ":";
    for (i = 0; i <= size1024; i++) {
        d.domain[i] = 0;
    }

    strcpy(d.req, req_in);

    if (strstr(req_in, cmp1)) {
        p = strstr(req_in, cmp1);
        q = strtok(p, "\r");
        q = q + 6;
        strcpy(d.domain, q);

        if (strstr(d.domain, cmp3)) {
            l = strstr(d.domain, cmp3);
            m = strtok(l, "\r");
            m = m + 1;
            strcpy(d.port, m);
        } else {
            strcpy(d.port, "80");
        }
        if (strstr(d.domain, cmp3)) {
            strcpy(temp, d.domain);
            x = strtok(temp, ":");
            strcpy(d.domain, x);
        }

        printf("\nThe value of port is\n");
        puts(d.port);
        printf("\nLength of port: %lu \n", strlen(d.port));
        printf("The value for domain is: \n");
        puts(d.domain);
        printf("\nLength of domain: %lu \n", strlen(d.domain));
    }
    return d;
}

//Function to induce DNS Lookup
char *dnsLOOKup(char *hostname) {
    int sockfd;
    struct addrinfo hints, *results, *p;
    struct sockaddr_in *ip_access;
    int rv, x;
    char *ipv4;
    char black_dns[6][size1024];
    strcpy(black_dns[0], "torrentz.eu");
    strcpy(black_dns[1], "makemoney.com");
    strcpy(black_dns[2], "lottoforever.com");
    strcpy(black_dns[3], "m.torrentz.eu");
    strcpy(black_dns[4], "m.makemoney.com");
    strcpy(black_dns[5], "m.lottoforever.com");
    for (x = 0; x < 6; x++) {
        printf("Comparing with blocked list site: %s\n", black_dns[x]);
        if (strcmp(black_dns[x], hostname) == 0) {
            printf("Match Found!!\n");
            char forbidden_dns[] = "HTTP/1.1 403 Forbidden \r\n\n""<html><body body style='background-color:#add8e6 '> <h1 style='text-align:center'> Access to the requested website is forbidden by the proxy </h1></body></html>";
            send(sd, forbidden_dns, sizeof(forbidden_dns), 0);
            return NULL;
        } else {
            //flag = TRUE;
            printf("No Match found! The side is good to go! value of flag chagged to TRUE\n");;
        }
    }
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(hostname, "domain", &hints, &results)) != 0) {
        printf("\n\nValue of rv: %d\n\n", rv);
        if (rv == -2) {
            //fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
            char bad_dns[] = "HTTP/1.1 105 DNS Resolution Error\r\n\n" "<html><body style='background-color: #ffa500'><h1 style='text-align:center'> DNS Failure</h1></body></html>";
            send(sd, bad_dns, sizeof(bad_dns), 0);
            printf("Response send to the server: \n %s\n", bad_dns);
            return NULL;
        } else {
            return NULL;
        }
    }
    //Taking the first IP address
    p = results;
    ip_access = (struct sockaddr_in *) p->ai_addr;
    ipv4 = inet_ntoa(ip_access->sin_addr);
    printf("IP address for domain %s is: %s\n", hostname, ipv4);
    printf("DNS LOOKUP COMPLETED\n");
    printf("*********************************************\n");
    freeaddrinfo(results); // all done with this structure
    return ipv4;
}

void init() {
    // There are no clients connected in the beginning, so.
    //initialise all client_socket[] to 0.
    for (i = 0; i < max_cli; i++) {
        client_socket[i] = 0;
    }
    //create a master socket
    if ((master_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(0);
    }
    //set master socket to allow multiple connections.It shall act as single point to monitor the change in status of client.
    if (setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) < 0) {
        perror("setsockopt");
        exit(1);
    }
    //inisitializing the socket.
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    //binding the socket, with the parameters mentioned above.
    if (bind(master_socket, (struct sockaddr *) &address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(0);
    }

    //To ensure maximum of 5 backLOG connections for the master socket
    if (listen(master_socket, 5) < 0) {
        perror("listen");
        exit(0);
    }
    //Verifying the port server is running on.
    printf("Listener on port %d \n", port);
    //accept the incoming connection
    puts("Waiting for connections ...");
}

void multi_sd_manager() {

    //Clear the socket set
    FD_ZERO(&readfds);

    //add master socket to set
    FD_SET(master_socket, &readfds);
    max_sd = master_socket;

    //add child sockets to set
    for (i = 0; i < max_cli; i++) {
        //socket descriptor
        sd = client_socket[i];
        //if valid socket descriptor then add to read list
        if (sd > 0)
            FD_SET(sd, &readfds);
        //highest file descriptor number, need it for the select function
        if (sd > max_sd)
            max_sd = sd;
    }

    //wait for an activity on one of the sockets , timeout is NULL ,
    //so wait indefinitely
    activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
    // if ((activity < 0) && (errno!=EINTR)){
    //     printf("select error");
    // }

    //If any activity happends on the master socket ,
    //then its an incoming connection
    if (FD_ISSET(master_socket, &readfds)) {
        if ((new_socket = accept(master_socket, (struct sockaddr *) &address, (socklen_t * ) & addrlen)) < 0) {
            perror("accept");
        }

        //Log socket number of proxy - used in send and receive commands
        printf("New connection is established, socket_fd is %d , ip is : %s , port : %d \n", new_socket,
               inet_ntoa(address.sin_addr), ntohs(address.sin_port));

        //add new socket to array of sockets
        for (i = 0; i < max_cli; i++) {
            //if position is empty
            if (client_socket[i] == 0) {
                client_socket[i] = new_socket;
                printf("Adding to list of sockets as %d\n", i);
                break;
            }
        }
    }
}

void go() {
    if ((prx_cli = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Client Socket: ");
        exit(0);
    }
    printf("Size of IP address: %lu ", sizeof(ip_address));
    struct sockaddr_in remote_address;
    remote_address.sin_family = AF_INET;
    remote_address.sin_port = htons(atoi(d.port));
    inet_aton(ip_address, (struct in_addr *) &(remote_address.sin_addr.s_addr));
    //Connecting the server. TCP connection establishes.
    connect(prx_cli, (struct sockaddr *) &remote_address, sizeof(remote_address));
}


int main(int argc, char *argv[]) {
    port = atoi(argv[1]);
    //This buffer contains the request from the client.
    char buffer[size1024];  //data buffer of 1K
    printf("Fall-2017/CS-656 Project\n --> Prof: Kumar Mani\n --> Project 1: HTTP_Blocking_Proxy\n --> Group: M4.\n -->Mail: ns776@njit.edu \n\n\n");
    init();

    while (TRUE) {
        multi_sd_manager();
        //else its some IO operation on some other socket
        for (i = 0; i < max_cli; i++) {
            sd = client_socket[i];
            if (FD_ISSET(sd, &readfds)) {
                for (i = 0; i < size1024; i++) {
                    buffer[i] = 0;
                }
                //Check if it was for closing , and also read the
                //incoming message
                if ((valread = recv(sd, buffer, 1024, 0)) == 0) {
                    //Somebody disconnected , get his details and print
                    getpeername(sd, (struct sockaddr *) &address, (socklen_t * ) & addrlen);
                    printf("Host disconnected , ip %s , port %d \n", inet_ntoa(address.sin_addr),
                           ntohs(address.sin_port));

                    //Close the socket and mark as 0 in list for reuse
                    close(sd);
                    client_socket[i] = 0;

                } else {
                    //Serve the request.
                    //set the string terminating NULL byte on the end
                    //of the data read
                    buffer[valread] = '\0';
                    //Parsing the request and get the host name.
                    //Basically this parses the code, to get the domain name
                    printf("\nRequest in buffer: %s\n", buffer);
                    parse(buffer);
                    //host_addr contains the host name.
                    //Beginning the DNS-LookUP code for hostname.
                    if ((ip_address = dnsLOOKup(d.domain)) == NULL) {
                        printf("Test string here");
                        getpeername(sd, (struct sockaddr *) &address, (socklen_t * ) & addrlen);
                        printf("\n Host disconnected , ip %s , port %d \n", inet_ntoa(address.sin_addr),
                               ntohs(address.sin_port));
                        close(sd);
                        client_socket[i] = 0;
                    } else {
                        // DNS lookup Completed.
                        printf("Executed till here, before segment block.\n");
                        //Starting with the in_proxy_CLIENT code:
                        go();
                        //Sending the HTTP Request to the Web-Server.
                        send(prx_cli, d.req, sizeof(d.req), 0);
                        printf("\nRequest sent to server: %s\n", d.req);
                        //Recieving the Response from the Web-Server.
                        memset(resp_out, 0, size1024);
                        if (strstr(d.req, "GET http://")) {
                            int rs, ss;
                            do {
                                rs = recv(prx_cli, resp_out, size1024 + (size256 * 2), 0);
                                ss = send(sd, resp_out, rs, 0);
                            } while ((rs != 0) && (ss != 0));
                            printf("\n\nThis is executed \n");
                            getpeername(sd, (struct sockaddr *) &address, (socklen_t * ) & addrlen);
                            printf("\n Host disconnected , ip %s , port %d \n", inet_ntoa(address.sin_addr),
                                   ntohs(address.sin_port));
                            close(sd);
                            client_socket[i] = 0;
                            close(prx_cli);
                            continue;
                        } else {
                            char bad_req[] = "HTTP/1.1 400 BAD REQUEST \r\n\n""<html><p> BAD REQUEST </p></html>";
                            send(sd, bad_req, sizeof(bad_req), 0);
                        }//sub-nested if ends here
                    }//DNS-else ends here..
                }//nested if ends here
            }//Primary if ends here
        }//For loop ends here
    }//while loop ends here.
    return 0;
}
