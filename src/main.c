/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  main function of the CerIDS project
 *
 *        Version:  1.0
 *        Created:  02/03/2015 21:26:04
 *       Revision:  none
 *       Compiler:  gcc
 *
 * =====================================================================================
 */

#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include <stdbool.h>
#include <syslog.h>
#include <sys/types.h>


#include "sniffer.h"
#include "config.h"


void usage(char * binname);
void pktcallback(u_char *user,const struct pcap_pkthdr* header,const u_char* packet);

int main(int argc, char * argv[])
{

  int opt;
  Options options;
  pid_t pid = 0;

  openlog("cerids", LOG_PID, LOG_DAEMON);

  syslog(LOG_INFO, "Starting up");

  if (!options.debug)
    pid = fork();

  if (pid == -1) {
    syslog(LOG_ERR, "Could not fork to background");
    return EXIT_FAILURE;
  }
  else if (pid > 0) {
    // parent process and not debug
    return EXIT_SUCCESS;
  }

  // debug or child process
 
  syslog(LOG_INFO, "Reading configuration");
  // Getting conf from both file and arguments
  getConf(argc, argv, &options);

  syslog(LOG_INFO, "Sniffer initialisation");
  snifferRun (&options, &pktcallback);

  syslog(LOG_INFO, "Exiting");

  closelog();

  return EXIT_SUCCESS;
}



void pktcallback(u_char *user, const struct pcap_pkthdr* header, const u_char* packet)
{
  unsigned char *array = NULL;
  printf("Sniffed a packet from %s with length %d\n", user, header->len);
  array = malloc(header->len * sizeof(unsigned char));
  memcpy(array, packet, header->len);

  for (int i = 0; i < header->len; i++){
    printf("%x", array[i]);
  }

  puts("");

}

