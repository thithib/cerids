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
#include "parser.h"


void pktcallback(u_char *user,const struct pcap_pkthdr* header,const u_char* packet);

int main(int argc, char * argv[])
{

  int code;
  Options options;
  pcap_t * handle;
  pid_t pid = 0;
  
  if (geteuid() != 0){
    fprintf(stderr, "ERROR: You must be root\n");
    return EXIT_FAILURE;
  }


  openlog("cerids", LOG_PID, LOG_DAEMON);

  if ((code = getConf(argc, argv, &options)) != 0){
    syslog(LOG_ERR, "Problem in config");
    help(argv[0]);
    return code;
  }

  if (options.debug){
    closelog();
    openlog("cerids", LOG_PID | LOG_PERROR, LOG_DAEMON);
  }

  syslog(LOG_INFO, "Starting up");
  if (!options.foreground)
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
 
  syslog(LOG_INFO, "Sniffer initialisation");
  snifferInit (&options, &handle);

  snifferRun (&handle, -1, &pktcallback);

  syslog(LOG_INFO, "Exiting");

  snifferCleanUp(&handle);

  closelog();

  return EXIT_SUCCESS;
}



void pktcallback(u_char *user, const struct pcap_pkthdr* header, const u_char* packet)
{
  Result * pResult = NULL;
  unsigned char *array = NULL;
  //printf("Sniffed a packet from %s with length %d\n", user, header->len);
  array = malloc(header->len * sizeof(unsigned char));
  memcpy(array, packet, header->len);

  pResult = malloc(sizeof(Result*));
  if (pResult == NULL) {
      syslog(LOG_ERR, "Could not allocate memory");
      exit(EXIT_FAILURE);
  }
 
  parser(header->len, array, pResult);
  free(array);  
}

