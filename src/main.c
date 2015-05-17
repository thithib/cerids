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
#include "detector.h"



// var that will be used in pktcallback by the detection engine
pcre * reCompiled;
pcre_extra * pcreExtra;



void pktcallback(u_char *user,const struct pcap_pkthdr* header,const u_char* packet);

int main(int argc, char * argv[])
{

  int code;
  Options options;
  pcap_t * handle;
  pid_t pid = 0;
  char ** whitelist;
  
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
  // getting whitelist
  whitelist = getWhitelist();

  syslog(LOG_DEBUG, "Detection engine startup");
  detectorInit(&reCompiled, whitelist, &pcreExtra);


  syslog(LOG_DEBUG, "Sniffer initialisation");
  snifferInit (&options, &handle);

  syslog(LOG_INFO, "Initialisation complete. Running up.");
  snifferRun (&handle, -1, &pktcallback);

  syslog(LOG_INFO, "Exiting");

  snifferCleanUp(&handle);
  detectorCleanUp(reCompiled, pcreExtra);

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
 
  if (parser(header->len, array, pResult) == EXIT_SUCCESS) {
    // match only GET req
    if (strcmp((char *)pResult->http_method, "GET") == 0 &&
        detectorMatch(reCompiled, pcreExtra, (char *)pResult->http_request_uri) != true){
      // log error
    }

  }

  free(pResult);
  free(array);  
}

