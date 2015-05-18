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
#include <sys/stat.h>
#include <libgen.h>
#include <time.h>


#include "sniffer.h"
#include "config.h"
#include "parser.h"
#include "detector.h"



// var that will be used in pktcallback by the detection engine
pcre * reCompiled;
pcre_extra * pcreExtra;
FILE * fh;

void getDate(char * date);
void logMatch(FILE * fh, Result * pResult);
void pktcallback(u_char *user,const struct pcap_pkthdr* header,const u_char* packet);

int main(int argc, char * argv[])
{

  int code;
  Options options;
  pcap_t * handle;
  pid_t pid = 0;
  char ** whitelist;

  setlogmask(LOG_UPTO(LOG_DEBUG));
  openlog("cerids", LOG_PID, LOG_DAEMON);

  if ((code = getConf(argc, argv, &options)) != 0){
    syslog(LOG_ERR, "Problem in config");
    help(argv[0]);
    return code;
  }

  // set log verbosity (previous + arg verbosity)
  setlogmask(LOG_UPTO(LOG_WARNING + options.verbose));

//  struct stat s;
//  char * logfilecopy = strdup(options.logfile);
/* 
  if (stat(dirname(logfilecopy), &s) != -1 && !S_ISDIR(s.st_mode)){
    syslog(LOG_ERR, "Logdir %s does not exist. Please create it.", logfilecopy);
    return EXIT_FAILURE;
  }
*/
  if (geteuid() != 0 && options.filename == NULL){
    fprintf(stderr, "ERROR: You must be root\n");
    return EXIT_FAILURE;
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

  fh = fopen("/var/log/cerids/match.log", "a");
  if (fh == NULL){
    syslog(LOG_ERR, "Could not write into logfile %s. Check directory or rights.", "/var/log/cerids/match.log");
    return EXIT_FAILURE;
  }


  // debug or child process
  // getting whitelist
  whitelist = getWhitelist();

  syslog(LOG_DEBUG, "Detection engine startup");
  if (detectorInit(&reCompiled, whitelist, &pcreExtra) != 0){
    syslog(LOG_ERR, "Could not start detection engine");
    return EXIT_FAILURE;
  }
  cleanWhitelist(whitelist);


  syslog(LOG_DEBUG, "Sniffer initialisation");
  if (snifferInit(&options, &handle) != 0){
    syslog(LOG_ERR, "Could not initialise sniffer engine");
    return EXIT_FAILURE;
  }

  syslog(LOG_INFO, "Initialisation complete. Running up.");
  snifferRun(&handle, -1, &pktcallback);

  fclose(fh);

  syslog(LOG_INFO, "Exiting");

  snifferCleanUp(&handle);
  detectorCleanUp(reCompiled, pcreExtra);

  closelog();

  return EXIT_SUCCESS;
}



void pktcallback(u_char *user, const struct pcap_pkthdr* header, const u_char* packet)
{
  Result pResult;
  //printf("Sniffed a packet from %s with length %d\n", user, header->len);
  if (header->len > 10000 || header->len < 20){
    syslog(LOG_CRIT, "Strange packet size detected (maybe handcrafted). POSSIBLE ATTACK");
    return;
  }

  if (parser((unsigned char *)packet, &pResult) == EXIT_SUCCESS) {

    // match only GET req
    if (strcmp((char *)pResult.http_method, "GET") == 0){
      if(detectorMatch(reCompiled, pcreExtra, (char *)pResult.http_request_uri) == false){
        printf("%d.%d.%d.%d\n", pResult.ip_src[0],
            pResult.ip_src[1], pResult.ip_src[2], pResult.ip_src[3]);
        logMatch(fh, &pResult);
      }
    }

  }
}


void logMatch(FILE * fh, Result * pResult)
{
  char * logline = malloc(256*sizeof(char));
        printf("%d.%d.%d.%d\n", pResult->ip_src[0],
            pResult->ip_src[1], pResult->ip_src[2], pResult->ip_src[3]);
  char * src_ip = malloc(16*sizeof(char));
  char * date = malloc(26*sizeof(char));
  getDate(date);

  snprintf(src_ip, 16, "%d.%d.%d.%d", pResult->ip_src[0],
      pResult->ip_src[1], pResult->ip_src[2], pResult->ip_src[3]);
  snprintf(logline, 256, "%s %s (%s) GET %s\n", date, src_ip, 
                pResult->http_host, pResult->http_request_uri);
  puts(logline);
  fputs(logline, fh);
  free(logline);
  free(src_ip);
  free(date);
}

void getDate(char * date)
{
    time_t timer;
    struct tm* tm_info;

    time(&timer);
    tm_info = localtime(&timer);

    strftime(date, 26, "[%d/%m/%Y:%H:%M:%S]", tm_info);
}
