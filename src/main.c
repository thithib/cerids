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

void usage(char * binname);


int main(int argc, char * argv[])
{

  char *errbuf;
  pcap_t *handle;
  int opt;

  struct {
    char * dev;
    char * filename;
    int port;
    bool live;

  } options;

  options.port = 80;
  options.dev = NULL;
  options.filename = NULL;


  // arg parsing
  while ((opt = getopt(argc, argv, "f:i:p:")) != -1){
    switch (opt) {
      case 'f':
        options.filename = strdup(optarg);
        break;
      case 'i':
        options.dev = strdup(optarg);
        break;
      case 'p':
        options.port = atoi(optarg);
        break;
      default:
        usage(argv[0]);
    }

  }

  if ( (options.filename == NULL && options.dev == NULL)
      || (options.filename != NULL && options.dev != NULL) ){
    fprintf(stderr, "Only one of filename and interface can be used at the same time\n");
    return 2;
    
  }

  if ( options.port < 1 || options.port > 65535){
    fprintf(stderr, "Invalid port number\n");
    return 3;
  }


  // Open pcap handler on device
  if (options.dev != NULL){
    options.live = true;

    handle = pcap_open_live(options.dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL){
      fprintf(stderr, "Could not open device %s: %s\n", options.dev, errbuf);
      return 4;
    }

  } else {
    options.live = false;

    handle = pcap_open_offline(options.filename, errbuf);
    if (handle == NULL){
      fprintf(stderr, "Could not open pcap file %s: %s\n", options.filename, errbuf);
      return 4;
    }

  }

  return EXIT_SUCCESS;
}

void usage(char * binname)
{
  fprintf(stderr, "Usage: %s [-f filename] [-i device] [-p port]\n", binname);
  exit(EXIT_FAILURE);
}

