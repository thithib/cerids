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

  struct bpf_program fp;   /*  The compiled filter expression */
  char filter_exp[] = "port 80"; /*  The filter expression */
  bpf_u_int32 mask;    /*  The netmask of our sniffing device */
  bpf_u_int32 net;   /*  The IP of our sniffing device */

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
    fprintf(stderr, "Not implemented for now\n");

    return -1;

    handle = pcap_open_offline(options.filename, errbuf);
    if (handle == NULL){
      fprintf(stderr, "Could not open pcap file %s: %s\n", options.filename, errbuf);
      return 4;
    }

  }

  if (pcap_lookupnet(options.dev, &net, &mask, errbuf) == -1) {
   fprintf(stderr, "Can't get netmask for device %s\n", options.dev);
     net = 0;
     mask = 0;
  }

  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return(5);
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return(6);
  }

  return EXIT_SUCCESS;
}



void usage(char * binname)
{
  fprintf(stderr, "Usage: %s [-f filename] [-i device] [-p port]\n", binname);
  exit(EXIT_FAILURE);
}

