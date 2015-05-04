/**
 * \file sniffer.c
 * \brief Sniffer components
 */

#include <syslog.h>
#include <pcap/pcap.h>

#include "sniffer.h"

/**
 * \param options { Pointer to an options structure }
 * \param callback { pcap_handler callback for pcap_loop }
 * \return 0 if ok, -1 if not implemented, 1 if pcap file or device could not be opened,
 *          2 if filter could not be parsed, 3 if filter could not be instanciated
 */
int snifferRun (Options *options, pcap_handler callback)
{
    char *errbuf;
    pcap_t *handle;
    struct bpf_program fp;   /*  The compiled filter expression */
    char filter_exp[] = "port 80"; /*  The filter expression */
    bpf_u_int32 mask;    /*  The netmask of our sniffing device */
    bpf_u_int32 net;   /*  The IP of our sniffing device */
    struct pcap_pkthdr header;  /*  The header that pcap gives us */
    const u_char *packet;   /*  The actual packet */

    if (options->dev != NULL){
        options->live = true;
  
        handle = pcap_open_live(options->dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL){
            syslog(LOG_ERR, "Could not open device %s: %s\n", options->dev, errbuf);
            return 1;
        }

    } else {
        options->live = false;

        handle = pcap_open_offline(options->filename, errbuf);
        if (handle == NULL){
            syslog(LOG_ERR, "Could not open pcap file %s: %s\n", options->filename, errbuf);
            return 1;
        }
    }


    if (pcap_lookupnet(options->dev, &net, &mask, errbuf) == -1) {
        syslog(LOG_WARNING, "Can't get netmask for device %s\n", options->dev);
        net = 0;
        mask = 0;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        syslog(LOG_ERR, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2 ;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        syslog(LOG_ERR, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 3 ;
    }

    /* pcap loop */
    pcap_loop(handle, -1, *callback, "live");


    pcap_close(handle);

    return EXIT_SUCCESS;
}
