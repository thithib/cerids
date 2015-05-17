/**
 * \file sniffer.c
 * \brief Sniffer components
 */

#include "sniffer.h"

/**
 * \param options { Pointer to an options structure }
 * \param handle {pcap_t ** pointer}
 * \return 0 if ok, -1 if not implemented, 1 if pcap file or device could not be opened,
 *          2 if filter could not be parsed, 3 if filter could not be instanciated
 */
int snifferInit (Options *options, pcap_t ** handle)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;   /*  The compiled filter expression */
    bpf_u_int32 mask;    /*  The netmask of our sniffing device */
    bpf_u_int32 net;   /*  The IP of our sniffing device */

    if (options->dev != NULL){
        options->live = true;
  
        *handle = pcap_open_live(options->dev, BUFSIZ, 1, 1000, errbuf);
        if (*handle == NULL){
            syslog(LOG_ERR, "Could not open device %s: %s\n", options->dev, errbuf);
            return 1;
        }

    } else {
        options->live = false;

        *handle = pcap_open_offline(options->filename, errbuf);
        if (*handle == NULL){
            syslog(LOG_ERR, "Could not open pcap file %s: %s\n", options->filename, errbuf);
            return 1;
        }
    }


    if (pcap_lookupnet(options->dev, &net, &mask, errbuf) == -1) {
        syslog(LOG_WARNING, "Can't get netmask for device %s\n", options->dev);
        net = 0;
        mask = 0;
    }

    if (pcap_compile(*handle, &fp, options->filter, 0, net) == -1) {
        syslog(LOG_ERR, "Could not parse filter %s: %s\n", options->filter, pcap_geterr(*handle));
        return 2 ;
    }

    if (pcap_setfilter(*handle, &fp) == -1) {
        syslog(LOG_ERR, "Could not install filter %s: %s\n", options->filter, pcap_geterr(*handle));
        return 3 ;
    }

    return 0;
}


/**
 * \param handle { pcap_t ** pointer handler }
 * \param cnt { number of packets to process }
 * \param callback { pcap_handler callback for pcap_loop }
 * \return 0 if ok, -1 or -2 in case of error,
 */
int snifferRun (pcap_t ** handle, int cnt, pcap_handler callback)
{
    /* pcap loop */
    return pcap_loop(*handle, cnt, *callback, (unsigned char*) "live");
}


/**
 * \param handle { pcap_t ** pointer handler }
 * \return 0 if ok, -1 or -2 in case of error,
 */
void snifferCleanUp(pcap_t ** handle)
{
    pcap_close(*handle);
}
