/**
 * \file parser.c
 * \brief HTTP Parser
 */

#include "parser.h"

/**
 * \param frame_length {total frame length}
 * \param pFrame {pointer to frame given for parsing}
 * \param pResult {pointer to structure for giving parsed HTTP request to the detector}
 * \return 0 if parsing went ok, other integer if not
 */
int parser (int frame_length, unsigned char *pFrame, Result* pResult) 
{
    Frame frame;
    
    // Ethernet
    if (ethernetParser(&frame, pFrame) != EXIT_SUCCESS)
        return EXIT_SUCCESS;

    // IP
    if (ipParser(&frame, pFrame) != EXIT_SUCCESS)
        return EXIT_SUCCESS;

    // TCP
    if (tcpParser(&frame, pFrame) != EXIT_SUCCESS)
        return EXIT_SUCCESS;

    // HTTP
    if (httpParser(&frame, pFrame, pResult) != EXIT_SUCCESS)
        return EXIT_SUCCESS;

    return EXIT_SUCCESS;
}

/**
 * \param frame {pointer to frame structure}
 * \param pFrame {pointer to frame given for parsing}
 * \return 0 if parsing went ok, other integer if not
 */
int ethernetParser (Frame *frame, unsigned char *pFrame)
{
    int i;
    // mac addresses
    for (i = 0; i < MAC_LENGTH; ++i) {
        frame->eth_mac_dst[i] = pFrame[i];
        frame->eth_mac_src[i] = pFrame[MAC_LENGTH+i];
    }

    // 1st test : is the frame an ip frame ?
    bool type4Bool = true;
    u_char eth_type4[] = {0x08, 0x00}; // if ipv4 frame, type is 0800
    for (i = 0; i < 2; ++i) {
        frame->eth_type[i] = pFrame[2*MAC_LENGTH+i];
        if (frame->eth_type[i] != eth_type4[i])
            type4Bool = false;
    }
    if(!type4Bool) {
        syslog(LOG_NOTICE, "It is not an ipv4 frame");
        return -2;
    }
    return EXIT_SUCCESS;
}

/**
 * \param frame {pointer to frame structure}
 * \param pFrame {pointer to frame given for parsing}
 * \return 0 if parsing went ok, other integer if not
 */
int ipParser (Frame *frame, unsigned char *pFrame)
{
    int i;
    // is the version of ip 4  ?
    frame->ip_vers = (pFrame[ETH_LENGTH] & 240) >> 4;
    if(frame->ip_vers != 0x4)
    {
        syslog(LOG_NOTICE, "ip version isn't 4");
        return -2;
    }
    // ip header length
    frame->ip_ihl = 4 * (int) (pFrame[ETH_LENGTH] & 15);    

    // type of service
    frame->ip_tos = pFrame[ETH_LENGTH + 1];
    
    // length of ip packet 
    frame->ip_len = 16 * 16 * (int)(u_char) pFrame[ETH_LENGTH + 2] + (int)(u_char) pFrame[ETH_LENGTH + 3];

    // id
    for (i = 0; i < 2; ++i)
        frame->ip_id[i] = pFrame[ETH_LENGTH + 4 + i];

    // flags : 3 bits and fragments offset : 13 bits
    for (i = 0; i < 2; ++i)
        frame->ip_flags_frag_offset[i] = pFrame[ETH_LENGTH + 6 +i];
   
    // ttl
    frame->ip_ttl = pFrame[ETH_LENGTH + 8];

    // protocol, 3rd test : if protocol is tcp, ip_proto is 06
    frame->ip_proto = pFrame[ETH_LENGTH + 9];
    if (frame->ip_proto != 0x06) {
        syslog(LOG_NOTICE, "The protocol isn't tcp");
        return -2;
    }

    // checksum
    for (i = 0; i < 2; ++i)
        frame->ip_checksum[i] = pFrame[ETH_LENGTH + 10 + i];

    // Source and destination ip
    for (i = 0; i < 4; ++i) {
        frame->ip_src[i] = pFrame[ETH_LENGTH + 12 + i];
        frame->ip_dst[i] = pFrame[ETH_LENGTH + 12 + IP_LENGTH + i]; 
    }

    // Options
    if ((frame->ip_ihl - 12 - 2 * IP_LENGTH) != 0) { // if there is options
        frame->ip_options = malloc( (frame->ip_ihl - 12 - 2 * IP_LENGTH) * sizeof(u_char) );
        if(frame->ip_options == NULL) {
            syslog(LOG_ERR, "Couldn't allocate memory");
            return EXIT_FAILURE;
        }
        for(i = 0; i < (frame->ip_ihl - 12 - 2 * IP_LENGTH); ++i)
            frame->ip_options[i] = pFrame[ETH_LENGTH + 12 + 2 * IP_LENGTH +i];
    }
    
    return EXIT_SUCCESS;
}

/**
 * \param frame {pointer to frame structure}
 * \param pFrame {pointer to frame given for parsing}
 * \return 0 if parsing went ok, other integer if not
 */
int tcpParser (Frame *frame, unsigned char *pFrame)
{
    int i = 0;
    frame->tcp_srcport = 16 * 16 * (int)(u_char) pFrame[ETH_LENGTH + frame->ip_ihl] + (int)(u_char) pFrame[ETH_LENGTH + frame->ip_ihl + 1];
    frame->tcp_dstport = 16 * 16 * (int)(u_char) pFrame[ETH_LENGTH + frame->ip_ihl + 2] + (int)(u_char) pFrame[ETH_LENGTH + frame->ip_ihl + 3];

    // sequence number and acknowledgement numbers
    for (i = 0; i < 4; ++i) {
        frame->tcp_seq[i] = pFrame[ETH_LENGTH + frame->ip_ihl + 4 + i];
        frame->tcp_ack[i] = pFrame[ETH_LENGTH + frame->ip_ihl + 8 + i];
    }

    // flags and offset
    for (i = 0; i < 2; ++i)
        frame->tcp_flags[i] = pFrame[ETH_LENGTH + frame->ip_ihl + 12 + i];

    // offset is the 4 first bits of flags
    frame->tcp_offset = 4 * (int)( (frame->tcp_flags[0] & 240) >> 4 );

    frame->tcp_flags[0] &= 15;

    // windows size value
    frame->tcp_window_size_value = 16 * 16 * (int)(u_char) pFrame[ETH_LENGTH + frame->ip_ihl + 14] + (int)(u_char) pFrame[ETH_LENGTH + frame->ip_ihl + 15];

    // checksum
    for (i = 0; i < 2; ++i)
        frame->tcp_checksum[i] = pFrame[ETH_LENGTH + frame->ip_ihl + 16 + i]; 

    // urg pointer
    for (i = 0; i < 2; ++i)
        frame->tcp_urg_pointer[i] = pFrame[ETH_LENGTH + frame->ip_ihl + 18 + i];

    // TCP options
    frame->tcp_options = malloc( (frame->tcp_offset - frame->ip_ihl) * sizeof(u_char) );
    if (frame->tcp_options == NULL) {
        syslog(LOG_ERR, "Couldn't allocate memory");
        return EXIT_FAILURE;
    }

    for (i = 0; i < frame->tcp_offset - frame->ip_ihl ; ++i)
        frame->tcp_options[i] = pFrame[ETH_LENGTH + frame->ip_ihl + 20 + i];

    // TCP data
    int tcp_data_length = frame->ip_len - frame->ip_ihl + frame->tcp_offset;
    frame->tcp_data = malloc(tcp_data_length * sizeof(u_char));
    if (frame->tcp_data == NULL) {
        syslog(LOG_ERR, "Couldn't allocate memory");
        return EXIT_FAILURE;
    }

    for (i = 0; i < tcp_data_length; ++i)
        frame->tcp_data[i] = pFrame[ETH_LENGTH + frame->ip_ihl + frame->tcp_offset + i];

    return EXIT_SUCCESS;
}

/**
 * \param frame {pointer to frame structure}
 * \param pFrame {pointer to frame given for parsing}
 * \param pResult {pointer to structure for giving parsed HTTP request to the detector}
 * \return 0 if parsing went ok, other integer if not
 */
int httpParser(Frame *frame, unsigned char *pFrame, Result* pResult)
{
    char* HTTP_methods[] = {"GET","POST", "HEAD", "PUT","CONNECT", "DELETE", "OPTIONS", "TRACE", "COPY", "LOCK", "MKCOL", "MOVE", "PROPFIND",
        "PROPPATCH", "SEARCH", "UNLOCK", "REPORT", "MKACTIVITY", "CHECKOUT", "MERGE", "MSEARCH", "NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE", "PATCH", "PURGE", "MKCALENDAR"};

    int i = 0; // for next while loop

    frame->http_request_uri = (u_char*) strstr((char*) frame->tcp_data," HTTP/"); // looks for a valid request
    if(frame->http_request_uri == NULL) { // This is not an HTTP header
        if (strstr((char *) frame->tcp_data, "HTTP/") == (char *) frame->tcp_data)
            syslog(LOG_INFO, "HTTP Answer");
        else
            syslog(LOG_DEBUG, "Non HTTP Header");
        return -3;
    }

    frame->http_request_uri = NULL; // set ptr at NULL (shows an invalid request) 

    while (frame->http_request_uri == NULL && i < NUMBER_METHODS) {
        if (strncmp((char*) frame->tcp_data, HTTP_methods[i], strlen(HTTP_methods[i])) == 0) { // method request
            frame->http_method = (u_char*) HTTP_methods[i];
            frame->http_request_uri = frame->tcp_data + strlen(HTTP_methods[i]) ;
        }
        else 
            ++i;
    } 

    frame->http_host = (u_char*) strstr((char *) frame->tcp_data, "Host:");
    if (frame->http_host == NULL) {
        syslog(LOG_NOTICE, "No host");
        return -3;
    }
    frame->http_host += 6;

    u_char* temp = (u_char*) strchr((char *) frame->http_host, '\r');
    if (temp == NULL) {
        syslog(LOG_NOTICE, "Invalid HTTP content");
        return -3;
    }
    *temp = '\0'; // we isolated the host

    temp = (u_char*) strstr((char*) frame->tcp_data, " HTTP/");
    *temp ='\0'; // we ended request first line

    frame->http_request_uri = (u_char*) strchr((char*) frame->tcp_data, ' ');
    if (frame->http_request_uri == NULL) {
        syslog(LOG_NOTICE, "Invalid HTTP content");
        return -3;
    }
    ++(frame->http_request_uri);

    pResult->http_method = frame->http_method;
    pResult->http_request_uri = frame->http_request_uri;
    pResult->http_host = frame->http_host;

    if (frame->http_request_uri != NULL) {
        printf("Method is %s\n", frame->http_method);
        printf("Request-URI is : %s\n", frame->http_request_uri);
    }

    if (frame->http_host != NULL)
        printf("Host: %s\n\n", frame->http_host);

    return EXIT_SUCCESS;
}
