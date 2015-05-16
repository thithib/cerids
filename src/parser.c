/**
 * \file parser.c
 * \brief HTTP Parser
 */

#include "parser.h"

//Doesn't work with frames with options

int parser (int frame_length, unsigned char *pFrame, Result* pResult) 
{
    Frame frame;
    int i;

    // Ethernet
    // mac addresses
    for (i = 0; i < 6; ++i) {
        frame.eth_mac_dst[i] = pFrame[i];
        frame.eth_mac_src[i] = pFrame[6+i];
    }
    // 1st test : is the frame a ip frame ?
    bool type4Bool = true;
    u_char eth_type4[] = {0x08, 0x00}; // if ipv4 frame, type is 0800
    for (i = 0; i < 2; ++i) {
        frame.eth_type[i] = pFrame[12+i];
        if (frame.eth_type[i] != eth_type4[i])
            type4Bool = false;
    }
    if(!type4Bool) {
        printf("\nIt is not an ip frame\n");
        return -2;
    }

    // IP
    // 2nd test : is the version of ip 4  ?
    frame.ip_vers_ihl = pFrame[14];
    if(frame.ip_vers_ihl != 0x45)
    {
        printf("ip version isn't 4\n");
        return -2;
    }

    // type of service
    frame.ip_tos = pFrame[15];
    // length of ip packet 
    frame.ip_len = 16 * 16 * (int)(u_char) pFrame[16] + (int)(u_char) pFrame[17];
    // id
    for (i = 0; i < 2; ++i)
        frame.ip_id[i] = pFrame[18+i];

    // flags : 3bits et fragments offset : 13 bits
    for (i = 0; i < 2; ++i)
        frame.ip_flags_frag_offset[i] = pFrame[20+i];
    // ttl
    frame.ip_ttl = pFrame[22];

    // protocol, 3rd test : if protocol is tcp, ip_proto is 06
    frame.ip_proto = pFrame[23];
    if (frame.ip_proto != 0x06) {
        printf("\nThe protocol isn't tcp\n");
        return -2;
    }

    // checksum
    for (i = 0; i < 2; ++i)
        frame.ip_checksum[i] = pFrame[24+i];

    // Source and destination ip
    for (i = 0; i < 4; ++i) {
        frame.ip_src[i] = pFrame[26+i];
        frame.ip_dst[i] = pFrame[30+i]; 
    }

    /* Options
     *   There is an option field if ihl != 5 (!= 20 bytes)
     *   
     *   TO DO
     *
     */

    // TCP
    // ports
    frame.tcp_srcport = 16 * 16 * (int)(u_char) pFrame[34] + (int)(u_char) pFrame[35];
    frame.tcp_dstport = 16 * 16 * (int)(u_char) pFrame[36] + (int)(u_char) pFrame[37];

    // sequence number and acknowledgement numbers
    for (i = 0; i < 4; ++i) {
        frame.tcp_seq[i] = pFrame[38+i];
        frame.tcp_ack[i] = pFrame[42+i];
    }

    // flags and offset
    for (i = 0; i < 2; ++i)
        frame.tcp_flags[i] = pFrame[46+i];

    // offset is the 4 first bits of flags
    frame.tcp_offset = 4 * (int)( (frame.tcp_flags[0] & 240) >> 4 );

    frame.tcp_flags[0] &= 15;

    // windows size value
    frame.tcp_window_size_value = 16 * 16 * (int)(u_char) pFrame[48] + (int)(u_char) pFrame[49];

    // checksum
    for (i = 0; i < 2; ++i)
        frame.tcp_checksum[i] = pFrame[50+i]; 

    // urg pointer
    for (i = 0; i < 2; ++i)
        frame.tcp_urg_pointer[i] = pFrame[52+i];

    // TCP options
    frame.tcp_options = malloc( (frame.tcp_offset - 20) * sizeof(u_char) );
    if (frame.tcp_options == NULL) {
        // syslog
        return EXIT_FAILURE;
    }

    for (i = 0; i < frame.tcp_offset - 20 ; ++i)
        frame.tcp_options[i] = pFrame[54+i];

    // TCP data
    int tcp_data_length = 14 + frame.ip_len - 66;
    frame.tcp_data = malloc(tcp_data_length * sizeof(u_char));
    if (frame.tcp_data == NULL) {
        // syslog
        return EXIT_FAILURE;
    }

    for (i = 0; i < tcp_data_length; ++i)
        frame.tcp_data[i] = pFrame[66+i];

    // HTTP
    char* HTTP_methods[] = {"GET","POST", "HEAD", "PUT","CONNECT", "DELETE", "OPTIONS", "TRACE", "COPY", "LOCK", "MKCOL", "MOVE", "PROPFIND",
        "PROPPATCH", "SEARCH", "UNLOCK", "REPORT", "MKACTIVITY", "CHECKOUT", "MERGE", "MSEARCH", "NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE", "PATCH", "PURGE", "MKCALENDAR"};

    i = 0; // for next while loop

    frame.http_request_uri = (u_char*) strstr((char*) frame.tcp_data," HTTP/"); // looks for a valid request
    if(frame.http_request_uri == NULL) {    // This HTTP content is not valid
        // syslog
        return -3;
    }

    frame.http_request_uri = NULL; // set ptr at NULL (shows an invalid request) 

    while (frame.http_request_uri == NULL && i < 27) {
        if (strncmp((char*) frame.tcp_data, HTTP_methods[i], strlen(HTTP_methods[i])) == 0) { // method request
            frame.http_method = (u_char*) HTTP_methods[i];
            frame.http_request_uri = frame.tcp_data + strlen(HTTP_methods[i]) ;
        }
        else 
            ++i;
    } 

    frame.http_host = (u_char*) strstr((char *) frame.tcp_data, "Host:");
    if (frame.http_host == NULL) {
        // syslog no host
        return -3;
    }
    frame.http_host += 6;

    u_char* temp = (u_char*) strchr((char *) frame.http_host, '\r');
    if (temp == NULL) {
        // syslog problem
        return -3;
    }
    *temp = '\0'; // we isolated the host

    temp = (u_char*) strstr((char*) frame.tcp_data, " HTTP/");
    *temp ='\0'; // we ended request first line

    frame.http_request_uri = (u_char*) strchr((char*) frame.tcp_data, ' ');
    if (frame.http_request_uri == NULL) {
        // syslog weird request
        return -3;
    }
    ++(frame.http_request_uri);

    
    if (frame.http_request_uri != NULL) {
        printf("Method is %s\n", frame.http_method);
        printf("Request-URI is : %s\n", frame.http_request_uri);
    }

    if (frame.http_host != NULL)
       printf("Host: %s\n\n", frame.http_host);
    
    pResult->http_method = frame.http_method;
    pResult->http_request_uri = frame.http_request_uri;
    pResult->http_host = frame.http_host;

    return EXIT_SUCCESS;
}

