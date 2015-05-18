#include "test_sniffer.h"
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

pcre *reCompiled;
pcre_extra *pcreExtra;
FILE * fh;

int init_suite_sniffer(void) // operations to be done before all tests
{
    return 0;
}

int clean_suite_sniffer(void) // operations to be done after all tests
{
    return 0;
}

void test_snifferInit(void)
{
    Options *options = malloc(sizeof(Options));
    pcap_t *handle = NULL;
    options->dev = "noExistingDevice";
    
    CU_ASSERT(snifferInit(options, &handle) == 1);

    options = malloc(sizeof(Options));
    handle = NULL;
    options->dev = NULL;
    options->filename = "noExistingFile";

    CU_ASSERT(snifferInit(options, &handle) == 1);

    options = malloc(sizeof(Options));
    handle = NULL;
    options->dev = "lo"; // for compatibility

    CU_ASSERT(snifferInit(options, &handle) == 0);

    free(options);
}

void test_snifferRun(void)
{
    pcap_t *handle = NULL;
    int cnt = 5; // number of packets to process
    Options *options = malloc(sizeof(Options));
    options->dev = "lo";
    fh = fopen("match.log", "a");

    snifferInit(options, &handle);

    CU_ASSERT(snifferRun(&handle, cnt, &pktcallback) >= 0);

    fclose(fh);
    free(options);
    pcap_close(handle);
}

void test_snifferCleanUp(void)
{
    pcap_t *handle = NULL;
    int cnt = 5; // number of packets to process
    Options *options = malloc(sizeof(Options));
    options->dev = "lo";
    fh = fopen("match.log", "a");

    snifferInit(options, &handle);
    snifferRun(&handle, cnt, &pktcallback);

    snifferCleanUp(&handle);
    fclose(fh);
    CU_PASS();

    free(options);
}

void pktcallback(u_char *user, const struct pcap_pkthdr* header, const u_char* packet)
{
  Result * pResult = NULL;
  unsigned char *array = NULL;
  //printf("Sniffed a packet from %s with length %d\n", user, header->len);
  if (header->len > 10000 || header->len < 20){
    syslog(LOG_CRIT, "Strange packet size detected (maybe handcrafted). POSSIBLE ATTACK");
    return;
  }

  pResult = malloc(sizeof(Result));
  if (pResult == NULL) {
      syslog(LOG_ERR, "Could not allocate memory in packet callback");
      exit(EXIT_FAILURE);
  }
 
  if (parser((unsigned char *)packet, pResult) == EXIT_SUCCESS) {

    // match only GET req
    if (strcmp((char *)pResult->http_method, "GET") == 0){
      if(detectorMatch(reCompiled, pcreExtra, (char *)pResult->http_request_uri) == false){
        printf("%d.%d.%d.%d\n", pResult->ip_src[0],
            pResult->ip_src[1], pResult->ip_src[2], pResult->ip_src[3]);
        logMatch(fh, pResult);
      }
    }

  }

  free(pResult);
  free(array);  
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

