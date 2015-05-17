#include "test_sniffer.h"
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

pcre *reCompiled;
pcre_extra *pcreExtra;

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

    snifferInit(options, &handle);

    CU_ASSERT(snifferRun(&handle, cnt, &pktcallback) >= 0);

    free(options);
    pcap_close(handle);
}

void test_snifferCleanUp(void)
{
    pcap_t *handle = NULL;
    int cnt = 5; // number of packets to process
    Options *options = malloc(sizeof(Options));
    options->dev = "lo";

    snifferInit(options, &handle);
    snifferRun(&handle, cnt, &pktcallback);

    snifferCleanUp(&handle);
    CU_PASS();

    free(options);
}

void pktcallback(u_char *user, const struct pcap_pkthdr* header, const u_char* packet)
{
  Result * pResult = NULL;
  unsigned char *array = NULL;
  //printf("Sniffed a packet from %s with length %d\n", user, header->len);
  array = malloc(header->len * sizeof(unsigned char));
  memcpy(array, packet, header->len);

  pResult = malloc(sizeof(Result));
  if (pResult == NULL) {
      syslog(LOG_ERR, "Could not allocate memory");
      exit(EXIT_FAILURE);
  }

  if (parser(header->len, array, pResult) == EXIT_SUCCESS) {
    // match only GET req
    if (strcmp((char *)pResult->http_method, "GET") == 0 &&
        detectorMatch(reCompiled, pcreExtra, (char *)pResult->http_request_uri) !=     true){
      // log error
    }

  }

  free(pResult);
  free(array);
}

