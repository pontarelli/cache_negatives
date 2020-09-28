
#ifndef _PCAP_SOURCE_H
#define _PCAP_SOURCE_H

#include <pcap.h>

#define MAX_PACKET_SIZE 1520

//typedef void(*packet_handler)(const unsigned char*, size_t);
typedef void(*packet_handler)(const unsigned char*, pcap_pkthdr );

pcap_t* pcap_source(const char* _device);

void pcap_run(pcap_t* handle, packet_handler callback);


#endif /* _PCAP_SOURCE_H */
