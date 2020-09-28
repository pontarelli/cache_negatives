
#include "pcap_source.hpp"

#include <cassert>
#include <iostream>

pcap_t* pcap_source(const char* _device)
{
    assert(_device);

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* phandle = NULL;

    //if (_device[0] == '/') || (_device[0] == '.')
    //{
        phandle = pcap_open_offline(_device, errbuf);
    //}
    //else
    //{
    //    phandle = pcap_open_live(_device, MAX_PACKET_SIZE, 0, 0, errbuf);
    //}

    if (phandle == NULL)
    {
        perror("PcapSource");
        return NULL;
    }

    return phandle;
}


void pcap_run(pcap_t* phandle, packet_handler callback)
{
    assert(callback);

    struct pcap_pkthdr header;

    const unsigned char* buffer;

    while( (buffer = pcap_next(phandle, &header)) != NULL )
    {
        /*        
        if (header.len != header.caplen)
            printf("len (%u) and caplen (%u) differs\n", header.len, header.caplen);
        */
       
        callback(buffer,header);    
    }

    // std::cout << "End capture (" << i << " packets).\n";
}
