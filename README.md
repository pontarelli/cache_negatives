

# Caching negatives

This is the repository for the simulator used in the paper "When Filtering is not Possible Caching Negatives with Fingerprints Comes to the Rescue", ACM CoNext 2020

# Getting Started

The simulator has been developed on Ubuntu 12.04. Other distributions or versions may need different steps.

# Building

Run the following commands in the cache negatives directory to build the executable:

```
$ make
```

# Running

The simulator investigates the HIT rate achievable using several configuration of caching a fingerprint of keys which results in negative lookups. The list of options available in the simulator can be retrieved running:

```
$ ./cn -h 
```
    
# Example

The aim of the simulator is to evaluate the HIT rate of different configurations.
The following example runs 10 iterations of a cache with 1024 rows. The simulator selects 10% (sampling rate) of the flows to be monitored.
The simulator sends all the trace to the cache and counts the HIT rate of different cache configurations:

1. A Traditional cache 
2. A negative cache with random eviction
3. A negative cache with LRU eviction
4. A cache composed by a positive and a negative cache. The ratio between the two caches in defined using the --pnratio option (default 50%) 

```
$ ./cn --cache_size 1024 --repeat 10 --sampling_rate 10 --pcap test.pcap
```

