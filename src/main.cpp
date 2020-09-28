#include <iostream>
#include <vector>
#include <string.h>
#include <string>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "utils.h"
#include <math.h>
#include <signal.h>
#include <time.h>       /* time_t, struct tm, difftime, time, mktime */
#include <getopt.h>
#include <iomanip>
#include <map>
#include "pcap_source.hpp"
#include "protocols.hpp"
#include <arpa/inet.h>
#include "CF.hpp"
#include <algorithm>
#include <math.h>       /* log2 */

bool start=false;
int currentfile=0;
int trace_type=0;
static pcap_t* handle; 
char* filenames[1024]; 
int numfiles=1; 

bool pcap_flag =true;
int offset[3]={14,18,0};

char *mybasename(char *path)
{
    char *s = strrchr(path, '/');
    if (!s)
        return strdup(path);
    
    char *s2 = strdup(s + 1);
    s = strchr(s2, '.');
    *s='\0';
    return strdup(s2);
}

int next_power_of_two(int n) {
    int i = 0;
    for (--n; n > 0; n >>= 1) {
        i++;
    }
    return 1 << i;
}



// read the IP from a file and provide the SRC,DST pair as an 64 bits int
int read_IP_from_file(five_tuple* ft)
{
    struct pcap_pkthdr header;
    
    const unsigned char* pkt_buffer = NULL;
back:
    if (!start) {
        handle = pcap_source(filenames[currentfile]);
        //std::cerr << "\n" << "----------------------------" << "\n";
        //std::cerr << "Start capturing from " << filenames[currentfile] << "\n";
        //std::cerr << "----------------------------" << "\n";
	 int dlt=pcap_datalink(handle); 
	 if (dlt==DLT_EN10MB) trace_type=0;
	 if (dlt==12) trace_type=2;
	 //printf("dlt is: %d\n", dlt);
	 //exit(1);
    }
    start=true;

    //read pkts

    unsigned char buffer[8];
    int16_t sp,dp;
    timeval init_tv;
    if( ( pkt_buffer = pcap_next(handle, &header)) != NULL ){
        timeval tv=header.ts;
        if (pcap_flag) 
        {
            init_tv=header.ts;
            pcap_flag=false;
        }
        if ((pkt_buffer[12]==0x81) && (pkt_buffer[13]==0x00)) trace_type=1; 
        int offset_id=offset[trace_type]; 
        if (((pkt_buffer[12]==0x08) && (pkt_buffer[13]==0x00) && (trace_type==0))  || 
             (trace_type==1) || (trace_type==2) )
            {
            if ((pkt_buffer[offset_id+9]==0x06) || (pkt_buffer[offset_id+9]==0x11)) {
                const struct tcp* header = (const struct tcp*) (pkt_buffer+offset_id);
                if ( ((unsigned char*) header)[0]!=0x45) return 0;
                memcpy(buffer, &(header->ip.source), 8);
                timersub(&tv,&init_tv,&tv); 
                //printf("%ld.%06ld ", tv.tv_sec, tv.tv_usec);
                //printf("%ld.%06ld ", tv.tv_sec, tv.tv_usec);
                //printf("%u.%u.%u.%u ",buffer[0],buffer[1],buffer[2],buffer[3]);       
                //printf("%u.%u.%u.%u ",buffer[4],buffer[5],buffer[6],buffer[7]);
                sp=header->src_port;
                dp=header->dst_port;
                //printf("%u %u %u ",ntohs(sp),ntohs(dp),pkt_buffer[offset_id+9]);
		ft->sip=ntohl(header->ip.source);
		ft->dip=ntohl(header->ip.destination);
		ft->proto=header->ip.protocol;
		ft->sp= ntohs(sp);
		ft->dp= ntohs(dp);
            }
        }
    } 
    else { 
        pcap_close(handle);
	currentfile++;
	printf("!");
	start=false;
        if (currentfile<numfiles) goto back;
        if (currentfile==numfiles) return -1;
    }
    return 1;
}



void PrintUsage( struct command_option* long_options);
struct option* long_options;
int m =0; // number of elements for each table
float pnratio=0.5;
int positive_m = 128; // number of elements for the positive cache
int cache_m = 1024; // number of rows for the negative cache
int stat_size = 1000000;
unsigned int flows=100; 
unsigned int sample_rate=0; 
int repeat; //number of trials
unsigned long seed; // value for initialization of random function
bool quiet=false;
bool multiplepcap=false;

int num_queries=0; // number of queries for lookup estimation
int policy=0; // 0: random 1: LRU 
int verbose; // set verbose level
int d; // number of probes
char filename[128]="/home/sal/traces/caida/imc/trace_univ2_pt7.pcap"; 

// generate random int in 0..x-1
int rand0K(int x) {
    //int result = int(genrand()*x);
    int result = rand() % x ;
    if (result==x) result--;
    return result;
}

// Init function. It is used to initialize the hash tables structures

void init(int argc, char **argv) {
    verbose=0;
    d=4;
    repeat=1;
    seed=time(NULL); // value for initialization of random function
    //print code version
    char str[512];
    sprintf(str,"%s",MD5);
    printf("Code version: \n");
    char* pch = strtok(str," ");
    while (pch != NULL){
	printf ("%s ",pch);
	pch = strtok (NULL," ");
	printf ("%s \n",pch);
	pch = strtok (NULL," ");
    }
    //print command line
    printf("Compiled @: %s \n",COMPILE_TIME);
#ifdef __SSE4_2__
    printf("With crc hash from Intel SSE4.2 \n");
#else
    printf("With software crc hash function \n");
#endif
/*    printf("With command line: ");
    char **currentArgv = argv;
    for (int i = 0; i < argc; i ++) {
	printf("%s ", *currentArgv); 
	currentArgv++; 
    }
    printf("\n");
*/
    // Check for switches
    int long_index =0;
    int opt= 0;

    static struct command_option long_command_options[] = {
	//{"option", optional_argument , flag, 'o'} //flag specifies how results are returned for a long option. 
	{"pnratio",             required_argument,  0,  'R', "P/N ratio"},
	{"quiet",               no_argument,        0,  'Q', "quiet"  },
	{"query",               required_argument,  0,  'q', "number of queries"  },
	{"policy",              required_argument,  0,  'P', "policy 0:random, 1:LRU"  },
	{"pcap",                required_argument,  0,  'p', "pcap file"  },
	{"mpcap",               no_argument,        0,  '1', "multiple pcap files"  },
	{"seed",                required_argument,  0,  's', "Initial random seed"  },
	{"size",                required_argument,  0,  'm', "number of rows in a table" },
	{"stat_size",           required_argument,  0,  'S', "configure the rate at which the stats about locality are produced " },
	{"cache_size",          required_argument,  0,  'M', "number of rows in the cache" },
	//{"positive_cache_size", required_argument,  0,  'c',  "number of entries of the positive cache" },
	{"flow",                required_argument,  0,  'f', "number of flows"   },
	{"sampling_rate",       required_argument,  0,  'F', "sampling rate"     },
	{"repeat",              required_argument,  0,  'r', "number of trials"  },
	{"verbose",             no_argument,        0,  'v', "verbose"  },
	{"help",                no_argument,        0,  'h', "print help "  },
	{0,                     0,                  0,   0 , ""  }
    };
    long_options = convert_options(long_command_options);

    while ((opt = getopt_long_only(argc, argv,"", long_options, &long_index )) != -1) {
	switch (opt) {
	    case 'R':
		pnratio = atoi(optarg)/1000.0; // number of rows
		break;
	    case 'Q':
		quiet=true; // number of rows
		break;
	    //case 'c':
		//positive_m = atoi(optarg); // number of rows
		//break;
	    case 'P':
		policy = atoi(optarg); // number of rows
		break;
	    case 'q':
		num_queries = atoi(optarg); // number of rows
		break;
	    case 'm':
		m = atoi(optarg); // number of rows
		break;
	    case 'M':
		cache_m = atoi(optarg); // number of rows
		break;
	    case 'S':
		stat_size = atoi(optarg); // number of rows
		break;
	    case '1':
		multiplepcap=true;
		break;
	    case 'p':
		strcpy(filename,optarg); // pcap filename 
		filenames[0]=strdup(filename);
		break;
	    case 's':
		seed = atoi(optarg); // seed for debug
		break;
	    case 'f':
		flows = atoi(optarg); // number of flows
		break;
	    case 'F':
		sample_rate = atoi(optarg); // sampling rate
		break;
	    case 'r':
		repeat = atoi(optarg); // how often to start from scratch
		break;
	    case 'v':
		printf("\nVerbose enabled\n");
		verbose += 1;
		break;
	    case 'h':
		PrintUsage(long_command_options);
		exit(1);
		break;
	    default :
		printf("Illegal option\n");
		PrintUsage(long_command_options);
		exit(1);
		break;
	}
    }

if (multiplepcap) {
	numfiles= argc-optind;
	cout << "numfiles: " << numfiles << std::endl;
	int j=0;
	for( int i = optind; i < argc; i++, j++) {
	    filenames[j]= strdup(argv[i]);
	//    cout << "file: " << filenames[j] << std::endl;
	}
	cout << "first file of split trace is : " << filenames[0] << std::endl;
	//cout << "first file of split trace is : " << mybasename(filenames[0]) << std::endl;
}
    printf("With command line: ");
    char **currentArgv = argv;
    for (int i = 0; i < optind; i ++) {
	printf("%s ", *currentArgv); 
	currentArgv++; 
    }
    printf("\n");



    printf("\n ------------------ \n");
    printf("With seed: %lu \n",seed);
    printf("number of table rows: %d \n",m);
    printf("number of cache rows: %d \n",cache_m);
    printf("number of trials %d \n",repeat);

    free(long_options);
} //end init

struct classcomp {
  bool operator() (const five_tuple& lhs, const five_tuple& rhs) const
  {
  if (lhs.sip < rhs.sip) return true;
  if (lhs.sip > rhs.sip) return false;
  if (lhs.dip < rhs.dip) return true;
  if (lhs.dip > rhs.dip) return false;
  if (lhs.proto < rhs.proto) return true;
  if (lhs.proto > rhs.proto) return false;
  if (lhs.sp < rhs.sp) return true;
  if (lhs.sp > rhs.sp) return false;
  return (lhs.dp < rhs.dp);
  }
};


// this function perform the run of the simulation
void run() {

    int64_t hit_map=0; 
    int64_t hit_cf=0; 
    int64_t hit_cache_positive=0; 
    int64_t two_caches_hit=0;
    int64_t two_caches_hit_positive=0;
    int64_t two_caches_hit_negative=0;
    int64_t hit_traditional_cache=0;
    int64_t hit_cache=0; 
    int64_t hit_cache_LRU=0; 
    int64_t queries=0; 
    int64_t tot_flows=0;
    time_t starttime,endtime;
    starttime= time(NULL);

    five_tuple key;
    //signal (SIGINT,my_handler);

    // main loop

    positive_m = (4*cache_m/15);
    cache<five_tuple> cache_positive2((1-pnratio)*positive_m);


    int temp_size = pnratio*cache_m;
    int temp_slot = 4;

    if (pnratio==0.75) { 
	temp_size = cache_m;
	temp_slot = 3;
    }
	  
    CF<five_tuple> cache_negative_cf_LRU2(temp_size,8,temp_slot);

    cache<five_tuple> traditional_cache(positive_m);
    cache<five_tuple> cache_positive(positive_m);
    CF<five_tuple> cache_negative_cf(cache_m,8,4);
    CF<five_tuple> cache_negative_cf_LRU(cache_m,8,4);
    map<five_tuple,int,classcomp> test_map;
    map<five_tuple,int,classcomp> tot_map;
    map<five_tuple,int,classcomp> split_map;

    map<int,int64_t> stat_map;
    map<int,int64_t> stat_r_map;
    vector<five_tuple> tot_ar;

    //cf1.clear();    
    cache_negative_cf.clear();    
    cache_negative_cf_LRU.clear();    
    //cache_positive.clear();    
    //cf1.clear();    
    test_map.clear();
    tot_map.clear();
    split_map.clear();
    tot_ar.clear();


    
    printf("***:CACHE CF:\n");
    printf("***:fingerprint bits: %d\n",8);
    printf("***:Rows: %d\n",cache_m);
    printf("***:Total size: %d\n",cache_negative_cf.get_size());
    printf("***:Total size (bits): %d\n",8*cache_negative_cf.get_size());
    printf("***:---------------------------\n");
    setbuf(stdout, NULL);

    printf("***:Traditional CACHE:\n");
    printf("***:Total size: %d\n",traditional_cache.get_size());
    printf("***:Total size (bits): %d\n",120*traditional_cache.get_size());
    printf("***:---------------------------\n");
    setbuf(stdout, NULL);

    printf("***:CACHE Positive:\n");
    printf("***:Total size: %d\n",cache_positive.get_size());
    printf("***:Total size (bits): %d\n",120*cache_positive.get_size());
    printf("***:---------------------------\n");
    setbuf(stdout, NULL);

    printf("***:CACHE Positive 2:\n");
    printf("***:Total size: %d\n",cache_positive2.get_size());
    printf("***:Total size (bits): %d\n",120*cache_positive2.get_size());
    printf("***:---------------------------\n");
    setbuf(stdout, NULL);

    printf("***:CACHE CF 2:\n");
    printf("***:fingerprint bits: %d\n",8);
    printf("***:Rows: %d\n",cache_m);
    printf("***:slots: %d\n",cache_negative_cf_LRU2.get_nslots() );
    printf("***:Total size: %d\n",cache_negative_cf_LRU2.get_size());
    printf("***:Total size (bits): %d\n",8*cache_negative_cf_LRU2.get_size());
    printf("***:---------------------------\n");
    setbuf(stdout, NULL);

//    for (int rep = 0;  rep < repeat;  rep++) {
	srand(++seed);
	//fprintf(stderr,"%d/%d\r",rep,repeat);
	//verprintf(" run number: %d/%d seed=%lu \n",rep,repeat,seed);
	int i =0;
	int64_t tot_pkt=0;

	//1: fill the main table 
        int stat_num=0; 
	while (-1!=read_IP_from_file(&key)){ // pcap type: ( 0: eth|ip 1: eth|vlan|ip 2: ip );
	    //std::cout << "-->" << key.sip << "," << key.dip << "," << key.proto << "," << key.sp << "," << key.dp <<'\n';
	    i++;
	    tot_pkt++;
	    if (tot_map.count(key)==0) {
		tot_ar.push_back(key);
	    }
	    tot_map[key]++; //# pkts of the flow
	    split_map[key]++; //# pkts of the flow
	    if (!(i%stat_size)) {
		//stat
		int split_flows=split_map.size();
		int topk=0;
		vector<pair<five_tuple, int>> sorted_vector;
		for (auto & k: split_map) {
		    sorted_vector.push_back(k);
		}
		std::sort(sorted_vector.begin(), sorted_vector.end(), [](std::pair<five_tuple,int> a, std::pair<five_tuple,int> b) {
			return ( b.second < a.second);
			});

                stat_num++;
		//printf("\n### Iteration num. %d ###\n",stat_num);
		//printf("\n### After %ld packets ###\n",tot_pkt);
		//printf("\n### Active flows: %d  ###\n",split_flows);
		for (int k=128; k<30000; k *= 2) {
		    topk = 0 ;
		    for (int ii=0; ii<k && ii< split_flows; ii++) {
			topk += sorted_vector[ii].second;
		    }
		    stat_map[k] += topk; 
		    stat_r_map[k] += 100*topk/(stat_size+0.0); 
		    //printf("Top-%d flows contains %d packets (%.0f %%)\n",k,topk, 100*topk/(stat_size+0.0) );
		} 
		split_map.clear();
	    }
	}
	
	start=false; // reset read_IP_from_file function
	currentfile=0;
	i =0;
	tot_flows=tot_map.size();
	if (multiplepcap) 
	    printf("the file list contains %ld flows and %ld packets\n",tot_flows,tot_pkt);
	else
	    printf("%s contains %ld flows and %ld packets\n",filenames[0],tot_flows,tot_pkt);


	//stat
	int topk=0;
	vector<pair<five_tuple, int>> sorted_vector;
	for (auto & k: tot_map) {
	    sorted_vector.push_back(k);
	}
	std::sort(sorted_vector.begin(), sorted_vector.end(), [](std::pair<five_tuple,int> a, std::pair<five_tuple,int> b) {
		return ( b.second < a.second);
		});

	printf("\n### Global ###\n");
	printf("### After %ld packets ###\n",tot_pkt);
	for (int k=128; k<30000; k *= 2) {
	    topk = 0 ;
	    for (int ii=0; ii<k && ii< tot_flows; ii++) {
		topk += sorted_vector[ii].second;
	    } 
	    printf("Top-%d flows contains %d packets\n",k,topk);
	} 

	printf("\n### Average (with %d windows )###",stat_num);
	printf("\n### Active flows: %ld  ###\n",tot_flows/stat_num);
	for (int k=128; k<30000; k *= 2) {
	    printf("Top-%d flows contains %ld packets (%.0f %%)\n",k,stat_map[k]/stat_num, 100*stat_map[k]/(stat_num*stat_size+0.0));
	} 
	

	//2: select N flows
	int tot_sampled_pkt=0;
        if (sample_rate!=0) flows =tot_flows/sample_rate;
	if (m==0) m= next_power_of_two(flows/2);

        CF<five_tuple> cf1(m,8,4);
	printf("***:CF:\n");
	printf("***:fingerprint bits: %d\n",8);
	printf("***:Rows: %d\n",m);
	printf("***:Total size: %d\n",cf1.get_size());
	printf("***:Total size (bits): %d\n",8*cf1.get_size());
	printf("***:---------------------------\n");
	
	while (test_map.size()<flows){ // pcap type: ( 0: eth|ip 1: eth|vlan|ip 2: ip );
	    i++;
	    int it= rand0K(tot_flows);
	    key = tot_ar[it];
	    test_map[key]=tot_map[key]; ///# pkts of the flow
	    tot_sampled_pkt +=tot_map[key];
	    //std::cout << "-->" << key.sip << "," << key.dip << "," << key.proto << "," << key.sp << "," << key.dp <<'\n';
	    // insert in cf
	    if(!(cf1.insert(key))) {
		printf("CF full \n");
		exit(1);
		break;
	    }
	    if (!(i%10000) && !quiet) printf(".");
	}
        printf("\n");
	printf("*** Selected %d flows with %d packets\n",flows,tot_sampled_pkt);


	//3: queries in the main table and in the cache 
	while (-1!=read_IP_from_file(&key)){ // pcap type: ( 0: eth|ip 1: eth|vlan|ip 2: ip );
	    //std::cout << "--->" << key.sip << "," << key.dip << "," << key.proto << "," << key.sp << "," << key.dp <<'\n';
	    queries++;
	    bool hit=false;
	    bool cacheable=true;
            if (test_map.count(key)>0) 
	    {
		verprintf("MAP: HIT\n");
		hit_map++;
		hit=true;
	    }
	    else 
		verprintf("MAP: MISS\n");


	    if (cf1.query(key))
	    {
		verprintf("CF: HIT\n");
		hit_cf++;
		cacheable=false;
	    }
	    else 
		verprintf("CF: MISS\n");

	    std::pair<int,int> pf=cf1.get_pf(key);
	    if ((cache_positive2.query(key,0)) ||(cache_negative_cf_LRU2.cache_query(key,pf.first,1))) two_caches_hit++;
	    if (cache_positive2.query(key,0)) two_caches_hit_positive++;
	    if (cache_negative_cf_LRU2.cache_query(key,pf.first,1)) two_caches_hit_negative++;

	    //TRADITIONAL 
	    if(traditional_cache.query(key,0)) 
	    {
		verprintf("TRADITIONAL CACHE: HIT\n");
		hit_traditional_cache++;
	    }
	    else {
		traditional_cache.insert(key,0);
		verprintf("TRADITIONAL CACHE: MISS\n");
	    }
	    //POSITIVE 
	    if(cache_positive.query(key,0)) 
	    {
		verprintf("CACHE POSITIVE: HIT\n");
		hit_cache_positive++;
		if(!hit) {
			printf("ERROR. FALSE POSITIVE\n"); 
			std::cout << "--->" << key.sip << "," << key.dip << "," << key.proto << "," << key.sp << "," << key.dp <<'\n';
			std::cout << cacheable << "\n";
			verbose=1;
			cache_positive.query(key,0); 
			exit(1);
			break; 
		}
	    }
	    else {
		if (hit) {
			//std::cout << "insert:" << key.sip << "," << key.dip << "," << key.proto << "," << key.sp << "," << key.dp <<'\n';
			cache_positive.insert(key,0);
		}
		verprintf("CACHE: MISS\n");
	    }

	    //POSITIVE 
	    if(cache_positive2.query(key,0)) 
	    {
		verprintf("CACHE POSITIVE: HIT\n");
		if(!hit) {
			printf("ERROR. FALSE POSITIVE\n"); 
			std::cout << "--->" << key.sip << "," << key.dip << "," << key.proto << "," << key.sp << "," << key.dp <<'\n';
			std::cout << cacheable << "\n";
			verbose=1;
			cache_positive2.query(key,0); 
			exit(1);
			break; 
		}
	    }
	    else {
		if (hit) {
			//std::cout << "insert:" << key.sip << "," << key.dip << "," << key.proto << "," << key.sp << "," << key.dp <<'\n';
			cache_positive2.insert(key,0);
		}
		verprintf("CACHE: MISS\n");
	    }


	    //NEGATIVE RANDOM
	    if(cache_negative_cf.cache_query(key,pf.first,0)) 
	    {
		verprintf("CACHE NEGATIVE: HIT\n");
		hit_cache++;
		if(hit) {
			printf("ERROR. FALSE NEGATIVE\n"); 
			std::cout << "--->" << key.sip << "," << key.dip << "," << key.proto << "," << key.sp << "," << key.dp <<'\n';
			std::cout << cacheable << "\n";
			verbose=1;
			cache_negative_cf.query(key); 
			exit(1);
			break; 
		}
	    }
	    else {
		if (cacheable && !hit) {
			//std::cout << "insert:" << key.sip << "," << key.dip << "," << key.proto << "," << key.sp << "," << key.dp <<'\n';
			cache_negative_cf.direct_insert(pf.first,pf.second,0);
		}
		verprintf("CACHE: MISS\n");
	    }
	    //NEGATIVE LRU
	    if(cache_negative_cf_LRU.cache_query(key,pf.first,1)) 
	    {
		verprintf("CACHE LRU NEGATIVE: HIT\n");
		hit_cache_LRU++;
		if(hit) {
			printf("ERROR. FALSE NEGATIVE\n"); 
			std::cout << "--->" << key.sip << "," << key.dip << "," << key.proto << "," << key.sp << "," << key.dp <<'\n';
			std::cout << cacheable << "\n";
			verbose=1;
			cache_negative_cf_LRU.query(key); 
			exit(1);
			break; 
		}
	    }
	    else {
		if (cacheable && !hit) {
			//std::cout << "insert:" << key.sip << "," << key.dip << "," << key.proto << "," << key.sp << "," << key.dp <<'\n';
			cache_negative_cf_LRU.direct_insert(pf.first,pf.second,1);
		}
		verprintf("CACHE LRU: MISS\n");
	    }
	    if(cache_negative_cf_LRU2.cache_query(key,pf.first,1)) 
	    {
		verprintf("CACHE LRU NEGATIVE: HIT\n");
		if(hit) {
			printf("ERROR. FALSE NEGATIVE\n"); 
			std::cout << "--->" << key.sip << "," << key.dip << "," << key.proto << "," << key.sp << "," << key.dp <<'\n';
			std::cout << cacheable << "\n";
			verbose=1;
			cache_negative_cf_LRU2.query(key); 
			exit(1);
			break; 
		}
	    }
	    else {
		if (cacheable && !hit) {
			//std::cout << "insert:" << key.sip << "," << key.dip << "," << key.proto << "," << key.sp << "," << key.dp <<'\n';
			cache_negative_cf_LRU2.direct_insert(pf.first,pf.second,1);
		}
		verprintf("CACHE LRU: MISS\n");
	    }


	    if (!(queries%10000000)&& !quiet) printf("*");
	    if (queries==num_queries) break;
	}
	printf("\n");
	//pcap_close(handle);
//    } // end trial loop

    //printf("DUMP:\n");
    //cache_negative_cf_LRU2.dump();
    
    std::cout << std::fixed << std::setprecision(2) << "*** tot number of flow: " << tot_flows << std::endl;
    std::cout << std::fixed << std::setprecision(2) << "*** main table size: " << test_map.size() << std::endl;
    std::cout << std::fixed << std::setprecision(2) << "*** main CF size: " << cf1.get_nitem() << std::endl;
    std::cout << std::fixed << std::setprecision(2) << "*** main table hit: " << hit_map << " " << 100*hit_map/(queries+0.0) << "%" << std::endl;
    std::cout << std::fixed << std::setprecision(2) << "*** cache size: " << cache_negative_cf.get_size() << std::endl;
    std::cout << std::fixed << std::setprecision(2) << "*** main CF hit: " << hit_cf << " " << 100*hit_cf/(queries+0.0) << "%" << std::endl;
    std::cout << std::fixed << std::setprecision(2) << "*** Traditional CACHE hit: " << hit_traditional_cache  << " " << 100*hit_traditional_cache/(queries+0.0) << "%" << std::endl;
    std::cout << std::fixed << std::setprecision(2) << "*** POSITIVE CACHE hit: " << hit_cache_positive  << " " << 100*hit_cache_positive/(queries+0.0) << "%" << std::endl;
    std::cout << std::fixed << std::setprecision(2) << "*** CACHE NEGATIVE hit: " << hit_cache << " " << 100*hit_cache/(queries+0.0) << "%" << std::endl;
    std::cout << std::fixed << std::setprecision(2) << "*** CACHE LRU NEGATIVE hit: " << hit_cache_LRU << " " << 100*hit_cache_LRU/(queries+0.0) << "%" << std::endl;
    std::cout << std::fixed << std::setprecision(2) << "*** 2 CACHES hit: " << two_caches_hit  << " " << 100*two_caches_hit/(queries+0.0) << "%" << std::endl;
    std::cout << std::fixed << std::setprecision(2) << "*** queries: " << queries << std::endl;



    printf("#stat:  Cache size, N ratio, sample rate, hit_traditional,  hit_cache\n");
    printf("stat:  %s: %d \t %.2f%% \t %.2f%% \t %.2f%% \t %.2f%% \n", mybasename(filenames[0]), 4*cache_m, 100*pnratio, 100/(0.0+sample_rate), 100*hit_traditional_cache/(queries+0.0),  100*two_caches_hit/(queries+0.0));



    endtime = time(NULL);
    struct tm * timeinfo=localtime(&starttime);
    double second = difftime(endtime,starttime);
    std::cout << "\nsimulation started @: " << asctime(timeinfo) << std::endl;
    timeinfo=localtime(&endtime);
    std::cout << "simulation ended   @: " << asctime(timeinfo) << std::endl;
    std::cout << "simulation time: " << second << " sec" << std::endl;
    if (queries==num_queries) pcap_close(handle);
}




int main(int argc, char **argv) {
    init(argc,argv);
    run();
}

// Function to print the program usage

void PrintUsage( struct command_option* long_options){
    printf("\n");
    int i=0;
    printf("Usage: cn ");
    while (long_options[i].name !=NULL ) {
	if (long_options[i].has_arg == required_argument) printf("[--%s N] ",long_options[i].name);
	else printf("[--%s] ",long_options[i].name);
	i++;
    }
    printf("\n\n");
    i=0;
    while (long_options[i].name !=NULL ) {
	std::string s;
	if (long_options[i].has_arg == required_argument)  
	    s= "[--" +  std::string(long_options[i].name) +  " N]";
	else 
	    s= "[--" +  std::string(long_options[i].name) +  "]";
	std::cout << std::left <<  std::setw(30) << s;
	std::cout << std::left << long_options[i].help_sentence << std::endl;
	i++;
    }

    //exit(1);
}


