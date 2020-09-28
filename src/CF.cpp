#include "CF.hpp"
#include <iostream>
#include "utils.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <functional>
#include <cstring>
#include <smmintrin.h>
#include "xxhash.h"

inline uint64 CityHash64WithSeed(int64_t key, uint64_t seed)
{
 return CityHash64WithSeed((const char *)&key,8,seed);
}


template <typename T>  
uint64 CityHash(T key, uint64_t seed) 
{
    //char* k = reinterpret_cast<char*>(&key);
    char* k= (char*) malloc(sizeof(T));
    k = (char*) memcpy(k,&key,sizeof(T));
    uint64 r= CityHash64WithSeed(k,sizeof(T),seed);
    free(k);
    return r;
}

template <typename T>  
uint64 CRCHash(T key, uint64_t seed) 
{
    char* k= (char*) malloc(sizeof(T));
    k = (char*) memcpy(k,&key,sizeof(T));

    XXH64_hash_t r=XXH64(k,sizeof(T),seed);
    free(k);
    return (uint64) r;
}

template <typename T>  
uint64 CityHash(std::string key, uint64_t seed) 
{
    return CityHash64WithSeed(key.c_str(),key.length(),seed);
}

template <typename key_type> int myhash(key_type key, int i, int s) {
    uint64_t   val;
    int ss=s;

    val=CityHash<key_type>(key,2137+i);
    //val=CRCHash<key_type>(key,2137+i);
    return (val %ss);
}

/*
 * Constructor
 */


extern int verbose; // define the debug level

template <typename key_type>
CF<key_type>::CF(int M,int f, int slot)
{
  cf_size=M;
  fp_size=(1<<f);
  num_slots=slot;
  if (cf_size>0) {
      table = new int*[M];
      table_lsb = new int*[M];
      for (int i = 0;  i < M;  i++) {table[i]= new int[num_slots]; table_lsb[i]= new int[num_slots]; }
      clear();
  }
}

/*template <typename key_type>
CF<key_type>::CF(int M,int f)
{
	//CF<key_type>::CF(M,f,4);
	CF<key_type>(M,f,4);
}
*/
/*
 * Distructor
 */
template <typename key_type>
CF<key_type>::~CF()
{
	//for (int i = 0;  i < cf_size;  i++) delete[] table[0][i];
	//for (int i = 0;  i < cf_size;  i++) delete[] table[1][i];
	//delete[] table[0];
	//delete[] table[1];
  if (cf_size>0) {
	for (int i = 0;  i < cf_size;  i++) delete[] table[i];
	for (int i = 0;  i < cf_size;  i++) delete[] table_lsb[i];
	delete[] table;
	delete[] table_lsb;
  }
}

//DUMP
template <typename key_type>
void CF<key_type>::dump()
{
  if (cf_size>0) {
	for(int i=0; i<cf_size; i++) {
	    for(int ii=0; ii<4; ii++) {
		printf("table[%d][%d] = %d, %d \n", i,ii, table[i][ii],table_lsb[i][ii]);
	}
	}
  }
}

/*
 * Clear
 */

template <typename key_type>
void CF<key_type>::clear()
{
	num_item=0; num_access=0;
	victim_fingerprint=-1;
	victim_pointer=-1;
  if (cf_size>0) {
	for(int i=0; i<cf_size; i++) {
            table[i][0]=-1;
            table[i][1]=-1;
            table[i][2]=-1;
            table[i][3]=-1;
            table_lsb[i][0]=0;
            table_lsb[i][1]=0;
            table_lsb[i][2]=0;
            table_lsb[i][3]=0;
        }
  }
}

/*
 * Insert
 */
template <typename key_type>
bool CF<key_type>::insert(key_type key)
{
  if (cf_size==0) return true;
  if (query(key)) return true;
  int fingerprint=myhash<key_type>(key,1,fp_size);
  int p=myhash<key_type>(key,2,cf_size);
  p=p % cf_size;
  //Debug1(printf("insert item %d \n",i);)
  //Debug1(printf("p= %d, f=%d\n",p,fingerprint);)
  return insert2(p,fingerprint);
}

template <typename key_type>
bool CF<key_type>::insert2(int p,int fingerprint)
{
  int t;
  int newf=-1;
  int j=0;
  int jj=0;
  if (cf_size==0) return true;

  for (t = 1;  t <= 500;  t++) {
      for (jj = 0;  jj < num_slots;  jj++) {
          p=p % cf_size;
            verprintf("i2: item in table[%d][%d] for p=%d and f=%u\n",p,jj,p,fingerprint);
            //verprintf("read f=%d\n",table[j][p][jj]);
            //if (table[0][p][jj] == -1) {
            //    table[0][p][jj]=fingerprint;
            if (table[p][jj] == -1){
                table[p][jj]=fingerprint;
                num_item++;
                verprintf("inserted in table[%d][%d] f=%u\n",p,jj,fingerprint);
                return true;
            }
            int p1=p^myhash<int>(fingerprint,2,1<<30);
            p1=p1 % cf_size;
            verprintf("i2: item in table[%d][%d] for p1=%d and f=%u\n",p1,jj,p1,fingerprint);
            if (table[p1][jj] == -1) {
                table[p1][jj]=fingerprint;
                num_item++;
                verprintf("inserted in table[%d][%d] f=%u\n",p1,jj,fingerprint);
                return true;
            }
      } // all place are full
      j = rand() % 2;
      jj = rand() % num_slots;
      p=p^(j*myhash<int>(fingerprint,2,1<<30));
      p=p % cf_size;
      newf = table[p][jj];
      table[p][jj]=fingerprint;
      verprintf("inserted in table[%d][%d] f=%u\n",p,jj,fingerprint);
      fingerprint = newf; // find new home for cuckoo victim
  }
  victim_pointer=p;
  victim_fingerprint=fingerprint;
  return false; // insertion failed
}

template <typename key_type>
bool CF<key_type>::direct_insert(key_type key, const int policy)
{
  if (cf_size==0) return true;
    if (query(key)) {
	printf ("item already here!!!\n");
	return true;
    }
    int fingerprint=myhash<key_type>(key,1,fp_size);
    int p=myhash<key_type>(key,2,cf_size);
    p=p % cf_size;
    int jj=0;
    for (jj = 0;  jj < num_slots;  jj++) {
            verprintf("di: item in table[%d][%d] for p=%d and f=%u\n",p,jj,p,fingerprint);
            //verprintf("read f=%d\n",table[j][p][jj]);
            //if (table[0][p][jj] == -1) {
            //    table[0][p][jj]=fingerprint;
            if (table[p][jj] == -1){
                table[p][jj]=fingerprint;
                num_item++;
                verprintf("inserted in table[%d][%d] f=%u\n",p,jj,fingerprint);
                return true;
            }
            int p1=p^myhash<int>(fingerprint,2,1<<30);
            p1=p1 % cf_size;
            verprintf("i2: item in table[%d][%d] for p1=%d and f=%u\n",p1,jj,p1,fingerprint);
            if (table[p1][jj] == -1) {
                table[p1][jj]=fingerprint;
                num_item++;
                verprintf("inserted in table[%d][%d] f=%u\n",p1,jj,fingerprint);
                return true;
	    }
    } // all place are full
    int j = rand() % 2;
    jj = rand() % num_slots;
    if (policy==1)  jj=num_slots-1;
    p=p^(j*myhash<int>(fingerprint,2,1<<30));
    p=p % cf_size;
    //int newf = table[p][jj];
    table[p][jj]=fingerprint;
    verprintf("inserted in table[%d][%d] f=%u\n",p,jj,fingerprint);
    return true;
}

template <typename key_type>
bool CF<key_type>::direct_insert(const int p_in, const int f_in, const int policy)
{
  if (cf_size==0) return true;
    int fingerprint=f_in; 
    int p=p_in % cf_size;
    int jj=0;
    for (jj = 0;  jj < num_slots;  jj++) {
            verprintf("di: item in table[%d][%d] for p=%d and f=%u\n",p,jj,p,fingerprint);
            //verprintf("read f=%d\n",table[j][p][jj]);
            //if (table[0][p][jj] == -1) {
            //    table[0][p][jj]=fingerprint;
            if (table[p][jj] == -1){
                table[p][jj]=fingerprint;
                table_lsb[p][jj]=p_in;
                num_item++;
                verprintf("inserted in table[%d][%d] f=%u\n",p,jj,fingerprint);
                return true;
            }
            int p1=p^myhash<int>(fingerprint,2,1<<30);
            p1=p1 % cf_size;
            verprintf("i2: item in table[%d][%d] for p1=%d and f=%u\n",p1,jj,p1,fingerprint);
            if (table[p1][jj] == -1) {
                table[p1][jj]=fingerprint;
                table_lsb[p1][jj]=p_in;
                num_item++;
                verprintf("inserted in table[%d][%d] f=%u\n",p1,jj,fingerprint);
                return true;
	    }
    } // all place are full

    int j = rand() % 2;
    jj = rand() % num_slots;
    if (policy==1)  jj=num_slots-1;
    p=p^(j*myhash<int>(fingerprint,2,1<<30));
    p=p % cf_size;
    //int newf = table[p][jj];
    table[p][jj]=fingerprint;
    table_lsb[p][jj]=p_in;
    verprintf("inserted in table[%d][%d] f=%u\n",p,jj,fingerprint);
    return true;
}

/*
 * Query
 */

template <typename key_type>
bool CF<key_type>::query(const key_type key)
{
  if (cf_size==0) return false;
    //std::cout << "<-->" << key.sip << "," << key.dip << "," << key.proto << "," << key.sp << "," << key.dp <<'\n';
    int fingerprint=myhash<key_type>(key,1,fp_size);
    fingerprint= fingerprint % fp_size;
    int p=myhash<key_type>(key,2,cf_size);
    if ((fingerprint==victim_fingerprint) && (p==victim_pointer)) return true;
    for (int j = 0;  j < 2;  j++) {
        p = myhash<key_type>(key,2,cf_size)^(j*myhash<int>(fingerprint,2,1<<30));
        p = p % cf_size;
        for (int jj = 0;  jj < num_slots;  jj++) {
            fingerprint= fingerprint % fp_size;
            //verprintf("query item in table[%d][%d] for p=%d and f=%d\n",p,jj,p,fingerprint);
            //verprintf("result is: %d\n",table[p][jj]);
            num_access++;
            if (table[p][jj] == fingerprint) {
                return true;
            }
        }
    }
    return false;
}

template <typename key_type>
bool CF<key_type>::cache_query(const key_type key, const int p_in)
{
    return  CF<key_type>::cache_query(key,p_in,0);
}

template <typename key_type>
bool CF<key_type>::cache_query(const key_type key, const int p_in, const int policy)
{
    if (cf_size==0) return false;
    int fingerprint=myhash<key_type>(key,1,fp_size);
    fingerprint= fingerprint % fp_size;
    int p=myhash<key_type>(key,2,cf_size);
    if ((fingerprint==victim_fingerprint) && (p==victim_pointer)) return true;
    for (int j = 0;  j < 2;  j++) {
        p = myhash<key_type>(key,2,cf_size)^(j*myhash<int>(fingerprint,2,1<<30));
        p = p % cf_size;
        for (int jj = 0;  jj < num_slots;  jj++) {
            fingerprint= fingerprint % fp_size;
            verprintf("query item in table[%d][%d] for p=%d and f=%d\n",p,jj,p,fingerprint);
            verprintf("result is: %d\n",table[p][jj]);
            num_access++;
            if ((table[p][jj] == fingerprint) && (table_lsb[p][jj]==p_in)) {
		if (policy==1){ //LRU
		    for (int z=jj; z>0; z--) {
			table[p][z] = table[p][z-1]; 
		    	table_lsb[p][z] = table_lsb[p][z-1]; 
		    }
		    table[p][0] = fingerprint;
		    table_lsb[p][0]=p_in;
		}
                return true;
            }
        }
    }
    return false;
}







template <typename key_type>
std::pair<int,int> CF<key_type>::get_pf(const key_type key) {
    int fingerprint=myhash<key_type>(key,1,fp_size);
    fingerprint= fingerprint % fp_size;
    int p=myhash<key_type>(key,2,cf_size);
    return make_pair(p,fingerprint);
}




template <typename key_type>
cache<key_type>::cache(int M)
{
  cache_size=M;
  if (cache_size>0)
	  table = new key_type[M];
  //for (int i = 0;  i < M;  i++) {table[i]= new int[4]; table_lsb[i]= new int[4]; }
  //clear();
}

/*
 * Distructor
 */
template <typename key_type>
cache<key_type>::~cache()
{
	//(for (int i = 0;  i < cf_size;  i++) delete[] table[i];
  if (cache_size>0)
	delete[] table;
}


/*
 * Clear
 */
/*
template <typename key_type>
void cache<key_type>::clear()
{
	num_item=0;
	for(int i=0; i<cf_size; i++) {
            table[i]=;
        }
}
*/


template <typename key_type>
bool cache<key_type>::insert(key_type key, const int policy)
{
  if (cache_size==0) return true;
    if (query(key,policy)) {
	printf ("item already here!!!\n");
	return true;
    }
    int p=myhash<key_type>(key,2,cache_size);
    p=p % cache_size;
    table[p]=key;
    verprintf("inserted in table[%d] \n",p);
    return true;
}


template <typename key_type>
bool cache<key_type>::query(key_type key, const int policy)
{
    if (cache_size==0) return false;
    int p=myhash<key_type>(key,2,cache_size);
    p=p % cache_size;
    if (table[p]==key) 
        return true;
    else 
        return false;
}

template class CF<five_tuple>;
template class cache<five_tuple>;
