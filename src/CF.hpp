#include <utility>
#include <cstdint> // include this header for uint64_t
using namespace std;



// https://stackoverflow.com/questions/8752837/undefined-reference-to-template-class-constructor
// add in the CF.cpp the template class eg:


template <typename key_type> class CF {
		//int ***table;//  memory
		int **table;//  memory
		int **table_lsb;//  memory
		int   cf_size; // size of CF memory
		int   fp_size;    // 1<<f
		int   num_item;   	// number of inserted item
		int   num_access;   	// number of inserted item
		int   num_slots;   	// number of slots
		int victim_fingerprint;
		int victim_pointer;
		bool insert2(int p,int fingerprint);

		public:
		CF(int M,int f,int slots);
		//CF(int M,int f);
		virtual ~CF();
		void clear();
		void dump();

		bool direct_insert(const key_type key, const int policy);
		//bool direct_insert(const int p, const int f);
		bool direct_insert(const int p, const int f, int policy);
		bool insert(const key_type key);
		bool query(const key_type key);
		bool cache_query(const key_type key, const int p_in);
		bool cache_query(const key_type key, const int p_in, const int policy);
		bool check(const key_type key) {return query(key);}
		pair<int,int> get_pf(const key_type key);
		int get_nslots() {return num_slots;}
		int get_nitem() {return num_item;}
		int get_size() {return  num_slots*cf_size;}
		int get_numaccess() {return num_access;}

};

template <typename key_type> class cache {
		//int ***table;//  memory
		key_type *table;//  memory
		int  cache_size; // size of cache memory
		int  num_item;   	// number of inserted item

		public:
		cache(int M);
		virtual ~cache();
		//void clear();

		bool insert(const key_type key, const int policy);
		bool query(const key_type key,const int policy);
		int get_size() {return cache_size;}
		int get_nitem() {return num_item;}
};

