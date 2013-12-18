#include <math.h>
#include <stdint.h>
#include <uint256.h>
#include <vector>

#include <pthread.h>

#include <iostream>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

extern "C" {
	void applog(int prio, const char *fmt, ...);

	uint32_t CalculateBestBirthdayHash(unsigned char *head, unsigned char *data, char *scratchpad, int totalThreads, volatile unsigned long *restart);
}

std::vector< std::pair<uint32_t,uint32_t> > momentum_search( uint256 midHash, char* scratchpad, int totalThreads );

#define PSUEDORANDOM_DATA_SIZE 30 //2^30 = 1GB
#define PSUEDORANDOM_DATA_CHUNK_SIZE 6 //2^6 = 64 bytes
#define L2CACHE_TARGET 16 // 2^16 = 64K
#define AES_ITERATIONS 50

// useful constants
uint32_t psuedoRandomDataSize=(1<<PSUEDORANDOM_DATA_SIZE);
uint32_t cacheMemorySize = (1<<L2CACHE_TARGET);
uint32_t chunks=(1<<(PSUEDORANDOM_DATA_SIZE-PSUEDORANDOM_DATA_CHUNK_SIZE));
uint32_t chunkSize=(1<<(PSUEDORANDOM_DATA_CHUNK_SIZE));
uint32_t comparisonSize=(1<<(PSUEDORANDOM_DATA_SIZE-L2CACHE_TARGET));

typedef struct {
    char *mainMemoryPsuedoRandomData;
    int threadNumber;
    int totalThreads;
    uint256 midHash;
    volatile unsigned long *restart; // TODO
} SHA512FillerArgs_t;

static void *SHA512Filler(void *pargs){
	// Thread arguments
	SHA512FillerArgs_t *args = (SHA512FillerArgs_t *)pargs;

	char *mainMemoryPsuedoRandomData = args->mainMemoryPsuedoRandomData;
    int threadNumber = args->threadNumber;
    int totalThreads = args->totalThreads;
    uint256 midHash = args->midHash;
    volatile unsigned long *restart = args->restart;
	
	//Generate psuedo random data to store in main memory
	unsigned char hash_tmp[sizeof(midHash)];
	memcpy((char*)&hash_tmp[0], (char*)&midHash, sizeof(midHash) );
	uint32_t* index = (uint32_t*)hash_tmp;
	
	uint32_t chunksToProcess=chunks/totalThreads;
	uint32_t startChunk=threadNumber*chunksToProcess;
	
	for( uint32_t i = startChunk; i < startChunk+chunksToProcess;  i++){
		*index = i;
		SHA512((unsigned char*)hash_tmp, sizeof(hash_tmp), (unsigned char*)&(mainMemoryPsuedoRandomData[i*chunkSize]));
		//This can take a while, so check periodically to see if we need to kill the thread
		/*if(i%100000==0){
			try{
				//If parent has requested termination
				boost::this_thread::interruption_point();
			}catch( boost::thread_interrupted const& e ){
     				throw e;
			}
		}*/
	}

	return NULL;
}

typedef struct {
    char *mainMemoryPsuedoRandomData;
    int threadNumber;
    int totalThreads;
    std::vector< std::pair<uint32_t,uint32_t> > *results;
    volatile unsigned long *restart; // TODO
} aesSearch_t;

static void *aesSearch(void *pargs){
	// Thread arguments
	aesSearch_t *args = (aesSearch_t *)pargs;

	char *mainMemoryPsuedoRandomData = args->mainMemoryPsuedoRandomData;
    int threadNumber = args->threadNumber;
    int totalThreads = args->totalThreads;
    std::vector< std::pair<uint32_t,uint32_t> > *results = args->results;
    volatile unsigned long *restart = args->restart;

	//Allocate temporary memory
	unsigned char *cacheMemoryOperatingData;
	unsigned char *cacheMemoryOperatingData2;	
	cacheMemoryOperatingData=new unsigned char[cacheMemorySize+16];
	cacheMemoryOperatingData2=new unsigned char[cacheMemorySize];

	//Create references to data as 32 bit arrays
	uint32_t* cacheMemoryOperatingData32 = (uint32_t*)cacheMemoryOperatingData;
	uint32_t* cacheMemoryOperatingData322 = (uint32_t*)cacheMemoryOperatingData2;
	uint32_t* mainMemoryPsuedoRandomData32 = (uint32_t*)mainMemoryPsuedoRandomData;
	
	//Search for pattern in psuedorandom data
	//AES_KEY AESkey;
	EVP_CIPHER_CTX ctx;
	unsigned char key[32] = {0};
	unsigned char iv[AES_BLOCK_SIZE];
	int outlen1, outlen2;
			
	
	//Iterate over the data
	int searchNumber=comparisonSize/totalThreads;
	int startLoc=threadNumber*searchNumber;
	for(uint32_t k=startLoc;k<startLoc+searchNumber;k++){
		
		//This can take a while, so check periodically to see if we need to kill the thread
		/*if(k%100==0){
			try{
				//If parent has requested termination
				boost::this_thread::interruption_point();
			}catch( boost::thread_interrupted const& e ){
				//free memory
				delete [] cacheMemoryOperatingData;
				delete [] cacheMemoryOperatingData2;
				isComplete[threadNumber]=1;
				throw e;
			}
		}*/
		
		//copy 64k of data to first l2 cache
		memcpy((char*)&cacheMemoryOperatingData[0], (char*)&mainMemoryPsuedoRandomData[k*cacheMemorySize], cacheMemorySize);
		
		for(int j=0;j<AES_ITERATIONS;j++){

			//use last 4 bits of first cache as next location
			uint32_t nextLocation = cacheMemoryOperatingData32[(cacheMemorySize/4)-1]%comparisonSize;

			//Copy data from indicated location to second l2 cache -
			memcpy((char*)&cacheMemoryOperatingData2[0], (char*)&mainMemoryPsuedoRandomData[nextLocation*cacheMemorySize], cacheMemorySize);

			//XOR location data into second cache
			for(uint32_t i = 0; i < cacheMemorySize/4; i++){
				cacheMemoryOperatingData322[i] = cacheMemoryOperatingData32[i] ^ cacheMemoryOperatingData322[i];
			}

			//AES Encrypt using last 256bits of Xorred value as key
			//AES_set_encrypt_key((unsigned char*)&cacheMemoryOperatingData2[cacheMemorySize-32], 256, &AESkey);
			
			//Use last X bits as initial vector
			
			//AES CBC encrypt data in cache 2, place it into cache 1, ready for the next round
			//AES_cbc_encrypt((unsigned char*)&cacheMemoryOperatingData2[0], (unsigned char*)&cacheMemoryOperatingData[0], cacheMemorySize, &AESkey, iv, AES_ENCRYPT);
			
			memcpy(key,(unsigned char*)&cacheMemoryOperatingData2[cacheMemorySize-32],32);
			memcpy(iv,(unsigned char*)&cacheMemoryOperatingData2[cacheMemorySize-AES_BLOCK_SIZE],AES_BLOCK_SIZE);
			EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), key, iv);
			EVP_EncryptUpdate(&ctx, cacheMemoryOperatingData, &outlen1, cacheMemoryOperatingData2, cacheMemorySize);
			EVP_EncryptFinal(&ctx, cacheMemoryOperatingData + outlen1, &outlen2);
			EVP_CIPHER_CTX_cleanup(&ctx);
			//printf("length: %d\n", sizeof(cacheMemoryOperatingData2));
		}
		
		//use last X bits as solution
		uint32_t solution=cacheMemoryOperatingData32[(cacheMemorySize/4)-1]%comparisonSize;
		//printf("solution - %d / %u \n",k,solution);
				
		if(solution==1968){
			uint32_t proofOfCalculation=cacheMemoryOperatingData32[(cacheMemorySize/4)-2];
			applog(2 /* LOG_INFO */, "Found solution - %u / %u / %u",k,solution,proofOfCalculation);
			(*results).push_back( std::make_pair( k, proofOfCalculation ) );
		}
	}
	
	//free memory
	delete [] cacheMemoryOperatingData;
	delete [] cacheMemoryOperatingData2;

	return NULL;
}

std::vector< std::pair<uint32_t,uint32_t> > momentum_search( uint256 midHash, char *mainMemoryPsuedoRandomData, int totalThreads, volatile unsigned long *restart){
	
	// printf("Start Search\n");
	//Take note of the current block, so we can interrupt the thread if a new block is found.
	// CBlockIndex* pindexPrev = pindexBest;
	
	std::vector< std::pair<uint32_t,uint32_t> > results;
			
	//results=new vector< std::pair<uint32_t,uint32_t> >;
	//results=NULL;
	
	//clock_t t1 = clock();
	pthread_t *threads = new pthread_t[totalThreads];
	SHA512FillerArgs_t *sha512ThreadsArgs=new SHA512FillerArgs_t[totalThreads];
	for (int i = 0; i < totalThreads; i++){
		sha512ThreadsArgs[i].mainMemoryPsuedoRandomData = mainMemoryPsuedoRandomData;
		sha512ThreadsArgs[i].totalThreads = totalThreads;
		sha512ThreadsArgs[i].threadNumber = i;
		sha512ThreadsArgs[i].midHash = midHash;
		sha512ThreadsArgs[i].restart = restart;

		memset(&threads[i], 0, sizeof(pthread_t));
		pthread_create(&threads[i], NULL, SHA512Filler, &sha512ThreadsArgs[i]);
	}

	//Wait for all threads to complete
	for (int i = 0; i < totalThreads; i++){
		pthread_join(threads[i], NULL);
	}
	delete[] sha512ThreadsArgs;
	delete[] threads;
	
	//clock_t t2 = clock();
	//printf("create psuedorandom data %f\n",(float)t2-(float)t1);

	threads = new pthread_t[totalThreads];
	aesSearch_t *aesThreadsArgs=new aesSearch_t[totalThreads];
	for (int i = 0; i < totalThreads; i++){
		aesThreadsArgs[i].mainMemoryPsuedoRandomData = mainMemoryPsuedoRandomData;
		aesThreadsArgs[i].totalThreads = totalThreads;
		aesThreadsArgs[i].threadNumber = i;
		aesThreadsArgs[i].results = &results;
		aesThreadsArgs[i].restart = restart;

		memset(&threads[i], 0, sizeof(pthread_t));
		pthread_create(&threads[i], NULL, aesSearch, &aesThreadsArgs[i]);
	}

	//Wait for all threads to complete
	for (int i = 0; i < totalThreads; i++){
		pthread_join(threads[i], NULL);
	}

	delete[] aesThreadsArgs;
	delete[] threads;
	
	//clock_t t3 = clock();
	//printf("comparisons %f\n",(float)t3-(float)t2);
	return results;
}

bool momentum_verify( uint256 midHash, uint32_t a, uint32_t b ){
	//return false;
	
	//Basic check
	if( a > comparisonSize ) return false;
	
	//Allocate memory required
	unsigned char *cacheMemoryOperatingData;
	unsigned char *cacheMemoryOperatingData2;	
	cacheMemoryOperatingData=new unsigned char[cacheMemorySize+16];
	cacheMemoryOperatingData2=new unsigned char[cacheMemorySize];
	uint32_t* cacheMemoryOperatingData32 = (uint32_t*)cacheMemoryOperatingData;
	uint32_t* cacheMemoryOperatingData322 = (uint32_t*)cacheMemoryOperatingData2;
	
	unsigned char  hash_tmp[sizeof(midHash)];
	memcpy((char*)&hash_tmp[0], (char*)&midHash, sizeof(midHash) );
	uint32_t* index = (uint32_t*)hash_tmp;
	
	//AES_KEY AESkey;
	//unsigned char iv[AES_BLOCK_SIZE];
	
	uint32_t startLocation=a*cacheMemorySize/chunkSize;
	uint32_t finishLocation=startLocation+(cacheMemorySize/chunkSize);
		
	//copy 64k of data to first l2 cache		
	for( uint32_t i = startLocation; i <  finishLocation;  i++){
		*index = i;
		SHA512((unsigned char*)hash_tmp, sizeof(hash_tmp), (unsigned char*)&(cacheMemoryOperatingData[(i-startLocation)*chunkSize]));
	}
	
	EVP_CIPHER_CTX ctx;
	unsigned char key[32] = {0};
	unsigned char iv[AES_BLOCK_SIZE];
	int outlen1, outlen2;
	
	//memset(cacheMemoryOperatingData2,0,cacheMemorySize);
	for(int j=0;j<AES_ITERATIONS;j++){
		
		//use last 4 bits as next location
		startLocation = (cacheMemoryOperatingData32[(cacheMemorySize/4)-1]%comparisonSize)*cacheMemorySize/chunkSize;
		finishLocation=startLocation+(cacheMemorySize/chunkSize);
		for( uint32_t i = startLocation; i <  finishLocation;  i++){
			*index = i;
			SHA512((unsigned char*)hash_tmp, sizeof(hash_tmp), (unsigned char*)&(cacheMemoryOperatingData2[(i-startLocation)*chunkSize]));
		}

		//XOR location data into second cache
		for(uint32_t i = 0; i < cacheMemorySize/4; i++){
			cacheMemoryOperatingData322[i] = cacheMemoryOperatingData32[i] ^ cacheMemoryOperatingData322[i];
		}
			
		//AES Encrypt using last 256bits as key
		//AES_set_encrypt_key((unsigned char*)&cacheMemoryOperatingData2[cacheMemorySize-32], 256, &AESkey);			
		//memcpy(iv,(unsigned char*)&cacheMemoryOperatingData2[cacheMemorySize-AES_BLOCK_SIZE],AES_BLOCK_SIZE);
		//AES_cbc_encrypt((unsigned char*)&cacheMemoryOperatingData2[0], (unsigned char*)&cacheMemoryOperatingData[0], cacheMemorySize, &AESkey, iv, AES_ENCRYPT);
		
		memcpy(key,(unsigned char*)&cacheMemoryOperatingData2[cacheMemorySize-32],32);
		memcpy(iv,(unsigned char*)&cacheMemoryOperatingData2[cacheMemorySize-AES_BLOCK_SIZE],AES_BLOCK_SIZE);
		EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), key, iv);
		EVP_EncryptUpdate(&ctx, cacheMemoryOperatingData, &outlen1, cacheMemoryOperatingData2, cacheMemorySize);
		EVP_EncryptFinal(&ctx, cacheMemoryOperatingData + outlen1, &outlen2);
		EVP_CIPHER_CTX_cleanup(&ctx);
		
	}
		
	//use last X bits as solution
	uint32_t solution=cacheMemoryOperatingData32[(cacheMemorySize/4)-1]%comparisonSize;
	uint32_t proofOfCalculation=cacheMemoryOperatingData32[(cacheMemorySize/4)-2];
	// printf("verify solution - %u / %u / %u / %u\n",a,solution,proofOfCalculation,b);
	
	//free memory
	delete [] cacheMemoryOperatingData;
	delete [] cacheMemoryOperatingData2;

	CRYPTO_cleanup_all_ex_data();
    EVP_cleanup();
				
	if(solution==1968 && proofOfCalculation==b){
		return true;
	}
	
	return false;

}

uint32_t CalculateBestBirthdayHash(unsigned char *head, unsigned char *data, char *scratchpad, int totalThreads, volatile unsigned long *restart) {
	uint32_t *nBirthdayA = (uint32_t *)(data + 80);
	uint32_t *nBirthdayB = (uint32_t *)(data + 84);
	uint256 mid_hash;
	memcpy((unsigned char *)&mid_hash, head, 32);
	uint32_t progress = 0;
	std::vector< std::pair<uint32_t, uint32_t> > results = momentum_search(mid_hash, scratchpad, totalThreads, restart); //, progress);
	uint32_t candidateBirthdayA = 0;
	uint32_t candidateBirthdayB = 0;
	uint256 smallestHashSoFar("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
	for (unsigned i=0; i < results.size() && !*restart; i++) {
		*nBirthdayA = results[i].first;
		*nBirthdayB = results[i].second;
		uint256 _hash, hash;
		SHA256(data, 88, (unsigned char *)&_hash);
		SHA256((unsigned char *)&_hash, 32, (unsigned char *)&hash);

		if (hash < smallestHashSoFar) {
			smallestHashSoFar = hash;
			candidateBirthdayA = results[i].first;
			candidateBirthdayB = results[i].second;
		}
		*nBirthdayA = candidateBirthdayA;
		*nBirthdayB = candidateBirthdayB;
	}

	if (!momentum_verify(mid_hash, *nBirthdayA, *nBirthdayB)) {
		for (int i = 0; i < 32; i++)
			head[i] = 0xFF;
	} else {
		uint256 _hash, hash;
		SHA256(data, 88, (unsigned char *)&_hash);
		SHA256((unsigned char *)&_hash, 32, (unsigned char *)&hash);
		memcpy(head, (unsigned char *)&hash, 32);
	}

	return progress;
}
