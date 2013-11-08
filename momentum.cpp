#include <math.h>
#include <stdint.h>
#include <uint256.h>
#include <vector>
#include <openssl/sha.h>

extern "C" {
	void CalculateBestBirthdayHash(unsigned char *head, unsigned char *data, volatile unsigned long *restart);
}

#define SEARCH_SPACE_BITS 50
#define BIRTHDAYS_PER_HASH 8

class semiOrderedMap {
	private:
		uint64_t *indexOfBirthdayHashes;
		uint32_t *indexOfBirthdays;
		int bucketSizeExponent;
		int bucketSize;
	public:
		void allocate(int bSE) {
			bucketSizeExponent = bSE;
			bucketSize=powf(2, bSE);
			indexOfBirthdayHashes = new uint64_t[67108864];
			indexOfBirthdays = new uint32_t[67108864];
		}
		void destroy() {
			delete [] indexOfBirthdayHashes;
			delete [] indexOfBirthdays;
		}
		uint32_t checkAdd(uint64_t birthdayHash, uint32_t nonce){
			uint64_t bucketStart = (birthdayHash >> (24 + bucketSizeExponent)) * bucketSize;
			for(int i = 0; i < bucketSize;i++){
				uint64_t bucketValue=indexOfBirthdayHashes[bucketStart+i];
				if (bucketValue == birthdayHash) {
					return indexOfBirthdays[bucketStart+i];
				} else if (bucketValue == 0) {
					indexOfBirthdayHashes[bucketStart + i] = birthdayHash;
					indexOfBirthdays[bucketStart + i] = nonce;
					return 0;
				}
			}
			return 0;
		}
};

std::vector< std::pair<uint32_t, uint32_t> >momentum_search(uint256 midHash, volatile unsigned long *restart)
{
	semiOrderedMap somap;
	somap.allocate(4);
	std::vector< std::pair<uint32_t, uint32_t> > results;
	char hash_tmp[sizeof(midHash) + 4];
	memcpy((char*)&hash_tmp[4], (char*)&midHash, sizeof(midHash));
	uint32_t *index = (uint32_t *)hash_tmp;
	for (uint32_t i = 0; i < 67108864 && !*restart;) {
		*index = i;
		uint64_t result_hash[8];
		SHA512((unsigned char *)hash_tmp, sizeof(hash_tmp), (unsigned char *)result_hash);
		for (uint32_t x = 0; x < 8; ++x) {
			uint64_t birthday = result_hash[x] >> (64 - SEARCH_SPACE_BITS);
			uint32_t nonce = i + x;
			uint64_t foundMatch = somap.checkAdd(birthday, nonce);
			if (foundMatch != 0){
				results.push_back(std::make_pair(foundMatch, nonce));
			}
		}
		i += BIRTHDAYS_PER_HASH;
	}
	somap.destroy();
	return results;
}

uint64_t getBirthdayHash(const uint256& midHash, uint32_t a)
{
	uint32_t index = a - (a % 8);
	char hash_tmp[sizeof(midHash) + 4];
	memcpy(&hash_tmp[4], (char*)&midHash, sizeof(midHash));
	memcpy(&hash_tmp[0], (char*)&index, sizeof(index));
	uint64_t result_hash[8];
	SHA512((unsigned char *)hash_tmp, sizeof(hash_tmp), (unsigned char *)&result_hash);
	uint64_t r = result_hash[a % BIRTHDAYS_PER_HASH] >> (64 - SEARCH_SPACE_BITS);
	return r;
}

void CalculateBestBirthdayHash(unsigned char *head, unsigned char *data, volatile unsigned long *restart) {
	uint32_t *nBirthdayA = (uint32_t *)(data + 80);
	uint32_t *nBirthdayB = (uint32_t *)(data + 84);
	uint256 mid_hash;
	memcpy((unsigned char *)&mid_hash, head, 32);
	std::vector< std::pair<uint32_t, uint32_t> > results = momentum_search(mid_hash, restart);
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
	uint256 _hash, hash;
	SHA256(data, 88, (unsigned char *)&_hash);
	SHA256((unsigned char *)&_hash, 32, (unsigned char *)&hash);
	memcpy(head, (unsigned char *)&hash, 32);
}
