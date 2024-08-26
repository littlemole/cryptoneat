/**
 * @file Base32.cpp
 *
 * This module contains the implementation of the
 * Base64::Base32 functions.
 *
 * © 2019 by Richard Walters
 */

#include "cryptoneat/base32.h"
#include <map>
#include <stdint.h>
#include <sstream>
#include <vector>

namespace cryptoneat {

const char EncodingTable[33] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const std::map< char, uint32_t > DecodingTable
{
	{'A', 0},  {'B', 1},  {'C', 2},  {'D', 3},  {'E', 4},  {'F', 5},  {'G', 6},  {'H', 7},
	{'I', 8},  {'J', 9},  {'K', 10}, {'L', 11}, {'M', 12}, {'N', 13}, {'O', 14}, {'P', 15},
	{'Q', 16}, {'R', 17}, {'S', 18}, {'T', 19}, {'U', 20}, {'V', 21}, {'W', 22}, {'X', 23},
	{'Y', 24}, {'Z', 25}, {'2', 26}, {'3', 27}, {'4', 28}, {'5', 29}, {'6', 30}, {'7', 31},
};


std::string Base32::encode( const std::string& data, bool omitPadding) 
{
	std::ostringstream output;
	size_t bits = 0;
	uint32_t buffer = 0;
	for (auto datum: data) {
		buffer <<= 8;
		buffer += (uint32_t)datum;
		bits += 8;
		while (bits >= 5) {
			output << EncodingTable[(buffer >> (bits - 5)) & 0x3f];
			buffer &= ~(0x1f << (bits - 5));
			bits -= 5;
		}
	}
	if ((data.size() % 5) == 1) {
		buffer <<= 2;
		output << EncodingTable[buffer & 0x1f];
		if (!omitPadding) {
			output << "======";
		}
	} else if ((data.size() % 5) == 2) {
		buffer <<= 4;
		output << EncodingTable[buffer & 0x1f];
		if (!omitPadding) {
			output << "====";
		}
	} else if ((data.size() % 5) == 3) {
		buffer <<= 1;
		output << EncodingTable[buffer & 0x1f];
		if (!omitPadding) {
			output << "===";
		}
	} else if ((data.size() % 5) == 4) {
		buffer <<= 3;
		output << EncodingTable[buffer & 0x1f];
		if (!omitPadding) {
			output << '=';
		}
	}
	return output.str();
}


std::string Base32::decode(const std::string& data) 
{
	std::ostringstream output;
	uint32_t buffer = 0;
	size_t bits = 0;
	for (auto datum: data) {
		const auto entry = DecodingTable.find(datum);
		uint32_t group = 0;
		if (entry != DecodingTable.end()) {
			group = entry->second;
		}
		buffer <<= 5;
		bits += 5;
		buffer += group;
		if (bits >= 8) {
			if (datum != '=') {
				output << (char)(buffer >> (bits - 8));
			}
			buffer &= ~(0xff << (bits - 8));
			bits -= 8;
		}
	}
	return output.str();
}
} // end namespace


