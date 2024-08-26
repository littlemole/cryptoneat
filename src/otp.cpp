/**
 * @file Base32.cpp
 *
 * This module contains the implementation of the
 * Base64::Base32 functions.
 *
 * © 2019 by Richard Walters
 */

#include "cryptoneat/totp.h"
#include "cryptoneat/cryptoneat.h"
#include "cryptoneat/base32.h"
#include <map>
#include <stdint.h>
#include <sstream>
#include <vector>
#include <arpa/inet.h>
#include <cmath>

namespace cryptoneat {

std::string TOTP::make_secret() 
{
	return cryptoneat::nonce(20);
}

std::string TOTP::make_uri(const std::string& user, const std::string& issuer)
{
	std::string uri = "otpauth://totp/";
	uri += user + "?secret=";
	uri += cryptoneat::Base32::encode(secret_,false);
	uri += "&algorithm=" + algo_;
	uri += "&digits=" + std::to_string(digits_);
	uri += "6&period=" + std::to_string(period_);
	uri += "&issuer=" + issuer;
	return uri;
}

bool TOTP::validate(const std::string& otp)
{
	char buf[1024];

	unsigned long int when = time(0);

	// calculate counter
	long t = when/period_;

	// convert to big endian
	long nt = htonl(t);

	// as a binary be string
	int ls = (nt >> 32) & 0xFFFFFFFF;
	int rs = (nt >>  0) & 0xFFFFFFFF;

	std::string tmp = std::string( (char*)&ls,4) + std::string( (char*)&rs,4);

	// hmac-sha1 the binary string of the counter
	cryptoneat::Hmac hmac( algo_, secret_ );
	std::string hash = hmac.hash(tmp);
	std::string hex = cryptoneat::toHex(hash);

	// get the offset as hex value
	std::string c = std::string("0") + hex.substr(hex.size()-1,1);

	// convert hex to binary and pull out offset value
	std::string bin = cryptoneat::fromHex(c);
	int offset = *( (char*) bin.c_str() );

	// get the encoded hex part and convert to binary
	std::string enc = hex.substr(offset*2,8);
	std::string dec = cryptoneat::fromHex(enc);

	// interprete the decoded value as long
	long l = *(long*)dec.c_str();

	// convert big endian to little endian
	l = ntohl(l);

	// skip high bits
	l = l & 0x7fffffff;

	// moduly 10 power to 6 (num of digits)
	long ll = l % ( int(pow (10,digits_)) );

	// convert to string keeping leading zeros
	std::string fs = std::string("%0") + std::to_string(digits_) + std::string("ld");
	sprintf(buf, fs.c_str(), ll );

	std::string code(buf);
	return code == otp;
}

} // end namespace


