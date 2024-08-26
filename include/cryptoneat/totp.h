#ifndef _MOL_DEF_GUARD_DEFINE_CRYPTONEAT_TOTP_DEF_GUARD_
#define _MOL_DEF_GUARD_DEFINE_CRYPTONEAT_TOTP_DEF_GUARD_

//! \file base64.h

#include "cryptoneat/common.h"

namespace cryptoneat {

class TOTP
{
public:

	TOTP(const std::string& secret)
		: secret_(secret), algo_("sha1")
	{}

	static std::string make_secret();

	std::string make_uri(const std::string& user, const std::string& issuer);

	bool validate(const std::string& otp);

private:
	std::string secret_;
	std::string algo_;
	int digits_ = 6;
	int period_ = 30;
};


} // close namespaces


#endif

