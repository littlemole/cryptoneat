#ifndef _MOL_DEF_GUARD_DEFINE_CRYPTONEAT_BASE32_DEF_GUARD_
#define _MOL_DEF_GUARD_DEFINE_CRYPTONEAT_BASE32_DEF_GUARD_

//! \file base64.h

#include "cryptoneat/common.h"

namespace cryptoneat {

class Base32ex : public std::exception {};

/**
 * \brief Base64 encoding
 */
class Base32
{
public:

    //! decode base64-encoded string
    static std::string decode(const std::string& s);
    //! encode given string in base64
    static std::string encode(const std::string& s, bool omitPadding=true);
};


} // close namespaces


#endif

