#ifndef _MOL_DEF_GUARD_DEFINE_CRYPTONEAT_BASE64_DEF_GUARD_
#define _MOL_DEF_GUARD_DEFINE_CRYPTONEAT_BASE64_DEF_GUARD_

//! \file base64.h

#include "cryptoneat/common.h"

namespace cryptoneat {

class Base64ex : public std::exception {};

/**
 * \brief Base64 encoding
 */
class Base64
{
public:

    //! decode base64-encoded string
    static std::string decode(const std::string& s);
    //! decode base64-encoded c-style string
    static std::string decode(const char* s);
    //! encode given string in base64
    static std::string encode(const std::string& s, bool singleline=true);
    //! encode given c-style string in base64
    static std::string encode(const char* s, size_t len, bool singleline=true);
};

/**
 * \brief Base64-URL-encoding
 */
class Base64Url
{
public:

    //! base64-url-decode given string
    static std::string decode(const std::string& s);
    //! base64-url-decode given c-style string
    static std::string decode(const char* s);
    //! base64-url-encode given string
    static std::string encode(const std::string& s);
    //! base64-url-encode given c-style string
    static std::string encode(const char* s, size_t len);
};

} // close namespaces


#endif

