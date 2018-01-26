#ifndef _MOL_DEF_GUARD_DEFINE_CRYPTONEAT_BASE64_DEF_GUARD_
#define _MOL_DEF_GUARD_DEFINE_CRYPTONEAT_BASE64_DEF_GUARD_


#include "cryptoneat/common.h"

namespace cryptoneat {

class Base64ex : public std::exception {};

class Base64
{
public:

    static std::string decode(const std::string& s);
    static std::string decode(const char* s);
    static std::string encode(const std::string& s, bool singleline=true);
    static std::string encode(const char* s, size_t len, bool singleline=true);
};

class Base64Url
{
public:

    static std::string decode(const std::string& s);
    static std::string decode(const char* s);
    static std::string encode(const std::string& s);
    static std::string encode(const char* s, size_t len);
};

} // close namespaces


#endif

