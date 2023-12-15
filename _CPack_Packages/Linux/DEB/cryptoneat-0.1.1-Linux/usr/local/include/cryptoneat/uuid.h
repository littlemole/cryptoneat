#ifndef _MOL_DEF_GUARD_DEFINE_CRYPT_UUID_DEF_GUARD_
#define _MOL_DEF_GUARD_DEFINE_CRYPT_UUID_DEF_GUARD_

//! \file uuid.h

#include <string>

namespace cryptoneat {

//! platform independent uuid
class uuid
{
public:

  //! generate a new UUID
  static std::string generate();

};


} // end namespaces

#endif