#ifndef _MOL_DEF_GUARD_DEFINE_CRYPTONEAT_TOTP_QR_DEF_GUARD_
#define _MOL_DEF_GUARD_DEFINE_CRYPTONEAT_TOTP_QR_DEF_GUARD_

//! \file base64.h

#include "cryptoneat/totp.h"

namespace cryptoneat {

#if __has_include("QrCode.hpp")
std::string make_totp_qr_image_data_url(const std::string& uri);
#endif 

} // close namespaces


#endif

