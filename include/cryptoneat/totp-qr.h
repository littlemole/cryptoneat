#ifndef _MOL_DEF_GUARD_DEFINE_CRYPTONEAT_TOTP_QR_DEF_GUARD_
#define _MOL_DEF_GUARD_DEFINE_CRYPTONEAT_TOTP_QR_DEF_GUARD_

//! \file base64.h

#include "cryptoneat/totp.h"
#include "QrCode.hpp" 

namespace cryptoneat {

// depends on https://github.com/nayuki/QR-Code-generator/ (cpp lib)
// sudo apt install libqrcodegencpp-dev	

namespace impl {
using namespace qrcodegen;


inline std::string toSvgString(const QrCode &qr, int border) 
{
	if (border < 0)
		throw std::domain_error("Border must be non-negative");
	if (border > INT_MAX / 2 || border * 2 > INT_MAX - qr.getSize())
		throw std::overflow_error("Border too large");
	
	std::ostringstream sb;
	sb << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
	sb << "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n";
	sb << "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" viewBox=\"0 0 ";
	sb << (qr.getSize() + border * 2) << " " << (qr.getSize() + border * 2) << "\" stroke=\"none\">\n";
	sb << "\t<rect width=\"100%\" height=\"100%\" fill=\"#FFFFFF\"/>\n";
	sb << "\t<path d=\"";
	for (int y = 0; y < qr.getSize(); y++) {
		for (int x = 0; x < qr.getSize(); x++) {
			if (qr.getModule(x, y)) {
				if (x != 0 || y != 0)
					sb << " ";
				sb << "M" << (x + border) << "," << (y + border) << "h1v1h-1z";
			}
		}
	}
	sb << "\" fill=\"#000000\"/>\n";
	sb << "</svg>\n";
	return sb.str();
}

} // close namespace

inline std::string make_totp_qr_image_data_url(const std::string& uri)
{
	QrCode qr0 = QrCode::encodeText(uri.c_str(), QrCode::Ecc::MEDIUM);
	std::string svg = impl::toSvgString(qr0, 4);  

	std::string result = "data:image/svg+xml;base64,";
	result += cryptoneat::Base64::encode(svg);
	return result;
}

} // close namespace


#endif

