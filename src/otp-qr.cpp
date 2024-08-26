#if __has_include("QrCode.hpp")

#include "cryptoneat/totp-qr.h"
#include "cryptoneat/cryptoneat.h"
#include "cryptoneat/base32.h"
#include <map>
#include <stdint.h>
#include <sstream>
#include <vector>
#include <arpa/inet.h>
#include <cmath>

#include "QrCode.hpp" 
using namespace qrcodegen;


namespace cryptoneat {


static std::string toSvgString(const QrCode &qr, int border) 
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


std::string make_totp_qr_image_data_url(const std::string& uri)
{
	QrCode qr0 = QrCode::encodeText(uri.c_str(), QrCode::Ecc::MEDIUM);
	std::string svg = toSvgString(qr0, 4);  
	return svg;
}


} // end namespace

#endif 

