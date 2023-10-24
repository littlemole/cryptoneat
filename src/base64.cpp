#include "cryptoneat/base64.h"
#include "cryptoneat/common.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <sstream>

namespace cryptoneat {
 
//Calculates the length of a decoded base64 string
size_t calcDecodeLength(const char* b64input, size_t len)
{ 
	size_t padding = 0;
	 
	if (b64input[len-1] == '=' && b64input[len-2] == '=') 
	{
		padding = 2;
	}
	else if (b64input[len-1] == '=') 
	{
		padding = 1;		
	}
	 
	return (len*3)/4 - padding;
}

std::string Base64::decode(const std::string& input)
{
	size_t decodeLen = calcDecodeLength(input.c_str(),input.size());
	char_buf buffer(decodeLen+1);
	buffer[decodeLen] = '\0';

	BIO* bio = BIO_new_mem_buf(input.c_str(), (long)input.size());
	BIO* b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	int length = BIO_read(bio, &buffer, (long) input.size());

	BIO_free_all(bio);

    return buffer.toString(length);

}

std::string Base64::decode(const char* s)
{
    return decode( std::string(s) );
}

std::string Base64::encode(const std::string& s, bool /*singleline*/ )
{
	BIO *bio, *b64;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
    BIO_write(bio, s.c_str(), (long)s.size());

    int unused = BIO_flush(bio);
	unused = BIO_set_close(bio, BIO_NOCLOSE);
    (void)unused;

    unsigned char* output;
    int len = BIO_get_mem_data(bio, &output);

    std::string result((char*)output, len);
	BIO_free_all(bio);

	return result;
}

std::string Base64::encode(const char* s, size_t len, bool singleline)
{
    return encode( std::string(s,len), singleline);
}


std::string Base64Url::decode(const std::string& input)
{
    std::ostringstream oss;
    
    for ( size_t i = 0; i < input.size(); i++)
    {
        switch( input[i] )
        {
            case '-' : 
            {
                oss << '+';
                break;
            }
            case '_' : 
            {
                oss << '/';
                break;
            }          
            default : 
            {
                oss << input[i];
            }
        }
    }

    return Base64::decode(oss.str());
}

std::string Base64Url::decode(const char* s)
{
    return decode( std::string(s) );
}

std::string Base64Url::encode(const std::string& s)
{
    std::string input = Base64::encode(s,true);
    
    std::ostringstream oss;
    for ( size_t i = 0; i < input.size(); i++)
    {
        switch( input[i] )
        { 
            case '+' : 
            {
                oss << '-';
                break;
            }
            case '/' : 
            {
                oss << '_';
                break;
            }         
//            case '=' :
//            {
//                oss << "%3D";
//                break;
//            }  
            default : 
            {
                oss << input[i];
            }
        }
    }
    
    return oss.str();
}

std::string Base64Url::encode(const char* s, size_t len)
{
    return encode( std::string(s,len));
}


}
