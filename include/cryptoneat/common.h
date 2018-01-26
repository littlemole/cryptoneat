#ifndef INCLUDE_CRYPTONEAT_CRYPT_COMMON_H_
#define INCLUDE_CRYPTONEAT_CRYPT_COMMON_H_

#include <string>
#include <vector>

//////////////////////////////////////////////////////////////

namespace cryptoneat {


template<class T>
class Buffer
{
public:

    Buffer(size_t s)
        : buf_(s,0)
    {}

    T* operator&()
    {
        return &(buf_[0]);
    }

    T& operator[](size_t i)
    {
        return buf_[i];
    }

    std::string toString()
    {
        return std::string( (char*)&(buf_[0]), buf_.size()*sizeof(T) );
    }


    std::string toString(size_t n)
    {
        return std::string( (char*)&(buf_[0]), n*sizeof(T) );
    }

    size_t size()
    {
        return buf_.size();
    }

	std::vector<T>& data()
	{
		return buf_;
	}

private:
    std::vector<T> buf_;

};

typedef Buffer<unsigned char> uchar_buf;
typedef Buffer<char> char_buf;


class CryptoEx : public std::exception {};
class CipherNotFoundEx : public CryptoEx {};
class InvalidHexCharEx : public CryptoEx {};
class InvalidMsgDigestEx : public CryptoEx {};
class MsgDigestCtxCtreateEx : public CryptoEx {};
class MsgDigestEx : public CryptoEx {};
class InvalidSaltEx : public CryptoEx {};
class SymCryptEx : public CryptoEx {};
class HmacEx : public CryptoEx {};
class PrivateKeyEx : public CryptoEx {};
class PublicKeyEx : public CryptoEx {};
class RsaKeyEx : public CryptoEx {};
class SignatureEx : public CryptoEx {};
class EnvelopeEx : public CryptoEx {};
class DhEx : public CryptoEx {};

}


#endif 
