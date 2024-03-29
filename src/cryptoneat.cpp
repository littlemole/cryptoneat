﻿#ifndef _WIN32
#include <unistd.h>
#include <arpa/inet.h>
#else
#define _CRT_SECURE_NO_WARNINGS 1
#define _CRT_RAND_S  
#include <stdlib.h>
#include <stdio.h>  
#include <limits.h>  
#include <winsock2.h>
#endif

#include "cryptoneat/cryptoneat.h"
#include "cryptoneat/base64.h"
#include "cryptoneat/common.h"

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/conf.h>

#include <mutex>
#include <memory>
#include <fcntl.h>
#include <iostream>
#include <sstream>
#include <thread>
#include <map>

#if OPENSSL_VERSION_NUMBER < 0x10100000L

::EVP_CIPHER_CTX* EVP_CIPHER_CTX_new()
{
	::EVP_CIPHER_CTX* ctx = new ::EVP_CIPHER_CTX;
	EVP_CIPHER_CTX_init(ctx);
	return ctx;
}

void EVP_CIPHER_CTX_free(::EVP_CIPHER_CTX* ctx)
{
	delete ctx;
}

::HMAC_CTX* HMAC_CTX_new()
{
	::HMAC_CTX* ctx = new ::HMAC_CTX;
	HMAC_CTX_init(ctx);
	return ctx;
}

void HMAC_CTX_free(::HMAC_CTX* ctx)
{
	HMAC_CTX_cleanup(ctx);
	delete ctx;
}

::EVP_MD_CTX* EVP_MD_CTX_new()
{
	::EVP_MD_CTX* ctx = new ::EVP_MD_CTX;
	return ctx;
}

void EVP_MD_CTX_free(::EVP_MD_CTX* ctx)
{
	EVP_MD_CTX_cleanup(ctx);
	delete ctx;
}


void DH_get0_key(::DH* dh, const BIGNUM** k, int unused)
{
	*k = dh->pub_key;	
}
#endif

#if OPENSSL_VERSION_MAJOR >= 3
//#include <openssl/provider.h>
#endif


namespace cryptoneat {


class Mutex
{
public:
	Mutex();
	virtual ~Mutex();
	virtual void aquire();
	virtual int  aquired();
	virtual void release();
private:
	std::mutex               mutex_;
};

}

struct CRYPTO_dynlock_value
{
	cryptoneat::Mutex mutex;
};

namespace cryptoneat {

	static char nibble_decode(char nibble)
	{
		const char byte_map[] = {
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f'
		};
		return byte_map[(int)nibble];
	}

	std::string toHex(const std::string& input)
	{
		unsigned char* bytes = (unsigned char*)input.c_str();

		std::ostringstream oss;
		for (size_t i = 0; i < input.size(); i++)
		{
			char c1 = nibble_decode(bytes[i] >> 4);
			char c2 = nibble_decode(bytes[i] & 0x0f);
			oss.write(&c1, 1);
			oss.write(&c2, 1);
		}
		return oss.str();
	}


	static int HexCharToInt(char ch)
	{
		if (ch >= '0' && ch <= '9')
			return (ch - '0');
		else if (ch >= 'a' && ch <= 'f')
			return (ch - 'a' + 10);
		else if (ch >= 'A' && ch <= 'F')
			return (ch - 'A' + 10);
		else
			throw InvalidHexCharEx();
	}


	static int HexByteToInt(const char * hex)
	{
		return HexCharToInt(hex[0]) * 16
			+ HexCharToInt(hex[1]);
	}


	std::string fromHex(const std::string& hex)
	{
		std::ostringstream oss;

		const char * p = hex.c_str();
		while (*p)
		{
			char i = HexByteToInt((char*)p);
			oss.write(&i, 1);
			p += 2;
		}

		return oss.str();
	}

	const EVP_MD* digest(const std::string& md)
	{
		return reinterpret_cast<const EVP_MD*>(EVP_get_digestbyname(md.c_str()));
	}

	const EVP_MD* digest(const std::string& md, const std::string& provider)
	{
#if OPENSSL_VERSION_MAJOR >= 3

		return reinterpret_cast<const EVP_MD*>(EVP_MD_fetch(NULL,md.c_str(),provider.c_str()));
#else
		return digest(md);
#endif

	}

	EVP_PKEY* crypto(::EVP_PKEY* ctx)
	{
		return reinterpret_cast<EVP_PKEY*>(ctx);
	}

	::EVP_PKEY* openssl(EVP_PKEY* ctx)
	{
		return reinterpret_cast<::EVP_PKEY*>(ctx);
	}

	::EVP_PKEY** openssl(EVP_PKEY** ctx)
	{
		return reinterpret_cast<::EVP_PKEY**>(ctx);
	}


	EVP_MD_CTX* crypto(::EVP_MD_CTX* ctx)
	{
		return reinterpret_cast<EVP_MD_CTX*>(ctx);
	}

	::EVP_MD_CTX* openssl(EVP_MD_CTX* ctx)
	{
		return reinterpret_cast<::EVP_MD_CTX*>(ctx);
	}

/*

	HMAC_CTX* crypto(::HMAC_CTX* ctx)
	{
		return reinterpret_cast<HMAC_CTX*>(ctx);
	}

	::HMAC_CTX* openssl(HMAC_CTX* ctx)
	{
		return reinterpret_cast<::HMAC_CTX*>(ctx);
	}
*/

	EVP_MAC_CTX* crypto(::EVP_MAC_CTX* ctx)
	{
		return reinterpret_cast<EVP_MAC_CTX*>(ctx);
	}

	::EVP_MAC_CTX* openssl(EVP_MAC_CTX* ctx)
	{
		return reinterpret_cast<::EVP_MAC_CTX*>(ctx);
	}





	const EVP_MD* crypto(const ::EVP_MD* md)
	{
		return reinterpret_cast<const EVP_MD*>(md);
	}

	const ::EVP_MD* openssl(const EVP_MD* md)
	{
		return reinterpret_cast<const ::EVP_MD*>(md);
	}


	const EVP_CIPHER* crypto(const ::EVP_CIPHER* c)
	{
		return reinterpret_cast<const EVP_CIPHER*>(c);
	}

	const ::EVP_CIPHER* openssl(const EVP_CIPHER* c)
	{
		return reinterpret_cast<const ::EVP_CIPHER*>(c);
	}

	typedef const ::EVP_CIPHER*(*cipher_factory)();

	std::map<std::string, cipher_factory> init_ciphermap();

	const EVP_CIPHER* cipher(const std::string& c)
	{
		static auto ciphermap = init_ciphermap();

		if (ciphermap.count(c) == 0)
		{
			throw CipherNotFoundEx();
		}

		cipher_factory cf = ciphermap[c];

		const ::EVP_CIPHER* ciph = cf();

		//printf("CIPHER: %s %li\r\n", c.c_str(), (const long)ciph);

		if(ciph == 0)
		{
				throw CipherNotFoundEx();
		}

		return crypto(ciph);
	}

	
	std::map<std::string, cipher_factory> init_ciphermap()
	{
		std::map<std::string, cipher_factory> theMap;
		theMap["aes_128_cbc"] = &EVP_aes_128_cbc;
		theMap["enc_null"] = &EVP_enc_null;
		theMap["des_ecb"] = &EVP_des_ecb;
		theMap["des_ede"] = &EVP_des_ede;
		theMap["des_ede3"] = &EVP_des_ede3;
		theMap["des_ede_ecb"] = &EVP_des_ede_ecb;
		theMap["des_ede3_ecb"] = &EVP_des_ede3_ecb;
		theMap["des_cfb64"] = &EVP_des_cfb64;
		theMap["des_cfb1"] = &EVP_des_cfb1;
		theMap["des_cfb8"] = &EVP_des_cfb8;
		theMap["des_ede_cfb64"] = &EVP_des_ede_cfb64;
		theMap["des_ede3_cfb64"] = &EVP_des_ede3_cfb64;
		theMap["des_ede3_cfb1"] = &EVP_des_ede3_cfb1;
		theMap["des_ede3_cfb8"] = &EVP_des_ede3_cfb8;
		theMap["des_ofb"] = &EVP_des_ofb;
		theMap["des_ede_ofb"] = &EVP_des_ede_ofb;
		theMap["des_ede3_ofb"] = &EVP_des_ede3_ofb;
		theMap["des_cbc"] = &EVP_des_cbc;
		theMap["des_ede_cbc"] = &EVP_des_ede_cbc;
		theMap["des_ede3_cbc"] = &EVP_des_ede3_cbc;
		theMap["desx_cbc"] = &EVP_desx_cbc;
		theMap["des_ede3_wrap"] = &EVP_des_ede3_wrap;
#ifndef OPENSSL_NO_RC4
		theMap["rc4"] = &EVP_rc4;
		theMap["rc4_40"] = &EVP_rc4_40;
#ifndef OPENSSL_NO_MD5
		theMap["rc4_hmac_md5"] = &EVP_rc4_hmac_md5;
#endif
#endif 
#ifndef OPENSSL_NO_IDEA
		theMap["idea_ecb"] = &EVP_idea_ecb;
		theMap["idea_cfb64"] = &EVP_idea_cfb64;
		theMap["idea_ofb"] = &EVP_idea_ofb;
		theMap["idea_cbc"] = &EVP_idea_cbc;
#endif
#ifndef OPENSSL_NO_RC2
		theMap["rc2_ecb"] = &EVP_rc2_ecb;
		theMap["rc2_cbc"] = &EVP_rc2_cbc;
		theMap["rc2_40_cbc"] = &EVP_rc2_40_cbc;
		theMap["rc2_64_cbc"] = &EVP_rc2_64_cbc;
		theMap["rc2_cfb64"] = &EVP_rc2_cfb64;
		theMap["rc2_ofb"] = &EVP_rc2_ofb;
#endif
#ifndef OPENSSL_NO_BF
		theMap["bf_ecb"] = &EVP_bf_ecb;
		theMap["bf_cbc"] = &EVP_bf_cbc;
		theMap["bf_cfb64"] = &EVP_bf_cfb64;
		theMap["bf_ofb"] = &EVP_bf_ofb;
#endif
#ifndef OPENSSL_NO_AES
		theMap["aes_128_ecb"] = &EVP_aes_128_ecb;
		theMap["aes_128_cbc"] = &EVP_aes_128_cbc;
		theMap["aes_128_cfb1"] = &EVP_aes_128_cfb1;
		theMap["aes_128_cfb8"] = &EVP_aes_128_cfb8;
		theMap["aes_128_cfb128"] = &EVP_aes_128_cfb128;
		theMap["aes_128_ofb"] = &EVP_aes_128_ofb;
		theMap["aes_128_ctr"] = &EVP_aes_128_ctr;
		theMap["aes_128_ccm"] = &EVP_aes_128_ccm;
		theMap["aes_128_gcm"] = &EVP_aes_128_gcm;
		theMap["aes_128_xts"] = &EVP_aes_128_xts;
		theMap["aes_128_wrap"] = &EVP_aes_128_wrap;
		theMap["aes_192_ecb"] = &EVP_aes_192_ecb;
		theMap["aes_192_cbc"] = &EVP_aes_192_cbc;
		theMap["aes_192_cfb1"] = &EVP_aes_192_cfb1;
		theMap["aes_192_cfb8"] = &EVP_aes_192_cfb8;
		theMap["aes_192_cfb128"] = &EVP_aes_192_cfb128;
		theMap["aes_192_ofb"] = &EVP_aes_192_ofb;
		theMap["aes_192_ctr"] = &EVP_aes_192_ctr;
		theMap["aes_192_ccm"] = &EVP_aes_192_ccm;
		theMap["aes_192_gcm"] = &EVP_aes_192_gcm;
		theMap["aes_192_wrap"] = &EVP_aes_192_wrap;
		theMap["aes_256_ecb"] = &EVP_aes_256_ecb;
		theMap["aes_256_cbc"] = &EVP_aes_256_cbc;
		theMap["aes_256_cfb1"] = &EVP_aes_256_cfb1;
		theMap["aes_256_cfb8"] = &EVP_aes_256_cfb8;
		theMap["aes_256_cfb128"] = &EVP_aes_256_cfb128;
		theMap["aes_256_ofb"] = &EVP_aes_256_ofb;
		theMap["aes_256_ctr"] = &EVP_aes_256_ctr;
		theMap["aes_256_ccm"] = &EVP_aes_256_ccm;
		theMap["aes_256_gcm"] = &EVP_aes_256_gcm;
		theMap["aes_256_xts"] = &EVP_aes_256_xts;
		theMap["aes_256_wrap"] = &EVP_aes_256_wrap;
#if !defined(OPENSSL_NO_SHA) && !defined(OPENSSL_NO_SHA1)
		theMap["aes_128_cbc_hmac_sha1"] = &EVP_aes_128_cbc_hmac_sha1;
		theMap["aes_256_cbc_hmac_sha1"] = &EVP_aes_256_cbc_hmac_sha1;
#endif
#ifndef OPENSSL_NO_SHA256
		theMap["aes_128_cbc_hmac_sha256"] = &EVP_aes_128_cbc_hmac_sha256;
		theMap["aes_256_cbc_hmac_sha256"] = &EVP_aes_256_cbc_hmac_sha256;
#endif
#endif
		return theMap;
	}


	Digest::Digest(const EVP_MD * md)
	{
		md_ = md;
		if (!md_)
		{
			throw InvalidMsgDigestEx();
		}

		EVP_MD_CTX* mdctx = crypto(EVP_MD_CTX_create());
		if (!mdctx)
		{
			throw MsgDigestCtxCtreateEx();
		}

		mdctx_ = std::shared_ptr<EVP_MD_CTX>(mdctx, [](EVP_MD_CTX* ctx) {  EVP_MD_CTX_destroy(openssl(ctx));  });
	}

	std::string Digest::digest(const std::string& input)
	{
		unsigned char md_value[EVP_MAX_MD_SIZE];
		unsigned int md_len = 0;

		::EVP_MD_CTX* ctx = openssl(mdctx_.get());

		if (!EVP_DigestInit_ex(ctx, openssl(md_), NULL))
		{
			throw MsgDigestEx();
		}
		if (!EVP_DigestUpdate(ctx, input.c_str(), input.size()))
		{
			throw MsgDigestEx();
		}
		if (!EVP_DigestFinal_ex(ctx, md_value, &md_len))
		{
			throw MsgDigestEx();
		}

		return std::string((char*)md_value, md_len);
	}

	std::string md5(const std::string& s)
	{
		Digest evp(crypto(EVP_md5()));
		return evp.digest(s);
	}


	std::string sha1(const std::string& s)
	{
		Digest evp(crypto(EVP_sha1()));
		return evp.digest(s);
	}


	std::string sha256(const std::string& s)
	{
		Digest evp(crypto(EVP_sha256()));
		return evp.digest(s);
	}

#ifndef _WIN32
	std::string nonce(unsigned int n)
	{
		int randomData = open("/dev/urandom", O_RDONLY);
		char myRandomData[256];
		size_t randomDataLen = 0;
		while (randomDataLen < n)
		{
			ssize_t result = read(randomData, myRandomData + randomDataLen, n - randomDataLen);
			if (result < 0)
			{
				// error, unable to read /dev/random
			}
			randomDataLen += result;
		}
		close(randomData);
		return std::string(myRandomData, n);
	}
#else
	std::string nonce(unsigned int n)
	{
		char myRandomData[256];
		size_t randomDataLen = 0;
		while (randomDataLen < n)
		{
			unsigned int v;
			rand_s(&v);
			myRandomData[randomDataLen] = v;
			randomDataLen++;
		}

		return std::string(myRandomData, n);
	}
#endif


	SymCrypt::SymCrypt( const std::string& pwd)
		: SymCrypt( cipher("aes_256_cbc"),pwd,digest("sha256") )
	{}

	SymCrypt::SymCrypt(const EVP_CIPHER* cipher, const std::string& pwd)
		: SymCrypt( cipher,pwd,digest("sha256") )
	{}

	SymCrypt::SymCrypt(const EVP_CIPHER* cipher, const std::string& pwd, const EVP_MD* md)
		: cipher_(cipher), md_(md), pwd_(pwd)
	{}

	class EvpCipherCtx //: public EVP_CIPHER_CTX
	{
	public:
	
		EVP_CIPHER_CTX* ctx;

		EvpCipherCtx()
		{
			ctx=EVP_CIPHER_CTX_new();
			EVP_CIPHER_CTX_init(ctx);
		}

		~EvpCipherCtx()
		{
			EVP_CIPHER_CTX_cleanup(ctx);
			EVP_CIPHER_CTX_free(ctx);
		}
	};

	class KeyIvFromPassword
	{
	public:

		KeyIvFromPassword(const EVP_CIPHER* cipher,const std::string& salt, const std::string& pwd)
			: KeyIvFromPassword(cipher,salt,pwd, digest("sha256"))
		{}

		KeyIvFromPassword(const EVP_CIPHER* ciph,const std::string& salt, const std::string& pwd, const EVP_MD* mdig)
			: iv(EVP_CIPHER_iv_length(openssl(ciph))), 
			  key(EVP_BytesToKey( openssl(ciph), openssl(mdig), (unsigned char*)(salt.c_str()),0, (long)pwd.size(),10,0,&iv))
		{
			if( salt.size() != 8 )
			{
				throw InvalidSaltEx();
			}

			EVP_BytesToKey( 
				openssl(ciph),
				openssl(mdig),
				(unsigned char*)(salt.c_str()),
				(const unsigned char*)(pwd.c_str()),
				(long)pwd.size(),
				10,
				&key,
				&iv
			);			
		}

		uchar_buf iv;
		uchar_buf key;		
	};

	std::string SymCrypt::encrypt(const std::string& input)
	{
		EvpCipherCtx ctx;

		std::string salt = nonce(8);

		KeyIvFromPassword kiv(cipher_,salt,pwd_,md_);

		if (!EVP_EncryptInit(
			ctx.ctx,
			openssl(cipher_),
			&(kiv.key),
			&(kiv.iv)
		))
		{
			printf("%s", ERR_error_string(ERR_get_error(), NULL));
			throw SymCryptEx();
		}

		int n = (int)(EVP_CIPHER_block_size(openssl(cipher_)) + input.size());

		uchar_buf outbuf(n);

		if (EVP_EncryptUpdate(
			ctx.ctx,
			&outbuf, &n,
			(unsigned char*)input.c_str(), (long)input.size()
		) != 1)
		{
			throw SymCryptEx();
		}

		int tlen = 0;
		if (EVP_EncryptFinal(ctx.ctx, (&outbuf) + n, &tlen) != 1)
		{
			throw SymCryptEx();
		}
		n += tlen;

		std::ostringstream oss;
		oss << "Salted__";
		oss.write(salt.c_str(),salt.size());
		oss.write((char*)(&outbuf),n);
		return oss.str();
	}

	std::string SymCrypt::decrypt(const std::string& raw)
	{
		if ( raw.substr(0,8) != "Salted__" )
		{
			throw SymCryptEx();
		}

		if ( raw.size() < 17 )
		{
			throw SymCryptEx(); 
		}

		std::string salt = raw.substr(8,8);

		EvpCipherCtx ctx;
		const ::EVP_CIPHER* c = openssl(cipher_);

		KeyIvFromPassword kiv(cipher_,salt,pwd_,md_);

		if (!EVP_DecryptInit(
			ctx.ctx,
			c,
			&(kiv.key),
			&(kiv.iv)
		))
		{
			throw SymCryptEx();
		}

		int n = (int) (EVP_CIPHER_block_size(c) + raw.size());
		uchar_buf outbuf(n + 1);

		if (EVP_DecryptUpdate(
			ctx.ctx,
			&outbuf, &n,
			(const unsigned char*)raw.c_str()+16, (long)raw.size()-16
		) != 1)
		{
			throw SymCryptEx();
		}

		int tlen = 0;
		if (EVP_DecryptFinal(ctx.ctx, &outbuf + n, &tlen) != 1)
		{
			throw SymCryptEx();
		}
		n += tlen;

		return std::string((char*)&outbuf, n);
	}

	Hmac::Hmac(const std::string& dig, const std::string& key)
		: digest_(dig), key_(key)
	{
		::EVP_MAC *mac = 0;
		::EVP_MAC_CTX* ctx = 0;

		mac = EVP_MAC_fetch(0, "hmac",0 );
		if ( mac == NULL ) 
		{
			throw HmacEx();
		}

		if ( (ctx = EVP_MAC_CTX_new(mac)) == NULL) throw HmacEx();

		ctx_ = std::shared_ptr<EVP_MAC_CTX>(
			(EVP_MAC_CTX*)ctx, 
			[](EVP_MAC_CTX* ctx) { 

				::EVP_MAC_CTX* c = openssl(ctx);	
				::EVP_MAC_CTX_free(c);
			}
		);

		EVP_MAC_free(mac);

		OSSL_PARAM macparams[2] = { 
		    OSSL_PARAM_construct_utf8_string("digest", (char *)dig.c_str(), 0),
            OSSL_PARAM_END 
		};

		EVP_MAC_CTX_set_params(ctx, macparams);

		if (!EVP_MAC_init(ctx, (const unsigned char*)key.c_str(), key.size(),macparams) )
		{
			throw HmacEx();
		}
	}

	std::string Hmac::hash(const std::string& msg)
	{
		::EVP_MAC_CTX* ctx = openssl(ctx_.get());

		size_t len = EVP_MD_size(openssl(digest(digest_)));

		uchar_buf buffer(len);

		if (EVP_MAC_update(
			ctx,
			(const unsigned char *)msg.c_str(), msg.size()
		) != 1)
		{
			throw HmacEx();
		}

		if (EVP_MAC_final(ctx, &buffer, &len, len) != 1)
		{
			throw HmacEx();
		}

		return buffer.toString(len);
	}

	PrivateKey::PrivateKey()
	{
		pkey_ = crypto(EVP_PKEY_new());
	}

	PrivateKey::PrivateKey(const std::string& file)
	{
		FILE* f = fopen(file.c_str(), "r");
		if (!f)
		{
			throw PrivateKeyEx();
		}
		pkey_ = crypto(PEM_read_PrivateKey(f, NULL, 0, 0));
		fclose(f);
	}

	PrivateKey::~PrivateKey()
	{
		EVP_PKEY_free(openssl(pkey_));
	}

	std::string PrivateKey::toDER()
	{
		::EVP_PKEY* pkey = openssl(pkey_);

		int len = i2d_PrivateKey(pkey, NULL);
		uchar_buf buf(len);

		unsigned char* p = &buf;
		i2d_PrivateKey(pkey, &p);

		return buf.toString(len);
	}

	std::string PrivateKey::toPEM()
	{
		BIO* bio = BIO_new(BIO_s_mem());

		int len = PEM_write_bio_PrivateKey(bio, openssl(pkey_), 0, 0, 0, 0, 0);

		unsigned char* output;
		len = BIO_get_mem_data(bio, &output);

		std::string result((char*)output, len);

		BIO_free(bio);

		return result;
	}

	void PrivateKey::fromDER(int type, const std::string& k)
	{
		const unsigned char* s = (const unsigned char*)k.c_str();
		pkey_ = crypto(d2i_PrivateKey(type, openssl(&pkey_), &s, (long)k.size()));
	}

	void PrivateKey::fromPEM(const std::string& k)
	{
		BIO* bio = BIO_new(BIO_s_mem());
		BIO_write(bio, k.c_str(), (long)k.size());
		pkey_ = crypto(PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL));
		BIO_free(bio);
	}

    std::string PrivateKey::get_public_key_der()
	{
		::EVP_PKEY* pkey = openssl(pkey_);

		int len = i2d_PublicKey(pkey, NULL);
		uchar_buf buf(len);

		unsigned char* p = &buf;
		i2d_PublicKey(pkey, &p);

		return buf.toString(len);
	}

    std::string PrivateKey::get_public_key_pem()
	{
		BIO* bio = BIO_new(BIO_s_mem());

		int len = PEM_write_bio_PUBKEY(bio, openssl(pkey_));

		unsigned char* output;
		len = BIO_get_mem_data(bio, &output);

		std::string result((char*)output, len);

		BIO_free(bio);

		return result;
	}


	PublicKey::PublicKey()
	{
		pkey_ = crypto(EVP_PKEY_new());
	}

	PublicKey::PublicKey(const std::string& file)
	{
		FILE* f = fopen(file.c_str(), "r");
		if (!f)
		{
			throw PublicKeyEx();
		}
		pkey_ = crypto(PEM_read_PUBKEY(f, NULL, 0, 0));
		fclose(f);
	}

	PublicKey::~PublicKey()
	{
		EVP_PKEY_free(openssl(pkey_));
	}

	std::string PublicKey::toDER()
	{
		::EVP_PKEY* pkey = openssl(pkey_);

		int len = i2d_PUBKEY(pkey, NULL);
		uchar_buf buf(len);

		unsigned char* p = &buf;
		i2d_PUBKEY(pkey, &p);

		return buf.toString(len);
	}

	std::string PublicKey::toPEM()
	{
		BIO* bio = BIO_new(BIO_s_mem());

		int len = PEM_write_bio_PUBKEY(bio, openssl(pkey_));

		unsigned char* output;
		len = BIO_get_mem_data(bio, &output);

		std::string result((char*)output, len);

		BIO_free(bio);

		return result;
	}

	void PublicKey::fromDER(const std::string& k)
	{
		const unsigned char* s = (const unsigned char*)k.c_str();
		d2i_PUBKEY(openssl(&pkey_), &s, (long) k.size());
	}


	void PublicKey::fromPEM(const std::string& k)
	{
		BIO* bio = BIO_new(BIO_s_mem());
		BIO_write(bio, k.c_str(), (long)k.size());
		pkey_ = crypto(PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL));
		BIO_free(bio);
	}

	bool generate_rsa_pair(PrivateKey& privKey, PublicKey& pubKey, int bits)
	{
		::EVP_PKEY* pkey = EVP_RSA_gen(bits);

		uchar_buf buf(bits);
		unsigned char *tmp = &buf;
		int len = i2d_PUBKEY(pkey, &tmp);
		if (len <= 0)
		{
			throw RsaKeyEx();
		}

		std::string pubKeyDer = buf.toString();
		pubKey.fromDER(pubKeyDer);

		tmp = &buf;
		len = i2d_PrivateKey(pkey, &tmp);
		if (len <= 0)
		{
			throw RsaKeyEx();
		}

		std::string privKeyDer = buf.toString();
		privKey.fromDER(EVP_PKEY_RSA, privKeyDer);

		return true;
	}


	class SignatureCtx 
	{
	public:
		::EVP_MD_CTX* ctx;
		
		SignatureCtx()
		{
			ctx = EVP_MD_CTX_new();
		}
		~SignatureCtx()
		{
			EVP_MD_CTX_free(ctx);
		}
	};

	Signature::Signature(EVP_PKEY* key)
		: md_(digest("sha256")), pkey_(key)
	{}

	Signature::Signature(const EVP_MD* md, EVP_PKEY* key)
		: md_(md), pkey_(key)
	{}

	std::string Signature::sign(const std::string& msg)
	{
		::EVP_PKEY* pkey = openssl(pkey_);

		SignatureCtx ctx;

		EVP_SignInit(ctx.ctx, openssl(md_));
		int size = EVP_PKEY_size(pkey);

		if (!EVP_SignUpdate(ctx.ctx, msg.c_str(), msg.size()))
		{
			throw SignatureEx();
		}

		uchar_buf sig(size);
		unsigned int len = 0;
		if (!EVP_SignFinal(ctx.ctx, &sig, &len, pkey))
		{
			throw SignatureEx();
		}

		return sig.toString(len);
	}

	bool Signature::verify(const std::string& msg, const std::string& sig)
	{
		SignatureCtx ctx;
		int r = EVP_VerifyInit(ctx.ctx, openssl(md_));

		r = EVP_VerifyUpdate(ctx.ctx, msg.c_str(), msg.size());
		if (!r)
		{
			//throw CryptoEx();
			return false;
		}
		r = EVP_VerifyFinal(
			ctx.ctx,
			(unsigned char *)sig.c_str(),
			(unsigned int)sig.size(),
			openssl(pkey_)
		);
		if (!r)
		{
			//int n = ERR_get_error();
			//const char* e = ERR_error_string(n,0);
			//throw CryptoEx(e);
		}

		return r == 1;
	}

	class EnvelopeCtx 
	{
	public:
		::EVP_CIPHER_CTX* ctx;
		
		EnvelopeCtx()
		{
			ctx = EVP_CIPHER_CTX_new();
		}
		~EnvelopeCtx()
		{
			EVP_CIPHER_CTX_free(ctx);
		}
	};

	Envelope::Envelope()
		: cipher_(cipher("aes_256_cbc"))
	{}

	Envelope::Envelope(const EVP_CIPHER* cipher)
		: cipher_(cipher)
	{}

	std::string Envelope::seal(EVP_PKEY* rsakey, const std::string& msg)
	{
		EnvelopeCtx ctx;

		::EVP_PKEY* pkey = openssl(rsakey);
		const ::EVP_CIPHER* cipher = openssl(cipher_);

		auto key = std::shared_ptr<unsigned char>(
			(unsigned char*)malloc(EVP_PKEY_size(pkey)), 
			[](unsigned char* p) { free(p); }
		);

		auto iv  = std::shared_ptr<unsigned char>(
			(unsigned char*)malloc(EVP_CIPHER_iv_length(cipher)), 
			[](unsigned char* p) { free(p); }
		);

		uint32_t ekl = 1;

		unsigned char* k = key.get();

		if (!EVP_SealInit(ctx.ctx, cipher, &k, (int*)&ekl, iv.get(), &pkey, 1))
		{
			throw EnvelopeEx();
		}

		int n = (int) (EVP_CIPHER_block_size(cipher) + msg.size() - 1);
		uchar_buf outbuf(n + 1);

		if (EVP_SealUpdate(
			ctx.ctx,
			&outbuf, &n,
			(unsigned char*)msg.c_str(), (long) msg.size()
		) != 1)
		{
			throw EnvelopeEx();
		}

		int tlen = 0;
		if (EVP_SealFinal(ctx.ctx, &outbuf + n, &tlen) != 1)
		{
			throw EnvelopeEx();
		}
		n += tlen;

		std::ostringstream oss;
		uint32_t l = htonl(ekl);
		oss.write((char*)(&l),sizeof(l));
		oss.write((char*)k,ekl);
		oss.write((char*)(iv.get()),EVP_CIPHER_iv_length(cipher));
		oss.write((char*)&outbuf,n);

		return oss.str();
	}

	std::string Envelope::open(EVP_PKEY* rsakey, const std::string & msg)
	{
		EnvelopeCtx ctx;
		uint32_t ekl = 0;
		uint32_t l = 0;
		const ::EVP_CIPHER* cipher = openssl(cipher_);

		std::istringstream iss(msg);
		iss.read((char*)&l,sizeof(l));
		ekl = ntohl(l);
		uchar_buf key(ekl);
		iss.read((char*)&key,ekl);
		uchar_buf iv(EVP_CIPHER_iv_length(cipher));
		iss.read((char*)&iv,iv.size());

		int headerlen = sizeof(ekl)+ekl+EVP_CIPHER_iv_length(cipher);
		std::string ciphertxt = msg.substr(headerlen);

		if (!EVP_OpenInit(ctx.ctx,cipher, &key, ekl, &iv, openssl(rsakey)))
		{
			throw EnvelopeEx();
		}

		int n = (int) (EVP_CIPHER_block_size(cipher) + ciphertxt.size() - 1);
		uchar_buf outbuf(n + 1);

		if (EVP_OpenUpdate(
			ctx.ctx,
			&outbuf, &n,
			(unsigned char*)ciphertxt.c_str(), (long) ciphertxt.size()
		) != 1)
		{
			throw EnvelopeEx();
		}

		int tlen = 0;
		if (EVP_OpenFinal(ctx.ctx, &outbuf + n, &tlen) != 1)
		{
			throw EnvelopeEx();
		}
		n += tlen;

		return std::string((char*)&outbuf, n);
	}

	std::string Password::hash(const std::string& plaintxt)
	{
		std::string salt = toHex(nonce(8)).substr(0, 8);

		return hash(plaintxt, salt);
	}

	bool Password::verify(const std::string& plaintxt, const std::string& h)
	{
		return hash(plaintxt, h) == h;
	}

	std::string Password::hash(const std::string& plaintxt, const std::string& h)
	{
		std::string salt = h.substr(0, 8);

		unsigned char buf[129];

		int r = PKCS5_PBKDF2_HMAC_SHA1(plaintxt.c_str(), (long) plaintxt.size(),
			(const unsigned char *)(salt.c_str()), (long) salt.size(), 1000,
			128, buf);

		if (!r)
		{
			throw CryptoEx();
		}

		std::ostringstream oss;
		oss << salt << toHex(std::string((char*)buf, 128));

		return oss.str();
	}
	///////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////

	DiffieHellman::DiffieHellman(const std::string& params)
	{		
		PrivateKey domainKey;
		domainKey.fromPEM(params);

		::EVP_PKEY* domainParamKey = openssl( (EVP_PKEY*) domainKey);

		EVP_PKEY_CTX* keyGenerationCtx = EVP_PKEY_CTX_new_from_pkey(nullptr, domainParamKey, nullptr);
		if (!keyGenerationCtx) 
		{
			printf("1: %s", ERR_error_string(ERR_get_error(), NULL));
			throw DhEx();		
		}
		if (EVP_PKEY_keygen_init(keyGenerationCtx) <= 0) 
		{
			printf("2: %s", ERR_error_string(ERR_get_error(), NULL));
			throw DhEx();		
		}
		
		int r = EVP_PKEY_generate(keyGenerationCtx, openssl( (EVP_PKEY**)dhparams_));
		if (r <= 0) 
		{
			printf("3: %i %s", r, ERR_error_string(ERR_get_error(), NULL));
			throw DhEx();		
		}

		EVP_PKEY_CTX_free(keyGenerationCtx);
	
	}

	std::string DiffieHellman::generate()
	{
		int priv_len = 2 * 112;
		OSSL_PARAM params[3];
		EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);

		params[0] = OSSL_PARAM_construct_utf8_string("group", (char*)"ffdhe2048", 0);
		/* "priv_len" is optional */
		params[1] = OSSL_PARAM_construct_int("priv_len", &priv_len);
		params[2] = OSSL_PARAM_construct_end();

		EVP_PKEY_keygen_init(pctx);
		EVP_PKEY_CTX_set_params(pctx, params);

		PrivateKey domainKey;
		::EVP_PKEY** domainParamKey = openssl( (EVP_PKEY**) domainKey);
		EVP_PKEY_generate(pctx, domainParamKey);

		std::string result = domainKey.toPEM();

		EVP_PKEY_CTX_free(pctx);


		EVP_PKEY_CTX* keyGenerationCtx = EVP_PKEY_CTX_new_from_pkey(nullptr, *domainParamKey, nullptr);
		if (!keyGenerationCtx) 
		{
			printf("1: %s", ERR_error_string(ERR_get_error(), NULL));
			throw DhEx();		
		}
		if (EVP_PKEY_keygen_init(keyGenerationCtx) <= 0) 
		{
			printf("2: %s", ERR_error_string(ERR_get_error(), NULL));
			throw DhEx();		
		}
		
		int r = EVP_PKEY_generate(keyGenerationCtx, openssl( (EVP_PKEY**)dhparams_));
		if (r <= 0) 
		{
			printf("3: %i %s", r, ERR_error_string(ERR_get_error(), NULL));
			throw DhEx();		
		}
		EVP_PKEY_CTX_free(keyGenerationCtx);

		return result;
	}

    std::string DiffieHellman::secret(const std::string& peerKeyPEM)
	{
		::EVP_PKEY_CTX* ctx = 0;
		unsigned char *skey = 0;
		size_t skeylen = 0;

		PublicKey pubKey;
		pubKey.fromPEM(peerKeyPEM);

		::EVP_PKEY* peerkey = openssl( (EVP_PKEY*)pubKey);
		::EVP_PKEY* pkey = openssl((EVP_PKEY*)dhparams_);

		ctx = EVP_PKEY_CTX_new(pkey,0);
		if (!ctx)
		{
			printf("%s", ERR_error_string(ERR_get_error(), NULL));
			throw DhEx();		
		}

		if (EVP_PKEY_derive_init(ctx) <= 0)
		{
			printf("%s", ERR_error_string(ERR_get_error(), NULL));
			throw DhEx();		
		}

		if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0)
		{
			printf("%s", ERR_error_string(ERR_get_error(), NULL));
			throw DhEx();		
		}

		/* Determine buffer length */
		if (EVP_PKEY_derive(ctx, NULL, &skeylen) <= 0)
		{
			printf("%s", ERR_error_string(ERR_get_error(), NULL));
			throw DhEx();		
		}

		skey = (unsigned char*) OPENSSL_malloc(skeylen);

		if (!skey)
		{
			printf("%s", ERR_error_string(ERR_get_error(), NULL));
			throw DhEx();		
		}
		
		if (EVP_PKEY_derive(ctx, skey, &skeylen) <= 0)
		{
			printf("%s", ERR_error_string(ERR_get_error(), NULL));
			throw DhEx();		
		}

		/* Shared secret is skey bytes written to buffer skey */
		std::string secret( (const char*) skey, skeylen );
		std::string result = toHex(sha256(secret));

		OPENSSL_free(skey);
		EVP_PKEY_CTX_free(ctx);
		return result;
	}

	std::string DiffieHellman::get_public_key()
	{
		return dhparams_.get_public_key_pem();
	}

	///////////////////////////////////////////////////////////////////////////////////
	// static callbacks
	///////////////////////////////////////////////////////////////////////////////////


	Mutex* SSLUser::mutexe()
	{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		static Mutex mutex_[CRYPTO_NUM_LOCKS];
		return mutex_;
#else
		return nullptr;
#endif		
	}

	CRYPTO_dynlock_value* SSLUser::dyn_create_function(const char* /*file*/, int /*line*/ )
	{
		return new CRYPTO_dynlock_value;
	}

	void SSLUser::dyn_lock_function(int mode, CRYPTO_dynlock_value* mutex, const char* /*file*/, int /*line*/ )
	{
		if (mode & CRYPTO_LOCK)
		{
			mutex->mutex.aquire();
		}
		else
		{
			mutex->mutex.release();
		}
	}

	void SSLUser::dyn_destroy_function(CRYPTO_dynlock_value* mutex, const char* /*file*/, int /*line*/ )
	{
		delete mutex;
	}

	void SSLUser::locking_function(int mode, int n, const char* /*file*/, int /*line*/ )
	{
		if (mode & CRYPTO_LOCK)
		{
			mutexe()[n].aquire();
		}
		else
		{
			mutexe()[n].release();
		}
	}

	unsigned long SSLUser::id_function()
	{
		std::stringstream ss;
		ss << std::this_thread::get_id();
		uint32_t id = std::stoul(ss.str());
		return id;
	}

	///////////////////////////////////////////////////////////////////////////////////
	// initialize ssl libs RAII helper
	///////////////////////////////////////////////////////////////////////////////////

	SSLUser::SSLUser()
	{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		CRYPTO_set_locking_callback(locking_function);
		CRYPTO_set_id_callback(id_function);
		CRYPTO_set_dynlock_create_callback(dyn_create_function);
		CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
		CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
#endif		
		SSL_library_init();
#if OPENSSL_VERSION_MAJOR < 3

		ERR_load_BIO_strings();
#endif
		//	SSL_load_error_strings();
		OpenSSL_add_all_algorithms();

		int rand_bytes_read;
		char buf[1024];

		rand_bytes_read = RAND_load_file("/dev/urandom", 1024);
		if (rand_bytes_read <= 0) 
		{
			// seed from stack as urandom has not enough entropie
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
			RAND_seed(buf, sizeof buf);
#pragma GCC diagnostic pop
		}

	}

	SSLUser::~SSLUser()
	{
		ENGINE_cleanup();
		CONF_modules_unload(1);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		ERR_remove_state(1);
#endif		
		ERR_free_strings();
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
		SSL_COMP_free_compression_methods();
	}

	Mutex::Mutex()
	{}

	Mutex::~Mutex()
	{}

	void Mutex::aquire()
	{
		mutex_.lock();
	}

	int Mutex::aquired()
	{
		if (mutex_.try_lock())
		{
			mutex_.unlock();
			return false;
		}
		return true;
	}

	void Mutex::release()
	{
		mutex_.unlock();
	}

}


