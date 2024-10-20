#include <memory>
#include <list>
#include <utility>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <exception>
#include <functional>

#include "utest.h"
#include "cryptoneat/cryptoneat.h"
#include "cryptoneat/base64.h"
#include "cryptoneat/uuid.h"

#ifdef _WIN32
#include <openssl/applink.c>
#endif


using namespace cryptoneat;

struct CryptoNeatTest
{};

UTEST_F_SETUP(CryptoNeatTest) {}
UTEST_F_TEARDOWN(CryptoNeatTest) {}



UTEST_F(CryptoNeatTest, Base64Test) 
{
    std::string input = "/bla/blub/wupp/bla/blub/wupp/bla/blub/wupp/bla/blub/wupp/";
    std::string b64 = Base64::encode(input);
    EXPECT_STREQ("L2JsYS9ibHViL3d1cHAvYmxhL2JsdWIvd3VwcC9ibGEvYmx1Yi93dXBwL2JsYS9ibHViL3d1cHAv",b64.c_str());
}


UTEST_F(CryptoNeatTest, Base64Test2) 
{
    std::string input = "ewogICAiYWxnIiA6ICJIUzI1NiIsCiAgICJ0eXAiIDogIkpXVCIKfQo=";
    std::string plain = Base64::decode(input);
    EXPECT_STREQ("{\n   \"alg\" : \"HS256\",\n   \"typ\" : \"JWT\"\n}\n",plain.c_str());
}


UTEST_F(CryptoNeatTest, Base64Binary)
{

	for( int i = 1; i < 250; i+=10)
	{
		std::ostringstream oss;
		for ( int j = 0; j < 100; j++)
		{
			std::string n = nonce(i);
			oss.write(n.c_str(),n.size());
		}
		char c = -32;
		oss.write(&c,1);
		size_t s1 = oss.str().size();
		std::string b64 = Base64::encode(oss.str());
		std::string tmp = Base64::decode(b64);
		size_t s2 = tmp.size();

		EXPECT_EQ(s1,s2);
	}

}


UTEST_F(CryptoNeatTest, Base64decodeTest) 
{
    std::string input = "L2JsYS9ibHViL3d1cHAvYmxhL2JsdWIvd3VwcC9ibGEvYmx1Yi93dXBwLw==";
    std::string plain = Base64::decode(input);
    EXPECT_STREQ("/bla/blub/wupp/bla/blub/wupp/bla/blub/wupp/",plain.c_str());
}

UTEST_F(CryptoNeatTest, Base64UrlTest) 
{
    std::string input = "/bla/blub/wupp/bla/blub/wupp/bla/blub/wupp/bla/blub/wupp/";
    std::string b64 = Base64Url::encode(input);
    EXPECT_STREQ("L2JsYS9ibHViL3d1cHAvYmxhL2JsdWIvd3VwcC9ibGEvYmx1Yi93dXBwL2JsYS9ibHViL3d1cHAv",b64.c_str());
}


UTEST_F(CryptoNeatTest, Base64UrldecodeTest) 
{
    std::string input = "L2JsYS9ibHViL3d1cHAvYmxhL2JsdWIvd3VwcC9ibGEvYmx1Yi93dXBwLw==";
    std::string plain = Base64Url::decode(input);
    EXPECT_STREQ("/bla/blub/wupp/bla/blub/wupp/bla/blub/wupp/",plain.c_str());
}

UTEST_F(CryptoNeatTest, MD5Test) 
{
    std::string input = "a well known secret";
    std::string hash = toHex(md5(input));
    EXPECT_STREQ("e981fe735ca6982848f913eb0d9d254d",hash.c_str());
}


UTEST_F(CryptoNeatTest, evpTest) 
{
    std::string input = "a well known secret";
    Digest evp(digest("md5"));
    std::string hash = toHex(evp.digest(input));
    EXPECT_STREQ("e981fe735ca6982848f913eb0d9d254d",hash.c_str());

    hash = toHex(evp.digest(input));
    EXPECT_STREQ("e981fe735ca6982848f913eb0d9d254d",hash.c_str());
}


UTEST_F(CryptoNeatTest, hextest2) 
{
    unsigned char hex[] = { 1, 244, 27, 0, 4, 5, 0 };
    std::string s( (char*)hex, 6 );
    std::string hexed = toHex( s );
    EXPECT_STREQ("01f41b000405",hexed.c_str());

    std::string raw = fromHex(hexed);
    EXPECT_STREQ(s.c_str(),raw.c_str());
}


UTEST_F(CryptoNeatTest, sha1test) 
{
    std::string input = "a well known secret";
    Digest evp(digest("sha1"));
    std::string hash = toHex(evp.digest(input));
    EXPECT_STREQ("652e0dbf69408801392353ba386313bf01ff04ce",hash.c_str());

    hash = toHex(evp.digest(input));
    EXPECT_STREQ("652e0dbf69408801392353ba386313bf01ff04ce",hash.c_str());
}




UTEST_F(CryptoNeatTest, sha1test3) 
{
    std::string input = "a well known secret";
    std::string hash = toHex(sha1(input));
    EXPECT_STREQ("652e0dbf69408801392353ba386313bf01ff04ce",hash.c_str());

    hash = toHex(sha1(input));
    EXPECT_STREQ("652e0dbf69408801392353ba386313bf01ff04ce",hash.c_str());
}



UTEST_F(CryptoNeatTest, sha256test) 
{
    std::string input = "a well known secret";
    std::string hash = toHex(sha256(input));
    EXPECT_STREQ("428b79463ec0b5b89379da202f663116f93cbdb99632a86cf84183bbf787c2af",hash.c_str());

    hash = toHex(sha256(input));
    EXPECT_STREQ("428b79463ec0b5b89379da202f663116f93cbdb99632a86cf84183bbf787c2af",hash.c_str());
}



UTEST_F(CryptoNeatTest, bfTest) 
{
    std::string input = "aha";
    std::string key   = "123";

	for(int i = 0; i < 1000; i++)
	{
		SymCrypt encrypt(cipher("aes_256_cbc"), key);
		std::string ciph = encrypt.encrypt(input);

		SymCrypt decrypt(cipher("aes_256_cbc"), key);
		std::string plain = decrypt.decrypt(fromHex(toHex(ciph)));

		EXPECT_STREQ(input.c_str(),plain.c_str());
	}
}



UTEST_F(CryptoNeatTest, rc4Test) 
{
    std::string input = "a well known secret";
    std::string key   = "the secret secret key";

    SymCrypt encrypt(cipher("des_ede3_cfb1"),key);
    std::string ciph = encrypt.encrypt(input);

    std::cerr << ciph.substr(0,8) << std::endl;
    std::cerr << toHex(ciph) << std::endl;

    SymCrypt decrypt(cipher("des_ede3_cfb1"), key);
    std::string plain = decrypt.decrypt(ciph);

    EXPECT_STREQ(input.c_str(),plain.c_str());
}

UTEST_F(CryptoNeatTest, hmacMD5Test) 
{
    std::string input = "a well known secret";
    std::string key   = "the secret secret key";

    Hmac hmac("md5",key);

    std::string hash = hmac.hash(input);
    std::cerr << toHex(hash) << std::endl;

    Hmac hmac2("md5",key);
    std::string input2 = "a well known secret";
    std::string hash2 = hmac2.hash(input2);
    std::cerr << toHex(hash2) << std::endl;

    EXPECT_STREQ(hash.c_str(),hash2.c_str());
}

UTEST_F(CryptoNeatTest, hmacSha1Test) 
{
    std::string input = "a well known secret";
    std::string key   = "the secret secret key";

    Hmac hmac("sha1",key);

    std::string hash = hmac.hash(input);
    std::cerr << toHex(hash) << std::endl;

    Hmac hmac2("sha1",key);
    std::string input2 = "a well known secret";
    std::string hash2 = hmac2.hash(input2);
    std::cerr << toHex(hash2) << std::endl;

    EXPECT_STREQ(hash.c_str(),hash2.c_str());
}

UTEST_F(CryptoNeatTest, SignTest) 
{
    std::string input = "a well known secret";
    PrivateKey privateKey("pem/private.pem");
    PublicKey publicKey("pem/public.pem");

    Signature signor(digest("sha1"), privateKey );

    std::string sig = signor.sign(input);
    std::cerr << toHex(sig) << std::endl;

    Signature verifier(digest("sha1"), publicKey );

    bool verified = verifier.verify(input,sig);

    EXPECT_EQ(int(true),int(verified));
}



UTEST_F(CryptoNeatTest, EvelopeTest) 
{
    std::string input = "a well known secret";
    PrivateKey privateKey("pem/private.pem");
    PublicKey publicKey("pem/public.pem");

    Envelope sealer(cipher("aes_128_cbc") );

    std::string sealed = sealer.seal(publicKey,input);

    std::cerr << toHex(sealed) << std::endl;

    Envelope opener(cipher("aes_128_cbc"));
    std::string plain = opener.open(privateKey,sealed);

    EXPECT_STREQ(input.c_str(),plain.c_str());
}


UTEST_F(CryptoNeatTest, EvelopeTest2) 
{
    std::string input = "a well known secret";
    PrivateKey privateKey("pem/private.pem");
    PublicKey publicKey("pem/public.pem");

    Envelope sealer(cipher("des_ede3_cfb1"));

    std::string sealed = sealer.seal(publicKey,input);

    std::cerr << toHex(sealed) << std::endl;

    Envelope opener(cipher("des_ede3_cfb1"));
    std::string plain = sealer.open(privateKey,sealed);

    EXPECT_STREQ(input.c_str(),plain.c_str());
}



/*
UTEST_F(CryptoNeatTest, PrintIVsize) {

    std::cerr << "des-cbc " << EVP_CIPHER_iv_length(EVP_des_cbc()) << std::endl;
    std::cerr << "bf-cbc " << EVP_CIPHER_iv_length(EVP_bf_cbc()) << std::endl;
    std::cerr << "des_ede3_cbc " << EVP_CIPHER_iv_length(EVP_des_ede3_cbc()) << std::endl;
    std::cerr << "aes-256-cbc " << EVP_CIPHER_iv_length(EVP_aes_256_cbc()) << std::endl;
    std::cerr << "rc4 " << EVP_CIPHER_iv_length(EVP_rc4()) << std::endl;
}
*/



UTEST_F(CryptoNeatTest, DERTest) 
{
    std::string input = "a well known secret";
    PrivateKey privateKey("pem/private.pem");
    PublicKey publicKey("pem/public.pem");

    Signature signor(digest("sha1"), privateKey );

    std::string sig = signor.sign(input);
    std::cerr << toHex(sig) << std::endl;

    std::string der = publicKey.toDER();
    std::cerr << toHex(der) << std::endl;

    std::ofstream ofs;
    ofs.open("pem/public.der");
    ofs.write(der.c_str(),der.size());
    ofs.close();

    std::string d = privateKey.toDER();
    std::ofstream ofs2;
    ofs2.open("pem/private.der");
    ofs2.write(d.c_str(),d.size());
    ofs2.close();

    PublicKey pk;
    pk.fromDER(der);

    Signature verifier(digest("sha1"), pk );

    bool verified = verifier.verify(input,sig);

    EXPECT_TRUE( verified );
}

UTEST_F(CryptoNeatTest, DER2Test) 
{
    std::string input = "a well known secret";
    PrivateKey privateKey("pem/private.pem");
    PublicKey publicKey("pem/public.pem");

    std::string der = privateKey.toDER();
    PrivateKey pk;
    pk.fromDER(PrivateKey::EVP_PKEY_RSA,der);

    Signature signor(digest("sha1"), pk );

    std::string sig = signor.sign(input);
    std::cerr << toHex(sig) << std::endl;

    Signature verifier(digest("sha1"), publicKey );

    bool verified = verifier.verify(input,sig);

    EXPECT_TRUE( verified );
}

UTEST_F(CryptoNeatTest, RSAKeyGenTest) 
{
    std::string input = "a well known secret";

    PrivateKey privateKey;
    PublicKey publicKey;

    bool b = generate_rsa_pair(privateKey,publicKey);
    EXPECT_TRUE(b);

//    std::cout << "publkey:" << std::endl << toHex(publicKey.toDER()).size() << std::endl;
//    std::cout << "privkey:" << std::endl << toHex(privateKey.toDER()).size() << std::endl;

    std::cout << "publkey:" << std::endl << publicKey.toPEM() << std::endl;
    std::cout << "privkey:" << std::endl << privateKey.toPEM() << std::endl;

    Signature signor(digest("sha1"), privateKey);

    std::string sig = signor.sign(input);
    std::cerr << toHex(sig) << std::endl;

    Signature verifier(digest("sha1"), publicKey );

    bool verified = verifier.verify(input,sig);

    EXPECT_TRUE( verified );

}

UTEST_F(CryptoNeatTest, RSAKeyGenTestPEM) 
{
    std::string input = "a well known secret";

    PrivateKey privateKey;
    PublicKey publicKey;

    bool b = generate_rsa_pair(privateKey,publicKey);
    EXPECT_TRUE( b );

    std::string privatekeyPEM = privateKey.toPEM();
    std::string publickeyPEM = publicKey.toPEM();

    PrivateKey privateKey2;
    PublicKey publicKey2;

    privateKey2.fromPEM(privatekeyPEM);
    publicKey2.fromPEM(publickeyPEM);

    Signature signor(digest("sha1"), privateKey2);

    std::string sig = signor.sign(input);
    std::cerr << toHex(sig) << std::endl;

    Signature verifier(digest("sha1"), publicKey2 );

    bool verified = verifier.verify(input,sig);

    EXPECT_TRUE( verified );
}



UTEST_F(CryptoNeatTest, pwdTest)
{
	Password pwd;

	std::string hash = pwd.hash("secretpwd");

	std::cout << hash.size() << ":" << hash << std::endl;

	bool b = pwd.verify("secretpwd", hash);

	std::cout << b << std::endl;
	EXPECT_TRUE(b);

	b = pwd.verify("secret-pwd", hash);

	std::cout << b << std::endl;
	EXPECT_FALSE(b);
}

UTEST_F(CryptoNeatTest, dhTest)
{
    DiffieHellman dhBob;
    std::string dhParams = dhBob.generate();
    std::string bobPubKey = dhBob.get_public_key();
    std::cout << bobPubKey << std::endl;

    DiffieHellman dhAlice(dhParams);
    std::string alicePubKey = dhAlice.get_public_key();
    std::cout << alicePubKey << std::endl;

    std::string bobSecret = dhBob.secret(alicePubKey);
    std::string aliceSecret = dhAlice.secret(bobPubKey);

    std::cout << (bobSecret == aliceSecret) << std::endl;
    std::cout << bobSecret << std::endl;
    std::cout << aliceSecret << std::endl;
    EXPECT_STREQ(bobSecret.c_str(),aliceSecret.c_str());
}

UTEST_F(CryptoNeatTest, uuidTest)
{
    std::string uuid = uuid::generate();
    std::cout << uuid << std::endl;
}



UTEST_STATE();

int main(int argc, char **argv) 
{    
	SSLUser sslUser;

    return utest_main(argc,argv);
}
