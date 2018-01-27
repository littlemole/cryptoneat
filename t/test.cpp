#include "gtest/gtest.h"
#include <memory>
#include <list>
#include <utility>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <exception>
#include <functional>

#include "cryptoneat/cryptoneat.h"
#include "cryptoneat/base64.h"
#include "cryptoneat/uuid.h"

#ifdef _WIN32
#include <openssl/applink.c>
#endif


using namespace cryptoneat;


class CryptoNeatTest : public ::testing::Test 
{
 protected:

  static void SetUpTestCase() 
  {}

  virtual void SetUp() 
  {
  }

  virtual void TearDown() 
  {
  }

}; // end test setup



TEST_F(CryptoNeatTest, Base64Test) 
{
    std::string input = "/bla/blub/wupp/bla/blub/wupp/bla/blub/wupp/bla/blub/wupp/";
    std::string b64 = Base64::encode(input);
    EXPECT_EQ("L2JsYS9ibHViL3d1cHAvYmxhL2JsdWIvd3VwcC9ibGEvYmx1Yi93dXBwL2JsYS9ibHViL3d1cHAv",b64);
}


TEST_F(CryptoNeatTest, Base64Test2) 
{
    std::string input = "ewogICAiYWxnIiA6ICJIUzI1NiIsCiAgICJ0eXAiIDogIkpXVCIKfQo=";
    std::string plain = Base64::decode(input);
    EXPECT_EQ("{\n   \"alg\" : \"HS256\",\n   \"typ\" : \"JWT\"\n}\n",plain);
}


TEST_F(CryptoNeatTest, Base64Binary)
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
		int s1 = oss.str().size();
		std::string b64 = Base64::encode(oss.str());
		std::string tmp = Base64::decode(b64);
		int s2 = tmp.size();

		EXPECT_EQ(s1,s2);
	}

}


TEST_F(CryptoNeatTest, Base64decodeTest) 
{
    std::string input = "L2JsYS9ibHViL3d1cHAvYmxhL2JsdWIvd3VwcC9ibGEvYmx1Yi93dXBwLw==";
    std::string plain = Base64::decode(input);
    EXPECT_EQ("/bla/blub/wupp/bla/blub/wupp/bla/blub/wupp/",plain);
}

TEST_F(CryptoNeatTest, Base64UrlTest) 
{
    std::string input = "/bla/blub/wupp/bla/blub/wupp/bla/blub/wupp/bla/blub/wupp/";
    std::string b64 = Base64Url::encode(input);
    EXPECT_EQ("L2JsYS9ibHViL3d1cHAvYmxhL2JsdWIvd3VwcC9ibGEvYmx1Yi93dXBwL2JsYS9ibHViL3d1cHAv",b64);
}


TEST_F(CryptoNeatTest, Base64UrldecodeTest) 
{
    std::string input = "L2JsYS9ibHViL3d1cHAvYmxhL2JsdWIvd3VwcC9ibGEvYmx1Yi93dXBwLw==";
    std::string plain = Base64Url::decode(input);
    EXPECT_EQ("/bla/blub/wupp/bla/blub/wupp/bla/blub/wupp/",plain);
}

TEST_F(CryptoNeatTest, MD5Test) 
{
    std::string input = "a well known secret";
    std::string hash = toHex(md5(input));
    EXPECT_EQ("e981fe735ca6982848f913eb0d9d254d",hash);
}


TEST_F(CryptoNeatTest, evpTest) 
{
    std::string input = "a well known secret";
    Digest evp(digest("md5"));
    std::string hash = toHex(evp.digest(input));
    EXPECT_EQ("e981fe735ca6982848f913eb0d9d254d",hash);

    hash = toHex(evp.digest(input));
    EXPECT_EQ("e981fe735ca6982848f913eb0d9d254d",hash);
}


TEST_F(CryptoNeatTest, hextest2) 
{
    unsigned char hex[] = { 1, 244, 27, 0, 4, 5, 0 };
    std::string s( (char*)hex, 6 );
    std::string hexed = toHex( s );
    EXPECT_EQ("01f41b000405",hexed);

    std::string raw = fromHex(hexed);
    EXPECT_EQ(s,raw);
}


TEST_F(CryptoNeatTest, sha1test) 
{
    std::string input = "a well known secret";
    Digest evp(digest("sha1"));
    std::string hash = toHex(evp.digest(input));
    EXPECT_EQ("652e0dbf69408801392353ba386313bf01ff04ce",hash);

    hash = toHex(evp.digest(input));
    EXPECT_EQ("652e0dbf69408801392353ba386313bf01ff04ce",hash);
}




TEST_F(CryptoNeatTest, sha1test3) 
{
    std::string input = "a well known secret";
    std::string hash = toHex(sha1(input));
    EXPECT_EQ("652e0dbf69408801392353ba386313bf01ff04ce",hash);

    hash = toHex(sha1(input));
    EXPECT_EQ("652e0dbf69408801392353ba386313bf01ff04ce",hash);
}



TEST_F(CryptoNeatTest, sha256test) 
{
    std::string input = "a well known secret";
    std::string hash = toHex(sha256(input));
    EXPECT_EQ("428b79463ec0b5b89379da202f663116f93cbdb99632a86cf84183bbf787c2af",hash);

    hash = toHex(sha256(input));
    EXPECT_EQ("428b79463ec0b5b89379da202f663116f93cbdb99632a86cf84183bbf787c2af",hash);
}



TEST_F(CryptoNeatTest, bfTest) 
{
    std::string input = "aha";
    std::string key   = "123";

	for(int i = 0; i < 1000; i++)
	{
		SymCrypt encrypt(cipher("bf_cbc"), key);
		std::string ciph = encrypt.encrypt(input);

		SymCrypt decrypt(cipher("bf_cbc"), key);
		std::string plain = decrypt.decrypt(fromHex(toHex(ciph)));

		EXPECT_EQ(input,plain);
	}
}



TEST_F(CryptoNeatTest, rc4Test) 
{
    std::string input = "a well known secret";
    std::string key   = "the secret secret key";

    SymCrypt encrypt(cipher("rc4"),key);
    std::string ciph = encrypt.encrypt(input);

    std::cerr << ciph.substr(0,8) << std::endl;
    std::cerr << toHex(ciph) << std::endl;

    SymCrypt decrypt(cipher("rc4"), key);
    std::string plain = decrypt.decrypt(ciph);

    EXPECT_EQ(input,plain);
}

TEST_F(CryptoNeatTest, hmacMD5Test) 
{
    std::string input = "a well known secret";
    std::string key   = "the secret secret key";

    Hmac hmac(digest("md5"),key);

    std::string hash = hmac.hash(input);
    std::cerr << toHex(hash) << std::endl;

    Hmac hmac2(digest("md5"),key);
    std::string input2 = "a well known secret";
    std::string hash2 = hmac2.hash(input2);
    std::cerr << toHex(hash2) << std::endl;

    EXPECT_EQ(hash,hash2);
}

TEST_F(CryptoNeatTest, hmacSha1Test) 
{
    std::string input = "a well known secret";
    std::string key   = "the secret secret key";

    Hmac hmac(digest("sha1"),key);

    std::string hash = hmac.hash(input);
    std::cerr << toHex(hash) << std::endl;

    Hmac hmac2(digest("sha1"),key);
    std::string input2 = "a well known secret";
    std::string hash2 = hmac2.hash(input2);
    std::cerr << toHex(hash2) << std::endl;

    EXPECT_EQ(hash,hash2);
}

TEST_F(CryptoNeatTest, SignTest) 
{
    std::string input = "a well known secret";
    PrivateKey privateKey("pem/private.pem");
    PublicKey publicKey("pem/public.pem");

    Signature signor(digest("sha1"), privateKey );

    std::string sig = signor.sign(input);
    std::cerr << toHex(sig) << std::endl;

    Signature verifier(digest("sha1"), publicKey );

    bool verified = verifier.verify(input,sig);

    EXPECT_EQ(true,verified);
}



TEST_F(CryptoNeatTest, EvelopeTest) 
{
    std::string input = "a well known secret";
    PrivateKey privateKey("pem/private.pem");
    PublicKey publicKey("pem/public.pem");

    Envelope sealer(cipher("bf_cbc") );

    std::string sealed = sealer.seal(publicKey,input);

    std::cerr << toHex(sealed) << std::endl;

    Envelope opener(cipher("bf_cbc"));
    std::string plain = opener.open(privateKey,sealed);

    EXPECT_EQ(input,plain);
}


TEST_F(CryptoNeatTest, EvelopeTest2) 
{
    std::string input = "a well known secret";
    PrivateKey privateKey("pem/private.pem");
    PublicKey publicKey("pem/public.pem");

    Envelope sealer(cipher("rc4"));

    std::string sealed = sealer.seal(publicKey,input);

    std::cerr << toHex(sealed) << std::endl;

    Envelope opener(cipher("rc4"));
    std::string plain = sealer.open(privateKey,sealed);

    EXPECT_EQ(input,plain);
}



/*
TEST_F(CryptoNeatTest, PrintIVsize) {

    std::cerr << "des-cbc " << EVP_CIPHER_iv_length(EVP_des_cbc()) << std::endl;
    std::cerr << "bf-cbc " << EVP_CIPHER_iv_length(EVP_bf_cbc()) << std::endl;
    std::cerr << "des_ede3_cbc " << EVP_CIPHER_iv_length(EVP_des_ede3_cbc()) << std::endl;
    std::cerr << "aes-256-cbc " << EVP_CIPHER_iv_length(EVP_aes_256_cbc()) << std::endl;
    std::cerr << "rc4 " << EVP_CIPHER_iv_length(EVP_rc4()) << std::endl;
}
*/

TEST_F(CryptoNeatTest, DERTest) 
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

    EXPECT_EQ(true,verified);
}

TEST_F(CryptoNeatTest, DER2Test) 
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

    EXPECT_EQ(true,verified);
}

TEST_F(CryptoNeatTest, RSAKeyGenTest) 
{
    std::string input = "a well known secret";

    PrivateKey privateKey;
    PublicKey publicKey;

    bool b = generate_rsa_pair(privateKey,publicKey);
    EXPECT_EQ(true,b);

    std::cout << "publkey:" << std::endl << toHex(publicKey.toDER()).size() << std::endl;
    std::cout << "privkey:" << std::endl << toHex(privateKey.toDER()).size() << std::endl;

    std::cout << "publkey:" << std::endl << publicKey.toPEM() << std::endl;
    std::cout << "privkey:" << std::endl << privateKey.toPEM() << std::endl;

    Signature signor(digest("sha1"), privateKey);

    std::string sig = signor.sign(input);
    std::cerr << toHex(sig) << std::endl;

    Signature verifier(digest("sha1"), publicKey );

    bool verified = verifier.verify(input,sig);

    EXPECT_EQ(true,verified);

}

TEST_F(CryptoNeatTest, RSAKeyGenTestPEM) 
{
    std::string input = "a well known secret";

    PrivateKey privateKey;
    PublicKey publicKey;

    bool b = generate_rsa_pair(privateKey,publicKey);
    EXPECT_EQ(true,b);

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

    EXPECT_EQ(true,verified);
}


TEST_F(CryptoNeatTest, dhTest) 
{
    DiffieHellman dh1;
    std::string dhp = dh1.initialize(32);

    std::cerr << dh1.generate() << std::endl;
    std::cerr << dh1.pubKey() << std::endl;

    DiffieHellman dh2(dhp);

    std::cerr << dh2.generate() << std::endl;
    std::cerr << dh2.pubKey() << std::endl;

    std::string secret1 = dh2.compute(dh1.pubKey());
    std::cerr << toHex(secret1) << std::endl;

    std::string secret2 = dh1.compute(dh2.pubKey());
    std::cerr << toHex(secret2) << std::endl;

    EXPECT_EQ(secret1,secret2);
}

TEST_F(CryptoNeatTest, dhTest2) 
{
    DiffieHellman dh1;
    dh1.load("pem/dh.pem");

    std::cerr << dh1.generate() << std::endl;
    std::cerr << dh1.pubKey() << std::endl;

    DiffieHellman dh2;
    dh2.load("pem/dh.pem");

    std::cerr << dh2.generate() << std::endl;
    std::cerr << dh2.pubKey() << std::endl;

    std::string secret1 = dh2.compute(dh1.pubKey());
    std::cerr << toHex(secret1) << std::endl;

    std::string secret2 = dh1.compute(dh2.pubKey());
    std::cerr << toHex(secret2) << std::endl;

    EXPECT_EQ(secret1,secret2);
}


TEST_F(CryptoNeatTest, pwdTest)
{
	Password pwd;

	std::string hash = pwd.hash("secretpwd");

	std::cout << hash.size() << ":" << hash << std::endl;

	bool b = pwd.verify("secretpwd", hash);

	std::cout << b << std::endl;

	b = pwd.verify("secret-pwd", hash);

	std::cout << b << std::endl;
}


TEST_F(CryptoNeatTest, uuidTest)
{
    std::string uuid = uuid::generate();
	std::cout << uuid << std::endl;
}

int main(int argc, char **argv) 
{    
	SSLUser sslUser;

    ::testing::InitGoogleTest(&argc, argv);
    int r = RUN_ALL_TESTS();

    return r;
}
