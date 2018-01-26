#ifndef _MOL_DEF_GUARD_DEFINE_CRYPTONEAT_CRYPT_DEF_GUARD_
#define _MOL_DEF_GUARD_DEFINE_CRYPTONEAT_CRYPT_DEF_GUARD_

#include <memory>
#include "cryptoneat/common.h"

struct CRYPTO_dynlock_value;

namespace cryptoneat {


// forward opaque types
struct EVP_MD;
struct EVP_MD_CTX;
struct EVP_CIPHER;
struct EVP_PKEY;
struct HMAC_CTX;
struct DH;
class Mutex;


// helpers 
std::string nonce (unsigned int n);

std::string toHex(const std::string& input);
std::string fromHex(const std::string& hex);

// Message Digest algorithm, ie "md5", "sha1" etc
const EVP_MD* digest(const std::string& md);

// Cipher algorithm, ie "rc4", "aes_128_cbc", "des_ede3_cbc"
const EVP_CIPHER* cipher(const std::string& c);

// Message Digest. produces a unique hash for some input. 
// example: md5
class Digest
{
public:

    Digest(const EVP_MD * md);
    
    std::string digest(const std::string& input);
    
private:

    std::shared_ptr<EVP_MD_CTX> mdctx_;
    const EVP_MD* md_;
};

// commons
std::string md5( const std::string& s);
std::string sha1( const std::string& s);
std::string sha256( const std::string& s);


// symetric crypt
// use a secret password to encrypt/decrypt some plaintext.

class SymCrypt
{
public:

    SymCrypt( const EVP_CIPHER* cipher, const std::string& pwd);
    SymCrypt( const EVP_CIPHER* cipher, const std::string& pwd, const EVP_MD* md);

    std::string encrypt(const std::string& input);    
    std::string decrypt(const std::string& raw);
    
private:

    const EVP_CIPHER* cipher_;
    const EVP_MD* md_;
    std::string pwd_;
};

// Signed Msg envelope
// seal some plaintext and open by the recipient
// uses asymetric encryption

class Envelope
{
public:
    Envelope(const EVP_CIPHER* cipher);
    
    std::string seal(EVP_PKEY* pubkey, const std::string& msg);
    std::string open(EVP_PKEY* privkey, const std::string & msg);

private:

    const EVP_CIPHER* cipher_;        
};

// HMAC - construct a hash using secret

class Hmac
{
public:
    Hmac(const EVP_MD* md, const std::string& key);
    
    std::string hash(const std::string& msg);
    
    Hmac(const Hmac& d) = delete;
    Hmac& operator=(const Hmac& rhs) = delete;

private:
    const EVP_MD* md_;
    std::string key_;
    std::shared_ptr<HMAC_CTX> ctx_;
};

// crypto private key (usually from PEM or DER)

class PrivateKey
{
public:
    PrivateKey();
    PrivateKey(const std::string& file);
    
    ~PrivateKey();
    
    operator EVP_PKEY* ()
    {
        return pkey_;
    }
    
    std::string toDER();
    std::string toPEM();

    void fromDER(int type, const std::string& s);
    void fromPEM(const std::string& s);

    PrivateKey(const PrivateKey& d) = delete;
    PrivateKey& operator=(const PrivateKey& rhs) = delete;

	// key identifiers. has to be specified to load from DER format

	enum {
		EVP_PKEY_NONE = 0,
		EVP_PKEY_RSA = 6,
		EVP_PKEY_RSA2 = 19,
		EVP_PKEY_DH = 28,
		EVP_PKEY_DSA2 = 66,
		EVP_PKEY_DSA1 = 67,
		EVP_PKEY_DSA4 = 70,
		EVP_PKEY_DSA3 = 113,
		EVP_PKEY_DSA = 116,
		EVP_PKEY_EC = 408,
		EVP_PKEY_HMAC = 855,
		EVP_PKEY_CMAC = 894,
		EVP_PKEY_DHX = 920
    };
    
private:
    EVP_PKEY* pkey_;
};

// crypto public key (usually from PEM or DER)

class PublicKey
{
public:
    PublicKey();
    PublicKey(const std::string& file);
    ~PublicKey();
    
    operator EVP_PKEY* ()
    {
        return pkey_;
    }
    
    std::string toDER();
    std::string toPEM();
    void fromDER( const std::string& s);
    void fromPEM( const std::string& s);
    
    PublicKey(const PublicKey& d) = delete;
    PublicKey& operator=(const PublicKey& rhs) = delete;    

private:
    EVP_PKEY* pkey_;    
};

bool generate_rsa_pair(PrivateKey& privKey, PublicKey& pubKey, int bits = 2048);

// Signature
// verify message integrity

class Signature
{
public:
    Signature(const EVP_MD* md,EVP_PKEY* key);

    std::string sign(const std::string& msg);    
    bool verify(const std::string& msg,const std::string& sig);

    Signature(const Signature& d) = delete;
    Signature& operator=(const Signature& rhs) = delete;

private:
    const EVP_MD* md_;
    EVP_PKEY* pkey_;
};

// DH

class DiffieHellman
{
public:
    DiffieHellman();
    DiffieHellman(const std::string& params);
    ~DiffieHellman();
    
    void load(const std::string& fp);
    void write(const std::string& fp);

    std::string initialize(size_t s);        
    bool generate();
    
    std::string compute(const std::string& pubKey );
    std::string pubKey();
    std::string params();
private:
    DH* dh_;
};

// secure password with openssl (for persistence, using salt(n=8)
class Password
{
public:

	std::string hash(const std::string& plaintxt);
	std::string hash(const std::string& plaintxt,const std::string& salt);
	bool verify(const std::string& plaintxt, const std::string& hash);
};

// initialize SSL libraries

class SSLUser
{
public:
	SSLUser( );
	~SSLUser();

	static CRYPTO_dynlock_value* dyn_create_function(const char* file, int line);
	static void dyn_lock_function(int mode, CRYPTO_dynlock_value* mutex, const char* file, int line);
	static void dyn_destroy_function(CRYPTO_dynlock_value* mutex,const char* file, int line);
	static void locking_function(int mode, int n, const char* file, int line );
	static unsigned long id_function();
	static Mutex* mutexe();
};

} // close namespaces

#endif

