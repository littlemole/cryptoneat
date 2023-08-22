#ifndef _MOL_DEF_GUARD_DEFINE_CRYPTONEAT_CRYPT_DEF_GUARD_
#define _MOL_DEF_GUARD_DEFINE_CRYPTONEAT_CRYPT_DEF_GUARD_

//! \file cryptoneat.h

#include <memory>
#include "cryptoneat/common.h"

struct CRYPTO_dynlock_value;

namespace cryptoneat {


// forward opaque types
struct EVP_MD;
struct EVP_MD_CTX;
struct EVP_MAC_CTX;
struct EVP_CIPHER;
struct EVP_PKEY;
class Mutex;


//! create unique random none of given size 
std::string nonce (unsigned int n);
//! hex encode a binary string
std::string toHex(const std::string& input);
//! hex decodde a binary string
std::string fromHex(const std::string& hex);

//! Message Digest algorithm, ie "md5", "sha1" etc
const EVP_MD* digest(const std::string& md);
const EVP_MD* digest(const std::string& md, const std::string& provider);


//! Cipher algorithm, ie "rc4", "aes_128_cbc", "des_ede3_cbc"
const EVP_CIPHER* cipher(const std::string& c);

//! Message Digest. produces a unique hash for some input. 
//!
//! example: md5
class Digest
{
public:

    //! construct a Digest object from a given Algorithm
    Digest(const EVP_MD * md);
    
    //! compute the message digest for given input
    std::string digest(const std::string& input);
    
private:

    std::shared_ptr<EVP_MD_CTX> mdctx_;
    const EVP_MD* md_;
};

//! simple md5 digest helper 
std::string md5( const std::string& s);
//! sha1 digest helper
std::string sha1( const std::string& s);
//! sha256 digest helper
std::string sha256( const std::string& s);


//! symetric crypt
//!
//! use a secret password to encrypt/decrypt some plaintext.

class SymCrypt
{
public:

    //! construct a SymCrypt object using given cipher and secret password. uses sha256
    SymCrypt( const EVP_CIPHER* cipher, const std::string& pwd);
    //! construct a SymCrypt object using given cipher, secret password using the specified message digest
    SymCrypt( const EVP_CIPHER* cipher, const std::string& pwd, const EVP_MD* md);

    //! enrypt given input, return cipher text
    std::string encrypt(const std::string& input);    
    //! decrypt cipher text
    std::string decrypt(const std::string& raw);
    
private:

    const EVP_CIPHER* cipher_;
    const EVP_MD* md_;
    std::string pwd_;
};

//! Signed Msg envelope
//!
//! seal some plaintext and open by the recipient
//! uses asymetric encryption

class Envelope
{
public:
    //! construct a Envelope object using specified cipher
    Envelope(const EVP_CIPHER* cipher);
    
    //! digitally encrypt given msg with public key
    std::string seal(EVP_PKEY* pubkey, const std::string& msg);
    //! digitally decrypt msg using private key
    std::string open(EVP_PKEY* privkey, const std::string & msg);

private:

    const EVP_CIPHER* cipher_;        
};

//! HMAC 
//! 
//! construct a hash using shared secret

class Hmac
{
public:
    //! construct HMAC using gven message digest and shared secret
    Hmac(const EVP_MD* md, const std::string& key);
    
    //! compute HMAC hash for message
    std::string hash(const std::string& msg);
    
    Hmac(const Hmac& d) = delete;
    Hmac& operator=(const Hmac& rhs) = delete;

private:
    const EVP_MD* md_;
    std::string key_;
    std::shared_ptr<EVP_MAC_CTX> ctx_;
};

//! crypto private key (usually from PEM or DER)

class PrivateKey
{
public:

    //! construct uninitialized PrivateKey object
    PrivateKey();
    //! construct initialized PrivateKey from PEM file
    PrivateKey(const std::string& file);
    
    ~PrivateKey();
    
    //! \private
    operator EVP_PKEY* ()
    {
        return pkey_;
    }
    
    //! return key in DER binary format
    std::string toDER();
    //! return key in PEM text format
    std::string toPEM();

    //! initialize key from DER format for specific type
    void fromDER(int type, const std::string& s);
    //! initialize key from PEM format
    void fromPEM(const std::string& s);

    PrivateKey(const PrivateKey& d) = delete;
    PrivateKey& operator=(const PrivateKey& rhs) = delete;

	//! key identifiers. has to be specified to load from DER format

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

//! crypto public key (usually from PEM or DER)

class PublicKey
{
public:

    //! construct uninitialized PublicKey object
    PublicKey();
    //! construct PublicKey from PEM file
    PublicKey(const std::string& file);
    ~PublicKey();
    
    //! \private
    operator EVP_PKEY* ()
    {
        return pkey_;
    }
    
    //! return key to DER binary format
    std::string toDER();
    //! return key in PEM text format
    std::string toPEM();
    //! initialize key from binary DER format
    void fromDER( const std::string& s);
    //! initialize key from text PEM format
    void fromPEM( const std::string& s);
    
    PublicKey(const PublicKey& d) = delete;
    PublicKey& operator=(const PublicKey& rhs) = delete;    

private:
    EVP_PKEY* pkey_;    
};

//! generate a RSA key pair with given key pair
//! note PrivateKey and PublicKey are output parameters
bool generate_rsa_pair(PrivateKey& privKey, PublicKey& pubKey, int bits = 2048);

//! Signature
//!
//! verify message integrity

class Signature
{
public:
    //! construct Signature object for given msg digest and public/private key
    Signature(const EVP_MD* md,EVP_PKEY* key);

    //! sign the given message and return signature
    std::string sign(const std::string& msg);    
    //! verify given message using given signature
    bool verify(const std::string& msg,const std::string& sig);

    Signature(const Signature& d) = delete;
    Signature& operator=(const Signature& rhs) = delete;

private:
    const EVP_MD* md_;
    EVP_PKEY* pkey_;
};

//! secure password with openssl (for persistence, using salt(n=8)
class Password
{
public:

    //! hash a password, return hash suitable to store in persistent medium
	std::string hash(const std::string& plaintxt);
    //! (re-)hash password using specified salt
	std::string hash(const std::string& plaintxt,const std::string& salt);
    //! verify plaintext password matches stored hash (hash assumed to be salted)
	bool verify(const std::string& plaintxt, const std::string& hash);
};

//! initialize SSL libraries

class SSLUser
{
public:
	SSLUser( );
	~SSLUser();

    //! \private
	static CRYPTO_dynlock_value* dyn_create_function(const char* file, int line);
    //! \private
	static void dyn_lock_function(int mode, CRYPTO_dynlock_value* mutex, const char* file, int line);
    //! \private
	static void dyn_destroy_function(CRYPTO_dynlock_value* mutex,const char* file, int line);
    //! \private
	static void locking_function(int mode, int n, const char* file, int line );
    //! \private
	static unsigned long id_function();
    //! \private
	static Mutex* mutexe();
};

} // close namespaces

#endif

