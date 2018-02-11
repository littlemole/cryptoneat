# cryptoneat
openssl with cpp for mere mortals

# features

- hash functions: md5, sha1, sha256 ...
- symetric crypto:
    - encrypt with secret password using blowfish, r4, aes ...
- asymetric crypto with key-pair:
    - enrypt envelope
- HMAC - verify integrity via shared secret and hash
- Signing a message using key-pair: verify integrity via public/private key.
- DiffieHellman: establish a known secret for two parties
- password - generate a password hash suitable for persistence (PKCS5_PBKDF2_HMAC_SHA1)
- Base64 encode/decode and Base64Url encode/decode
- hex encode/encode

# dependencies
openssl, c++14, gtest, libuuid (libuuid on linux only)

for ubuntu do the following to install dependencies
	
	sudo apt-get install libgtest-dev uuid-dev libgtest-dev cmake
	cd /usr/src/gtest
	sudo cmake .
	sudo make
	sudo ln -s /usr/src/gtest/libgtest.a /usr/lib/libgtest.a

# install - linux

- clone from github
- cd cryproneat
- make && make test && sudo make install

this will by default install to /usr/local


# compile and link with cryptoneat

    pkg-config --libs cryptoneat
    pkg-config --cflags cryptoneat

# usage

    using namespace cryptoneat;

## md5

    std::string input = "some plaintext to be hashed";
    std::string hash = toHex(md5(input));

## sha256

    std::string input = "some plaintext to be hashed";
    std::string hash = toHex(sha256(input));

## symetric crypto with blowfish

    std::string input  = "some plaintext to be encrypted";
    std::string secret = "some secret scret key";

    SymCrypt encrypt(cipher("bf_cbc"), secret);
    std::string ciphertext = toHex(encrypt.encrypt(input));

    SymCrypt decrypt(cipher("bf_cbc"), secret);
    std::string plain = decrypt.decrypt(fromHex(ciphertext));

## asymetric encryption with rsa+blowfish

    PrivateKey privateKey("pem/private.pem");
    PublicKey publicKey("pem/public.pem");

    std::string input = "some plaintext to be encrypted";

    Envelope sealer(cipher("bf_cbc"));

    std::string sealed = sealer.seal(publicKey,input);

    Envelope opener(cipher("bf_cbc"));
    std::string plain = opener.open(privateKey,sealed);

## HMAC - produce a verifiable hash

    std::string plaintext = "some plaintext to be hashed";
    std::string secret    = "some secret secret key";

    Hmac hmac(digest("sha256"),secret);

    std::string hash = hmac.hash(plaintext);
    std::cerr << toHex(hash) << std::endl;

## Message signing - verify message has not been tampered

    std::string message = "some plaintext to be signed";

    PrivateKey privateKey("pem/private.pem");
    PublicKey publicKey("pem/public.pem");

    Signature signor(digest("sha1"), privateKey );
    std::string signature = signor.sign(message);

    Signature verifier(digest("sha1"), publicKey );
    bool verified = verifier.verify(message,signature);

## DH generate secret for two parties on the fly

    # party A loads DH params
    DiffieHellman alice;
    alice.load("pem/dh.pem");

    # pass params to party B
    DiffieHellman bob(alice.params());

    # both parties generate a key pair
    alice.generate();
    bob.generate();

    # both parties exchange public keys

    # both sides can derive the shared secret
    std::string secret1 = bob.compute(alice.pubKey());
    std::string secret2 = alice.compute(bob.pubKey());

## password hashing (to store pwd like in DB)

    Password pwd;

    #create hash for persistence from plaintext pwd
	std::string hash = pwd.hash("secretpwd");

    # persist that hash. later, when user
    # send pwd in plaintext, verify with persisted hash:

	bool verified = pwd.verify("secretpwd", hash);

## get message digest algorithm (ie md5,sha1,sha2,sha256)

    const EVP_MD* md = digest("sha256");

## get cipher algorithm (ie r4,bf_cbc, aes_128_cbc)

    const EVP_MD* ciph = cipher("rc4");

# helpers

## base64encode and bas64urlencode

    std::string plaintext = "some plaintext to be base64ed";

    std::string b64 = Base64::encode(input);
    assert(Base64::decode(b64) == plaintext);

    std::string b64url = Base64Url::encode(input);
    assert(Base64Url::decode(b64url) == plaintext);
}

## toHex

    unsigned char raw[] = { 1, 244, 27, 0, 4, 5, 0 };
    std::string s( (char*)raw, 6 );
    std::string hexed = toHex( s );
    std::string unhexed = fromHex(hexed);
    assert(unhexed == s);

## uuid

    std::string uuid = uuid::generate();


see test.cpp for more usage examples.

# implementation design
- RAII 
- easy to consume interface
- hide openssl api by default; do not pollute global namespace


# win32

get vcpkg for dependency resolution: [vcpg]

assuming vcpg installed in c: 

	cd c:\vcpkg
	.\vcpkg.exe install opensll gtest
	

clone and install lib. note yoz have to specify %PATH_TO_VCPKG_DIR% somehow.

	git clone https://littlemole/cryptoneat
	cd cryptoneat
	mkdir build
	cd build
	cmake .. -DCMAKE_TOOLCHAIN_FILE=%PATH_TO_VCPKG_DIR%\scripts\buildsystems\vcpkg.cmake

now you should have a nice vc++ solution to run. 

alternatively build from a dev prompt with:

	msbuild ALL_BUILD.vcxproj

and run the tests

	msbuild RUN_TESTS.vcxproj


## use vcpkg clone

https://github.com/littlemole/vcpkg/tree/promise

use the cryptoneat ports.


	