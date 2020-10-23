<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<tagfile>
  <compound kind="file">
    <name>base64.h</name>
    <path>/home/mike/workspace/cryptoneat/include/cryptoneat/</path>
    <filename>base64_8h.html</filename>
    <class kind="class">cryptoneat::Base64</class>
    <class kind="class">cryptoneat::Base64Url</class>
  </compound>
  <compound kind="file">
    <name>cryptoneat.h</name>
    <path>/home/mike/workspace/cryptoneat/include/cryptoneat/</path>
    <filename>cryptoneat_8h.html</filename>
    <class kind="class">cryptoneat::Digest</class>
    <class kind="class">cryptoneat::SymCrypt</class>
    <class kind="class">cryptoneat::Envelope</class>
    <class kind="class">cryptoneat::Hmac</class>
    <class kind="class">cryptoneat::PrivateKey</class>
    <class kind="class">cryptoneat::PublicKey</class>
    <class kind="class">cryptoneat::Signature</class>
    <class kind="class">cryptoneat::DiffieHellman</class>
    <class kind="class">cryptoneat::Password</class>
    <class kind="class">cryptoneat::SSLUser</class>
    <member kind="function">
      <type>std::string</type>
      <name>nonce</name>
      <anchorfile>cryptoneat_8h.html</anchorfile>
      <anchor>ada2a46551a9bac4eb814c877adeb9be5</anchor>
      <arglist>(unsigned int n)</arglist>
    </member>
    <member kind="function">
      <type>std::string</type>
      <name>toHex</name>
      <anchorfile>cryptoneat_8h.html</anchorfile>
      <anchor>aa0b1ea2eb5847ff886183c5c6df1c417</anchor>
      <arglist>(const std::string &amp;input)</arglist>
    </member>
    <member kind="function">
      <type>std::string</type>
      <name>fromHex</name>
      <anchorfile>cryptoneat_8h.html</anchorfile>
      <anchor>ac16793bd8b5023dd397d7aafb40ae4d2</anchor>
      <arglist>(const std::string &amp;hex)</arglist>
    </member>
    <member kind="function">
      <type>const EVP_MD *</type>
      <name>digest</name>
      <anchorfile>cryptoneat_8h.html</anchorfile>
      <anchor>abc8bb6624a02c5ae5e53146398bddf26</anchor>
      <arglist>(const std::string &amp;md)</arglist>
    </member>
    <member kind="function">
      <type>const EVP_CIPHER *</type>
      <name>cipher</name>
      <anchorfile>cryptoneat_8h.html</anchorfile>
      <anchor>a0b4d3b8304a875c5c548ec7b6fa07166</anchor>
      <arglist>(const std::string &amp;c)</arglist>
    </member>
    <member kind="function">
      <type>std::string</type>
      <name>md5</name>
      <anchorfile>cryptoneat_8h.html</anchorfile>
      <anchor>a5e11c6af5ddb0d220edc7c102c437903</anchor>
      <arglist>(const std::string &amp;s)</arglist>
    </member>
    <member kind="function">
      <type>std::string</type>
      <name>sha1</name>
      <anchorfile>cryptoneat_8h.html</anchorfile>
      <anchor>aac872462ccf8f52e3e2a4fb903f1a55e</anchor>
      <arglist>(const std::string &amp;s)</arglist>
    </member>
    <member kind="function">
      <type>std::string</type>
      <name>sha256</name>
      <anchorfile>cryptoneat_8h.html</anchorfile>
      <anchor>a395dfc8d32d288ad43450df79c937518</anchor>
      <arglist>(const std::string &amp;s)</arglist>
    </member>
    <member kind="function">
      <type>bool</type>
      <name>generate_rsa_pair</name>
      <anchorfile>cryptoneat_8h.html</anchorfile>
      <anchor>ab8ca51e75e5e522448fb37f92356a9e1</anchor>
      <arglist>(PrivateKey &amp;privKey, PublicKey &amp;pubKey, int bits=2048)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>uuid.h</name>
    <path>/home/mike/workspace/cryptoneat/include/cryptoneat/</path>
    <filename>uuid_8h.html</filename>
    <class kind="class">cryptoneat::uuid</class>
  </compound>
  <compound kind="class">
    <name>cryptoneat::Base64</name>
    <filename>classcryptoneat_1_1Base64.html</filename>
    <member kind="function" static="yes">
      <type>static std::string</type>
      <name>decode</name>
      <anchorfile>classcryptoneat_1_1Base64.html</anchorfile>
      <anchor>a11df6bb3724a0abe322d0310c430d192</anchor>
      <arglist>(const std::string &amp;s)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static std::string</type>
      <name>decode</name>
      <anchorfile>classcryptoneat_1_1Base64.html</anchorfile>
      <anchor>a937b5bc9e94ec8bce094665baee82bdb</anchor>
      <arglist>(const char *s)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static std::string</type>
      <name>encode</name>
      <anchorfile>classcryptoneat_1_1Base64.html</anchorfile>
      <anchor>a2f86b5eba223577dfeb588afdd6478bc</anchor>
      <arglist>(const std::string &amp;s, bool singleline=true)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static std::string</type>
      <name>encode</name>
      <anchorfile>classcryptoneat_1_1Base64.html</anchorfile>
      <anchor>a1842a57ab95e885910d4eea336a3975a</anchor>
      <arglist>(const char *s, size_t len, bool singleline=true)</arglist>
    </member>
  </compound>
  <compound kind="class">
    <name>cryptoneat::Base64Url</name>
    <filename>classcryptoneat_1_1Base64Url.html</filename>
    <member kind="function" static="yes">
      <type>static std::string</type>
      <name>decode</name>
      <anchorfile>classcryptoneat_1_1Base64Url.html</anchorfile>
      <anchor>a216a1448224361efb018d92f7e99be85</anchor>
      <arglist>(const std::string &amp;s)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static std::string</type>
      <name>decode</name>
      <anchorfile>classcryptoneat_1_1Base64Url.html</anchorfile>
      <anchor>a7b5ca8a084848022fa11f2c57d8c6598</anchor>
      <arglist>(const char *s)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static std::string</type>
      <name>encode</name>
      <anchorfile>classcryptoneat_1_1Base64Url.html</anchorfile>
      <anchor>a33bf0fefc932a9cb1f93115c184149aa</anchor>
      <arglist>(const std::string &amp;s)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static std::string</type>
      <name>encode</name>
      <anchorfile>classcryptoneat_1_1Base64Url.html</anchorfile>
      <anchor>abb224c26c9979fea2b7eb4c64b3762bd</anchor>
      <arglist>(const char *s, size_t len)</arglist>
    </member>
  </compound>
  <compound kind="class">
    <name>cryptoneat::DiffieHellman</name>
    <filename>classcryptoneat_1_1DiffieHellman.html</filename>
  </compound>
  <compound kind="class">
    <name>cryptoneat::Digest</name>
    <filename>classcryptoneat_1_1Digest.html</filename>
    <member kind="function">
      <type></type>
      <name>Digest</name>
      <anchorfile>classcryptoneat_1_1Digest.html</anchorfile>
      <anchor>a64e916267c066cd1f7f840008fc4f7ea</anchor>
      <arglist>(const EVP_MD *md)</arglist>
    </member>
    <member kind="function">
      <type>std::string</type>
      <name>digest</name>
      <anchorfile>classcryptoneat_1_1Digest.html</anchorfile>
      <anchor>abddc1cf27135efbdb3ecf63e6c7a750c</anchor>
      <arglist>(const std::string &amp;input)</arglist>
    </member>
  </compound>
  <compound kind="class">
    <name>cryptoneat::Envelope</name>
    <filename>classcryptoneat_1_1Envelope.html</filename>
    <member kind="function">
      <type></type>
      <name>Envelope</name>
      <anchorfile>classcryptoneat_1_1Envelope.html</anchorfile>
      <anchor>afcd4b00bd2573b1ef7772e0afde6dd72</anchor>
      <arglist>(const EVP_CIPHER *cipher)</arglist>
    </member>
    <member kind="function">
      <type>std::string</type>
      <name>seal</name>
      <anchorfile>classcryptoneat_1_1Envelope.html</anchorfile>
      <anchor>a7bc41a040094d5b0b062ad83006e6d97</anchor>
      <arglist>(EVP_PKEY *pubkey, const std::string &amp;msg)</arglist>
    </member>
    <member kind="function">
      <type>std::string</type>
      <name>open</name>
      <anchorfile>classcryptoneat_1_1Envelope.html</anchorfile>
      <anchor>abc216810eb270d71efe0f8c91aad7627</anchor>
      <arglist>(EVP_PKEY *privkey, const std::string &amp;msg)</arglist>
    </member>
  </compound>
  <compound kind="class">
    <name>cryptoneat::Hmac</name>
    <filename>classcryptoneat_1_1Hmac.html</filename>
    <member kind="function">
      <type></type>
      <name>Hmac</name>
      <anchorfile>classcryptoneat_1_1Hmac.html</anchorfile>
      <anchor>ad960b45fc458fd1a3eff6c03e2a59a3d</anchor>
      <arglist>(const EVP_MD *md, const std::string &amp;key)</arglist>
    </member>
    <member kind="function">
      <type>std::string</type>
      <name>hash</name>
      <anchorfile>classcryptoneat_1_1Hmac.html</anchorfile>
      <anchor>ad587d1756d1cba7aeda94fc4eb915a5b</anchor>
      <arglist>(const std::string &amp;msg)</arglist>
    </member>
  </compound>
  <compound kind="class">
    <name>cryptoneat::Password</name>
    <filename>classcryptoneat_1_1Password.html</filename>
    <member kind="function">
      <type>std::string</type>
      <name>hash</name>
      <anchorfile>classcryptoneat_1_1Password.html</anchorfile>
      <anchor>aabd9beeb2b25c4b452721b0cbd68ddad</anchor>
      <arglist>(const std::string &amp;plaintxt)</arglist>
    </member>
    <member kind="function">
      <type>std::string</type>
      <name>hash</name>
      <anchorfile>classcryptoneat_1_1Password.html</anchorfile>
      <anchor>a3b85a666b71dd263e7e9f60fda0f14a3</anchor>
      <arglist>(const std::string &amp;plaintxt, const std::string &amp;salt)</arglist>
    </member>
    <member kind="function">
      <type>bool</type>
      <name>verify</name>
      <anchorfile>classcryptoneat_1_1Password.html</anchorfile>
      <anchor>af788fe3703a9d9db7d1d94f408c3d07a</anchor>
      <arglist>(const std::string &amp;plaintxt, const std::string &amp;hash)</arglist>
    </member>
  </compound>
  <compound kind="class">
    <name>cryptoneat::PrivateKey</name>
    <filename>classcryptoneat_1_1PrivateKey.html</filename>
    <member kind="function">
      <type></type>
      <name>PrivateKey</name>
      <anchorfile>classcryptoneat_1_1PrivateKey.html</anchorfile>
      <anchor>aa40988aa565192abb42c87b730fe2dc2</anchor>
      <arglist>()</arglist>
    </member>
    <member kind="function">
      <type></type>
      <name>PrivateKey</name>
      <anchorfile>classcryptoneat_1_1PrivateKey.html</anchorfile>
      <anchor>a0d7e922139bfb1d82b724614131d7e10</anchor>
      <arglist>(const std::string &amp;file)</arglist>
    </member>
    <member kind="function">
      <type>std::string</type>
      <name>toDER</name>
      <anchorfile>classcryptoneat_1_1PrivateKey.html</anchorfile>
      <anchor>a54e8aab517ae47456b646ce8cbfd6234</anchor>
      <arglist>()</arglist>
    </member>
    <member kind="function">
      <type>std::string</type>
      <name>toPEM</name>
      <anchorfile>classcryptoneat_1_1PrivateKey.html</anchorfile>
      <anchor>ab4a420638353df77bcbcb28cda632681</anchor>
      <arglist>()</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>fromDER</name>
      <anchorfile>classcryptoneat_1_1PrivateKey.html</anchorfile>
      <anchor>a78ea69eded969123dbe8d823000edf7b</anchor>
      <arglist>(int type, const std::string &amp;s)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>fromPEM</name>
      <anchorfile>classcryptoneat_1_1PrivateKey.html</anchorfile>
      <anchor>a934f742894edb84fbeb262ed847bc50c</anchor>
      <arglist>(const std::string &amp;s)</arglist>
    </member>
  </compound>
  <compound kind="class">
    <name>cryptoneat::PublicKey</name>
    <filename>classcryptoneat_1_1PublicKey.html</filename>
    <member kind="function">
      <type></type>
      <name>PublicKey</name>
      <anchorfile>classcryptoneat_1_1PublicKey.html</anchorfile>
      <anchor>ae86baa0f21cd8a45090c90ac8c16c9ab</anchor>
      <arglist>()</arglist>
    </member>
    <member kind="function">
      <type></type>
      <name>PublicKey</name>
      <anchorfile>classcryptoneat_1_1PublicKey.html</anchorfile>
      <anchor>adb508caffdbd8dd394702b2eb8afe417</anchor>
      <arglist>(const std::string &amp;file)</arglist>
    </member>
    <member kind="function">
      <type>std::string</type>
      <name>toDER</name>
      <anchorfile>classcryptoneat_1_1PublicKey.html</anchorfile>
      <anchor>abf98467b4e31960b5b3d88eedbd74cc9</anchor>
      <arglist>()</arglist>
    </member>
    <member kind="function">
      <type>std::string</type>
      <name>toPEM</name>
      <anchorfile>classcryptoneat_1_1PublicKey.html</anchorfile>
      <anchor>aa99c01aa486b87dd8c112252efe6ba0f</anchor>
      <arglist>()</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>fromDER</name>
      <anchorfile>classcryptoneat_1_1PublicKey.html</anchorfile>
      <anchor>ab22563399ad62d7e8d4ea43828967a91</anchor>
      <arglist>(const std::string &amp;s)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>fromPEM</name>
      <anchorfile>classcryptoneat_1_1PublicKey.html</anchorfile>
      <anchor>aa68fb1a27c811ddd62a2a358a67852ca</anchor>
      <arglist>(const std::string &amp;s)</arglist>
    </member>
  </compound>
  <compound kind="class">
    <name>cryptoneat::Signature</name>
    <filename>classcryptoneat_1_1Signature.html</filename>
    <member kind="function">
      <type></type>
      <name>Signature</name>
      <anchorfile>classcryptoneat_1_1Signature.html</anchorfile>
      <anchor>ac1c0041e24554314ec83898cc99ae6ea</anchor>
      <arglist>(const EVP_MD *md, EVP_PKEY *key)</arglist>
    </member>
    <member kind="function">
      <type>std::string</type>
      <name>sign</name>
      <anchorfile>classcryptoneat_1_1Signature.html</anchorfile>
      <anchor>a3273fb3180245a96c612f4cccf18828d</anchor>
      <arglist>(const std::string &amp;msg)</arglist>
    </member>
    <member kind="function">
      <type>bool</type>
      <name>verify</name>
      <anchorfile>classcryptoneat_1_1Signature.html</anchorfile>
      <anchor>a85b8e8079e6dbe3ae85d55709dfd7158</anchor>
      <arglist>(const std::string &amp;msg, const std::string &amp;sig)</arglist>
    </member>
  </compound>
  <compound kind="class">
    <name>cryptoneat::SSLUser</name>
    <filename>classcryptoneat_1_1SSLUser.html</filename>
  </compound>
  <compound kind="class">
    <name>cryptoneat::SymCrypt</name>
    <filename>classcryptoneat_1_1SymCrypt.html</filename>
    <member kind="function">
      <type></type>
      <name>SymCrypt</name>
      <anchorfile>classcryptoneat_1_1SymCrypt.html</anchorfile>
      <anchor>ad3b858bf8ce1ecbcbba8a83a2b4f1054</anchor>
      <arglist>(const EVP_CIPHER *cipher, const std::string &amp;pwd)</arglist>
    </member>
    <member kind="function">
      <type></type>
      <name>SymCrypt</name>
      <anchorfile>classcryptoneat_1_1SymCrypt.html</anchorfile>
      <anchor>a34a26543596b889febf3bc7232a69f3d</anchor>
      <arglist>(const EVP_CIPHER *cipher, const std::string &amp;pwd, const EVP_MD *md)</arglist>
    </member>
    <member kind="function">
      <type>std::string</type>
      <name>encrypt</name>
      <anchorfile>classcryptoneat_1_1SymCrypt.html</anchorfile>
      <anchor>a98e3120d0788ef7c0e6dbf7775508dcc</anchor>
      <arglist>(const std::string &amp;input)</arglist>
    </member>
    <member kind="function">
      <type>std::string</type>
      <name>decrypt</name>
      <anchorfile>classcryptoneat_1_1SymCrypt.html</anchorfile>
      <anchor>aa17e5ac8302f0aee40a11aa39ac04dbc</anchor>
      <arglist>(const std::string &amp;raw)</arglist>
    </member>
  </compound>
  <compound kind="class">
    <name>cryptoneat::uuid</name>
    <filename>classcryptoneat_1_1uuid.html</filename>
    <member kind="function" static="yes">
      <type>static std::string</type>
      <name>generate</name>
      <anchorfile>classcryptoneat_1_1uuid.html</anchorfile>
      <anchor>a6d8633df78f3f316da2e253e64f26aeb</anchor>
      <arglist>()</arglist>
    </member>
  </compound>
  <compound kind="page">
    <name>index</name>
    <title>cryptoneat</title>
    <filename>index</filename>
  </compound>
</tagfile>
