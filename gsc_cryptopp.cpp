#include "gsc_cryptopp.hpp"

#if COMPILE_CRYPTOPP == 1

// Allow weak algorithms (MD5 only)
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

// Crypto++ methods
#include "cryptopp/base64.h"
#include "cryptopp/hex.h"
#include "cryptopp/md5.h"
#include "cryptopp/ripemd.h"
#include "cryptopp/sha.h"
#include "cryptopp/whrlpool.h"

void gsc_cryptopp_base64_encode() {
	const char *str;
	if (!stackGetParams("s", &str) || strlen(str) == 0) {
		stackPushUndefined();
		return;
	}

	std::string output;
	CryptoPP::StringSource(str, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(output)));

	stackPushString((char*) output.c_str());
}

void gsc_cryptopp_base64_decode() {
	const char *str;
	if (!stackGetParams("s", &str) || strlen(str) == 0) {
		stackPushUndefined();
		return;
	}

	std::string output;
	CryptoPP::StringSource(str, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(output)));

	stackPushString((char*) output.c_str());
}

void gsc_cryptopp_md5() {
	const char *str;
	if (!stackGetParams("s", &str) || strlen(str) == 0) {
		stackPushUndefined();
		return;
	}

	std::string message(str);

	CryptoPP::Weak::MD5 hash;
	byte digest[CryptoPP::Weak::MD5::DIGESTSIZE];
	
	hash.CalculateDigest(digest, (byte*)str, message.length());

	CryptoPP::HexEncoder encoder(NULL, false);
	std::string output;

	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();

	stackPushString((char*) output.c_str());
}

void gsc_cryptopp_sha1() {
	const char *str;
	if (!stackGetParams("s", &str) || strlen(str) == 0) {
		stackPushUndefined();
		return;
	}

	std::string message(str);

	CryptoPP::SHA1 hash;
	byte digest[CryptoPP::SHA1::DIGESTSIZE];
	
	hash.CalculateDigest(digest, (byte*)str, message.length());

	CryptoPP::HexEncoder encoder(NULL, false);
	std::string output;

	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();

	stackPushString((char*) output.c_str());
}

void gsc_cryptopp_sha224() {
	const char *str;
	if (!stackGetParams("s", &str) || strlen(str) == 0) {
		stackPushUndefined();
		return;
	}

	std::string message(str);

	CryptoPP::SHA224 hash;
	byte digest[CryptoPP::SHA224::DIGESTSIZE];
	
	hash.CalculateDigest(digest, (byte*)str, message.length());

	CryptoPP::HexEncoder encoder(NULL, false);
	std::string output;

	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();

	stackPushString((char*) output.c_str());
}

void gsc_cryptopp_sha256() {
	const char *str;
	if (!stackGetParams("s", &str) || strlen(str) == 0) {
		stackPushUndefined();
		return;
	}

	std::string message(str);

	CryptoPP::SHA256 hash;
	byte digest[CryptoPP::SHA256::DIGESTSIZE];
	
	hash.CalculateDigest(digest, (byte*)str, message.length());

	CryptoPP::HexEncoder encoder(NULL, false);
	std::string output;

	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();

	stackPushString((char*) output.c_str());
}

void gsc_cryptopp_sha384() {
	const char *str;
	if (!stackGetParams("s", &str) || strlen(str) == 0) {
		stackPushUndefined();
		return;
	}

	std::string message(str);

	CryptoPP::SHA384 hash;
	byte digest[CryptoPP::SHA384::DIGESTSIZE];
	
	hash.CalculateDigest(digest, (byte*)str, message.length());

	CryptoPP::HexEncoder encoder(NULL, false);
	std::string output;

	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();

	stackPushString((char*) output.c_str());
}

void gsc_cryptopp_sha512() {
	const char *str;
	if (!stackGetParams("s", &str) || strlen(str) == 0) {
		stackPushUndefined();
		return;
	}

	std::string message(str);

	CryptoPP::SHA512 hash;
	byte digest[CryptoPP::SHA512::DIGESTSIZE];
	
	hash.CalculateDigest(digest, (byte*)str, message.length());

	CryptoPP::HexEncoder encoder(NULL, false);
	std::string output;

	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();

	stackPushString((char*) output.c_str());
}

void gsc_cryptopp_ripemd128() {
	const char *str;
	if (!stackGetParams("s", &str) || strlen(str) == 0) {
		stackPushUndefined();
		return;
	}

	std::string message(str);

	CryptoPP::RIPEMD128 hash;
	byte digest[CryptoPP::RIPEMD128::DIGESTSIZE];

	hash.CalculateDigest(digest, (byte*)str, message.length());
	
	CryptoPP::HexEncoder encoder(NULL, false);
	std::string output;

	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();

	stackPushString((char*) output.c_str());
}

void gsc_cryptopp_ripemd160() {
	const char *str;
	if (!stackGetParams("s", &str) || strlen(str) == 0) {
		stackPushUndefined();
		return;
	}

	std::string message(str);

	CryptoPP::RIPEMD160 hash;
	byte digest[CryptoPP::RIPEMD160::DIGESTSIZE];

	hash.CalculateDigest(digest, (byte*)str, message.length());
	
	CryptoPP::HexEncoder encoder(NULL, false);
	std::string output;

	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();

	stackPushString((char*) output.c_str());
}

void gsc_cryptopp_ripemd256() {
	const char *str;
	if (!stackGetParams("s", &str) || strlen(str) == 0) {
		stackPushUndefined();
		return;
	}

	std::string message(str);

	CryptoPP::RIPEMD256 hash;
	byte digest[CryptoPP::RIPEMD256::DIGESTSIZE];

	hash.CalculateDigest(digest, (byte*)str, message.length());
	
	CryptoPP::HexEncoder encoder(NULL, false);
	std::string output;

	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();

	stackPushString((char*) output.c_str());
}

void gsc_cryptopp_ripemd320() {
	const char *str;
	if (!stackGetParams("s", &str) || strlen(str) == 0) {
		stackPushUndefined();
		return;
	}

	std::string message(str);

	CryptoPP::RIPEMD320 hash;
	byte digest[CryptoPP::RIPEMD320::DIGESTSIZE];

	hash.CalculateDigest(digest, (byte*)str, message.length());
	
	CryptoPP::HexEncoder encoder(NULL, false);
	std::string output;

	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();

	stackPushString((char*) output.c_str());
}

void gsc_cryptopp_whirlpool() {
	const char *str;
	if (!stackGetParams("s", &str) || strlen(str) == 0) {
		stackPushUndefined();
		return;
	}

	std::string message(str);

	CryptoPP::Whirlpool hash;
	byte digest[CryptoPP::Whirlpool::DIGESTSIZE];

	hash.CalculateDigest(digest, (byte*)str, message.length());
	
	CryptoPP::HexEncoder encoder(NULL, false);
	std::string output;

	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();

	stackPushString((char*) output.c_str());
}

#endif
