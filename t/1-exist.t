use Test::More tests => 1;
BEGIN { use_ok('Digest::SHA', qw(
	hmac_sha1	hmac_sha1_base64	hmac_sha1_hex
	hmac_sha256	hmac_sha256_base64	hmac_sha256_hex
	hmac_sha384	hmac_sha384_base64	hmac_sha384_hex
	hmac_sha512	hmac_sha512_base64	hmac_sha512_hex
	sha1		sha1_base64		sha1_hex
	sha256		sha256_base64		sha256_hex
	sha384		sha384_base64		sha384_hex
	sha512		sha512_base64		sha512_hex)) };
