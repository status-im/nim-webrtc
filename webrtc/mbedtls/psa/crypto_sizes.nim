#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
# Generated @ 2023-05-12T13:12:44+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/psa/crypto_sizes.h

# const 'PSA_MAC_MAX_SIZE' has unsupported value 'PSA_HASH_MAX_SIZE'
# const 'PSA_VENDOR_ECDSA_SIGNATURE_MAX_SIZE' has unsupported value 'PSA_ECDSA_SIGNATURE_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)'
# const 'PSA_SIGNATURE_MAX_SIZE' has unsupported value '(PSA_BITS_TO_BYTES(PSA_VENDOR_RSA_MAX_KEY_BITS) > PSA_VENDOR_ECDSA_SIGNATURE_MAX_SIZE ? PSA_BITS_TO_BYTES(PSA_VENDOR_RSA_MAX_KEY_BITS) : PSA_VENDOR_ECDSA_SIGNATURE_MAX_SIZE)'
# const 'PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE' has unsupported value '(PSA_BITS_TO_BYTES(PSA_VENDOR_RSA_MAX_KEY_BITS))'
# const 'PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE' has unsupported value '(PSA_BITS_TO_BYTES(PSA_VENDOR_RSA_MAX_KEY_BITS))'
# const 'PSA_EXPORT_KEY_PAIR_MAX_SIZE' has unsupported value '(PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(PSA_VENDOR_RSA_MAX_KEY_BITS) > PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS) ? PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(PSA_VENDOR_RSA_MAX_KEY_BITS) : PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS))'
# const 'PSA_EXPORT_PUBLIC_KEY_MAX_SIZE' has unsupported value '(PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_RSA_MAX_KEY_BITS) > PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS) ? PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_RSA_MAX_KEY_BITS) : PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS))'
# const 'PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE' has unsupported value '(PSA_BITS_TO_BYTES(PSA_VENDOR_ECC_MAX_CURVE_BITS))'
{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.pragma: impcrypto_sizesHdr,
  header: "/home/lchenut/minnim/webrtc/mbedtls/include/psa/crypto_sizes.h".}
{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  PSA_HASH_MAX_SIZE* = 64
  PSA_HMAC_MAX_HASH_BLOCK_SIZE* = 128
  PSA_AEAD_TAG_MAX_SIZE* = 16
  PSA_VENDOR_RSA_MAX_KEY_BITS* = 4096
  PSA_VENDOR_ECC_MAX_CURVE_BITS* = 521
  PSA_TLS12_PSK_TO_MS_PSK_MAX_SIZE* = 128
  PSA_TLS12_ECJPAKE_TO_PMS_INPUT_SIZE* = 65
  PSA_TLS12_ECJPAKE_TO_PMS_DATA_SIZE* = 32
  PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE* = 16
  PSA_AEAD_NONCE_MAX_SIZE* = 13
  PSA_AEAD_FINISH_OUTPUT_MAX_SIZE* = (PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE)
  PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE* = (PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE)
  PSA_CIPHER_IV_MAX_SIZE* = 16
  PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE* = (PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE)
{.pop.}
