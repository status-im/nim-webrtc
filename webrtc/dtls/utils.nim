# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import std/times

import stew/byteutils

import mbedtls/pk
import mbedtls/rsa
import mbedtls/ctr_drbg
import mbedtls/x509_crt
import mbedtls/bignum
import mbedtls/md

import chronicles

# This sequence is used for debugging.
const mb_ssl_states* = @[
  "MBEDTLS_SSL_HELLO_REQUEST",
  "MBEDTLS_SSL_CLIENT_HELLO",
  "MBEDTLS_SSL_SERVER_HELLO",
  "MBEDTLS_SSL_SERVER_CERTIFICATE",
  "MBEDTLS_SSL_SERVER_KEY_EXCHANGE",
  "MBEDTLS_SSL_CERTIFICATE_REQUEST",
  "MBEDTLS_SSL_SERVER_HELLO_DONE",
  "MBEDTLS_SSL_CLIENT_CERTIFICATE",
  "MBEDTLS_SSL_CLIENT_KEY_EXCHANGE",
  "MBEDTLS_SSL_CERTIFICATE_VERIFY",
  "MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC",
  "MBEDTLS_SSL_CLIENT_FINISHED",
  "MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC",
  "MBEDTLS_SSL_SERVER_FINISHED",
  "MBEDTLS_SSL_FLUSH_BUFFERS",
  "MBEDTLS_SSL_HANDSHAKE_WRAPUP",
  "MBEDTLS_SSL_NEW_SESSION_TICKET",
  "MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT",
  "MBEDTLS_SSL_HELLO_RETRY_REQUEST",
  "MBEDTLS_SSL_ENCRYPTED_EXTENSIONS",
  "MBEDTLS_SSL_END_OF_EARLY_DATA",
  "MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY",
  "MBEDTLS_SSL_CLIENT_CCS_AFTER_SERVER_FINISHED",
  "MBEDTLS_SSL_CLIENT_CCS_BEFORE_2ND_CLIENT_HELLO",
  "MBEDTLS_SSL_SERVER_CCS_AFTER_SERVER_HELLO",
  "MBEDTLS_SSL_CLIENT_CCS_AFTER_CLIENT_HELLO",
  "MBEDTLS_SSL_SERVER_CCS_AFTER_HELLO_RETRY_REQUEST",
  "MBEDTLS_SSL_HANDSHAKE_OVER",
  "MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET",
  "MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET_FLUSH"
]

template generateKey*(random: mbedtls_ctr_drbg_context): mbedtls_pk_context =
  var res: mbedtls_pk_context
  mb_pk_init(res)
  discard mbedtls_pk_setup(addr res, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))
  mb_rsa_gen_key(mb_pk_rsa(res), mbedtls_ctr_drbg_random, random, 2048, 65537)
  let x = mb_pk_rsa(res)
  res

template generateCertificate*(random: mbedtls_ctr_drbg_context,
                              issuer_key: mbedtls_pk_context): mbedtls_x509_crt =
  let
    # To be honest, I have no clue what to put here as a name
    name = "C=FR,O=Status,CN=webrtc"
    time_format = initTimeFormat("YYYYMMddHHmmss")
    time_from = times.now().format(time_format)
    time_to = (times.now() + times.years(1)).format(time_format)

  var write_cert: mbedtls_x509write_cert
  var serial_mpi: mbedtls_mpi
  mb_x509write_crt_init(write_cert)
  mb_x509write_crt_set_md_alg(write_cert, MBEDTLS_MD_SHA256);
  mb_x509write_crt_set_subject_key(write_cert, issuer_key)
  mb_x509write_crt_set_issuer_key(write_cert, issuer_key)
  mb_x509write_crt_set_subject_name(write_cert, name)
  mb_x509write_crt_set_issuer_name(write_cert, name)
  mb_x509write_crt_set_validity(write_cert, time_from, time_to)
  mb_x509write_crt_set_basic_constraints(write_cert, 0, -1)
  mb_x509write_crt_set_subject_key_identifier(write_cert)
  mb_x509write_crt_set_authority_key_identifier(write_cert)
  mb_mpi_init(serial_mpi)
  let serial_hex = mb_mpi_read_string(serial_mpi, 16)
  mb_x509write_crt_set_serial(write_cert, serial_mpi)
  let buf =
    try:
      mb_x509write_crt_pem(write_cert, 2048, mbedtls_ctr_drbg_random, random)
    except MbedTLSError as e:
      raise e
  var res: mbedtls_x509_crt
  mb_x509_crt_parse(res, buf)
  res
