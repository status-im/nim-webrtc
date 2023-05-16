{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}

const
  MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT* = 0
  MBEDTLS_SSL_MAX_EARLY_DATA_SIZE* = 1024
  MBEDTLS_SSL_TLS1_3_TICKET_AGE_TOLERANCE* = 6000
  MBEDTLS_SSL_TLS1_3_TICKET_NONCE_LENGTH* = 32
  MBEDTLS_SSL_TLS1_3_DEFAULT_NEW_SESSION_TICKETS* = 1
{.pop.}
