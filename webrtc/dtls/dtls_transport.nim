# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import times, deques, tables, sequtils
import chronos, chronicles
import ./[dtls_utils, dtls_connection], ../errors,
       ../stun/[stun_connection, stun_transport]

import mbedtls/ssl
import mbedtls/ssl_cookie
import mbedtls/ssl_cache
import mbedtls/pk
import mbedtls/md
import mbedtls/entropy
import mbedtls/ctr_drbg
import mbedtls/rsa
import mbedtls/x509
import mbedtls/x509_crt
import mbedtls/bignum
import mbedtls/error
import mbedtls/net_sockets
import mbedtls/timing

logScope:
  topics = "webrtc dtls"

# Implementation of a DTLS client and a DTLS Server by using the Mbed-TLS library.
# Multiple things here are unintuitive partly because of the callbacks
# used by Mbed-TLS and that those callbacks cannot be async.

# -- Dtls --

type
  Dtls* = ref object of RootObj
    connections: Table[TransportAddress, DtlsConn]
    transport: Stun
    laddr*: TransportAddress
    started: bool
    ctr_drbg: mbedtls_ctr_drbg_context
    entropy: mbedtls_entropy_context

    serverPrivKey: mbedtls_pk_context
    serverCert: mbedtls_x509_crt
    localCert: seq[byte]

proc new*(T: type Dtls, transport: Stun): T =
  var self = T(
    connections: initTable[TransportAddress, DtlsConn](),
    transport: transport,
    laddr: transport.laddr,
    started: true
  )

  mb_ctr_drbg_init(self.ctr_drbg)
  mb_entropy_init(self.entropy)
  mb_ctr_drbg_seed(self.ctr_drbg, mbedtls_entropy_func, self.entropy, nil, 0)

  self.serverPrivKey = self.ctr_drbg.generateKey()
  self.serverCert = self.ctr_drbg.generateCertificate(self.serverPrivKey)
  self.localCert = newSeq[byte](self.serverCert.raw.len)
  copyMem(addr self.localCert[0], self.serverCert.raw.p, self.serverCert.raw.len)
  return self

proc stop*(self: Dtls) {.async.} =
  if not self.started:
    warn "Already stopped"
    return

  await allFutures(toSeq(self.connections.values()).mapIt(it.close()))
  self.started = false

# -- Remote / Local certificate getter --

proc localCertificate*(self: Dtls): seq[byte] =
  self.localCert

# -- Dtls Accept / Connect procedures --

proc cleanupDtlsConn(self: Dtls, conn: DtlsConn) {.async.} =
  # Waiting for a connection to be closed to remove it from the table
  await conn.join()
  self.connections.del(conn.raddr)

proc accept*(self: Dtls): Future[DtlsConn] {.async.} =
  ## Accept a Dtls Connection
  ##
  var res = DtlsConn.new(await self.transport.accept(), self.laddr)

  mb_ssl_init(res.ctx.ssl)
  mb_ssl_config_init(res.ctx.config)
  mb_ssl_cookie_init(res.ctx.cookie)
  mb_ssl_cache_init(res.ctx.cache)

  res.ctx.ctr_drbg = self.ctr_drbg
  res.ctx.entropy = self.entropy

  var pkey = self.serverPrivKey
  var srvcert = self.serverCert
  res.localCert = self.localCert

  mb_ssl_config_defaults(
    res.ctx.config,
    MBEDTLS_SSL_IS_SERVER,
    MBEDTLS_SSL_TRANSPORT_DATAGRAM,
    MBEDTLS_SSL_PRESET_DEFAULT
  )
  mb_ssl_conf_rng(res.ctx.config, mbedtls_ctr_drbg_random, res.ctx.ctr_drbg)
  mb_ssl_conf_read_timeout(res.ctx.config, 10000) # in milliseconds
  mb_ssl_conf_ca_chain(res.ctx.config, srvcert.next, nil)
  mb_ssl_conf_own_cert(res.ctx.config, srvcert, pkey)
  mb_ssl_cookie_setup(res.ctx.cookie, mbedtls_ctr_drbg_random, res.ctx.ctr_drbg)
  mb_ssl_conf_dtls_cookies(res.ctx.config, addr res.ctx.cookie)
  mb_ssl_set_timer_cb(res.ctx.ssl, res.ctx.timer)
  mb_ssl_setup(res.ctx.ssl, res.ctx.config)
  mb_ssl_session_reset(res.ctx.ssl)
  mb_ssl_set_verify(res.ctx.ssl, verify, res)
  mb_ssl_conf_authmode(res.ctx.config, MBEDTLS_SSL_VERIFY_OPTIONAL)
  mb_ssl_set_bio(res.ctx.ssl, cast[pointer](res), dtlsSend, dtlsRecv, nil)
  while true:
    try:
      self.connections[res.raddr] = res
      await res.dtlsHandshake(true)
      asyncSpawn self.cleanupDtlsConn(res)
      break
    except WebRtcError as exc:
      trace "Handshake fails, try accept another connection",
            remoteAddress = res.raddr, error = exc.msg
      self.connections.del(res.raddr)
      res.conn = await self.transport.accept()
  return res

proc connect*(self: Dtls, raddr: TransportAddress): Future[DtlsConn] {.async.} =
  ## Connect to a remote address, creating a Dtls Connection
  var res = DtlsConn.new(await self.transport.connect(raddr), self.laddr)

  mb_ssl_init(res.ctx.ssl)
  mb_ssl_config_init(res.ctx.config)

  res.ctx.ctr_drbg = self.ctr_drbg
  res.ctx.entropy = self.entropy

  var pkey = res.ctx.ctr_drbg.generateKey()
  var srvcert = res.ctx.ctr_drbg.generateCertificate(pkey)
  res.localCert = newSeq[byte](srvcert.raw.len)
  copyMem(addr res.localCert[0], srvcert.raw.p, srvcert.raw.len)

  mb_ctr_drbg_init(res.ctx.ctr_drbg)
  mb_entropy_init(res.ctx.entropy)
  mb_ctr_drbg_seed(res.ctx.ctr_drbg, mbedtls_entropy_func, res.ctx.entropy, nil, 0)

  mb_ssl_config_defaults(res.ctx.config,
                         MBEDTLS_SSL_IS_CLIENT,
                         MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                         MBEDTLS_SSL_PRESET_DEFAULT)
  mb_ssl_conf_rng(res.ctx.config, mbedtls_ctr_drbg_random, res.ctx.ctr_drbg)
  mb_ssl_conf_read_timeout(res.ctx.config, 10000) # in milliseconds
  mb_ssl_conf_ca_chain(res.ctx.config, srvcert.next, nil)
  mb_ssl_set_timer_cb(res.ctx.ssl, res.ctx.timer)
  mb_ssl_setup(res.ctx.ssl, res.ctx.config)
  mb_ssl_set_verify(res.ctx.ssl, verify, res)
  mb_ssl_conf_authmode(res.ctx.config, MBEDTLS_SSL_VERIFY_OPTIONAL)
  mb_ssl_set_bio(res.ctx.ssl, cast[pointer](res), dtlsSend, dtlsRecv, nil)

  try:
    self.connections[raddr] = res
    await res.dtlsHandshake(false)
    asyncSpawn self.cleanupDtlsConn(res)
  except WebRtcError as exc:
    trace "Handshake fails", remoteAddress = raddr, error = exc.msg
    self.connections.del(raddr)
    raise exc

  return res
