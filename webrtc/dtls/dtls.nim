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
import ./utils, ../errors,
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

# Implementation of a DTLS client and a DTLS Server by using the mbedtls library.
# Multiple things here are unintuitive partly because of the callbacks
# used by mbedtls and that those callbacks cannot be async.
#
# TODO:
# - Check the viability of the add/pop first/last of the asyncqueue with the limit.
#   There might be some errors (or crashes) with some edge cases with the no wait option
# - Not critical - Check how to make a better use of MBEDTLS_ERR_SSL_WANT_WRITE
# - Not critical - May be interesting to split Dtls and DtlsConn into two files

# This limit is arbitrary, it could be interesting to make it configurable.
const PendingHandshakeLimit = 1024

# -- DtlsConn --
# A Dtls connection to a specific IP address recovered by the receiving part of
# the Udp "connection"

type
  DtlsConn* = ref object
    conn: StunConn
    laddr: TransportAddress
    raddr*: TransportAddress
    dataRecv: seq[byte]
    sendFuture: Future[void]
    closed: bool
    closeEvent: AsyncEvent

    timer: mbedtls_timing_delay_context

    ssl: mbedtls_ssl_context
    config: mbedtls_ssl_config
    cookie: mbedtls_ssl_cookie_ctx
    cache: mbedtls_ssl_cache_context

    ctr_drbg: mbedtls_ctr_drbg_context
    entropy: mbedtls_entropy_context

    localCert: seq[byte]
    remoteCert: seq[byte]

proc new(T: type DtlsConn, conn: StunConn, laddr: TransportAddress): T =
  ## Initialize a Dtls Connection
  ##
  var self = T(conn: conn, laddr: laddr)
  self.raddr = conn.raddr
  self.closed = false
  self.closeEvent = newAsyncEvent()
  return self

proc join*(self: DtlsConn) {.async: (raises: [CancelledError]).} =
  ## Wait for the Dtls Connection to be closed
  ##
  await self.closeEvent.wait()

proc dtlsHandshake(
    self: DtlsConn,
    isServer: bool
  ) {.async: (raises: [CancelledError, WebRtcError].} =
  var shouldRead = isServer
  while self.ssl.private_state != MBEDTLS_SSL_HANDSHAKE_OVER:
    if shouldRead:
      if isServer:
        case self.raddr.family
        of AddressFamily.IPv4:
          mb_ssl_set_client_transport_id(self.ssl, self.raddr.address_v4)
        of AddressFamily.IPv6:
          mb_ssl_set_client_transport_id(self.ssl, self.raddr.address_v6)
        else:
          raise newException(WebRtcError, "DTLS - Remote address isn't an IP address")
      self.dataRecv = await self.conn.read()
    self.sendFuture = nil
    let res = mb_ssl_handshake_step(self.ssl)
    if not self.sendFuture.isNil():
      await self.sendFuture
    shouldRead = false
    if res == MBEDTLS_ERR_SSL_WANT_WRITE:
      continue
    elif res == MBEDTLS_ERR_SSL_WANT_READ:
      shouldRead = true
      continue
    elif res == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED:
      mb_ssl_session_reset(self.ssl)
      shouldRead = isServer
      continue
    elif res != 0:
      raise newException(WebRtcError, "DTLS - " & $(res.mbedtls_high_level_strerr()))

proc close*(self: DtlsConn) {.async: (raises: [CancelledError]).} =
  ## Close a Dtls Connection
  ##
  if self.closed:
    debug "Try to close an already closed DtlsConn"
    return

  self.closed = true
  self.sendFuture = nil
  # TODO: proc mbedtls_ssl_close_notify => template mb_ssl_close_notify in nim-mbedtls
  let x = mbedtls_ssl_close_notify(addr self.ssl)
  if not self.sendFuture.isNil():
    await self.sendFuture
  self.closeEvent.fire()

proc write*(self: DtlsConn, msg: seq[byte]) {.async.} =
  ## Write a message using mbedtls_ssl_write
  ##
  # Mbed-TLS will wrap the message properly and call `dtlsSend` callback.
  # `dtlsSend` will write the message on the higher Stun connection.
  if self.closed:
    debug "Try to write on an already closed DtlsConn"
    return
  var buf = msg
  try:
    self.sendFuture = nil
    let write = mb_ssl_write(self.ssl, buf)
    if not self.sendFuture.isNil():
      let sendFuture = self.sendFuture
      await sendFuture
    trace "Dtls write", msgLen = msg.len(), actuallyWrote = write
  except MbedTLSError as exc:
    trace "Dtls write error", errorMsg = exc.msg
    raise exc

proc read*(self: DtlsConn): Future[seq[byte]] {.async.} =
  if self.closed:
    debug "Try to read on an already closed DtlsConn"
    return
  var res = newSeq[byte](8192)
  while true:
    self.dataRecv = await self.conn.read()
    # TODO: Find a clear way to use the template `mb_ssl_read` without
    #       messing up things with exception
    let length = mbedtls_ssl_read(addr self.ssl, cast[ptr byte](addr res[0]), res.len().uint)
    if length == MBEDTLS_ERR_SSL_WANT_READ:
      continue
    if length < 0:
      raise newException(WebRtcError, "DTLS - " & $(length.cint.mbedtls_high_level_strerr()))
    res.setLen(length)
    return res

# -- Dtls --

type
  Dtls* = ref object of RootObj
    connections: Table[TransportAddress, DtlsConn]
    transport: Stun
    laddr: TransportAddress
    started: bool
    ctr_drbg: mbedtls_ctr_drbg_context
    entropy: mbedtls_entropy_context

    serverPrivKey: mbedtls_pk_context
    serverCert: mbedtls_x509_crt
    localCert: seq[byte]

proc updateOrAdd(aq: AsyncQueue[(TransportAddress, seq[byte])],
                 raddr: TransportAddress, buf: seq[byte]) =
  for kv in aq.mitems():
    if kv[0] == raddr:
      kv[1] = buf
      return
  aq.addLastNoWait((raddr, buf))

proc new*(T: type Dtls, transport: Stun, laddr: TransportAddress): T =
  var self = T()

  self.connections = initTable[TransportAddress, DtlsConn]()
  self.conn = conn
  self.laddr = laddr
  self.started = true

  mb_ctr_drbg_init(self.ctr_drbg)
  mb_entropy_init(self.entropy)
  mb_ctr_drbg_seed(self.ctr_drbg, mbedtls_entropy_func, self.entropy, nil, 0)

  self.serverPrivKey = self.ctr_drbg.generateKey()
  self.serverCert = self.ctr_drbg.generateCertificate(self.serverPrivKey)
  self.localCert = newSeq[byte](self.serverCert.raw.len)
  copyMem(addr self.localCert[0], self.serverCert.raw.p, self.serverCert.raw.len)

proc stop*(self: Dtls) {.async.} =
  if not self.started:
    warn "Already stopped"
    return

  await allFutures(toSeq(self.connections.values()).mapIt(it.close()))
  self.started = false

# -- Remote / Local certificate getter --

proc remoteCertificate*(conn: DtlsConn): seq[byte] =
  conn.remoteCert

proc localCertificate*(conn: DtlsConn): seq[byte] =
  conn.localCert

proc localCertificate*(self: Dtls): seq[byte] =
  self.localCert

# -- MbedTLS Callbacks --

proc verify(ctx: pointer, pcert: ptr mbedtls_x509_crt,
            state: cint, pflags: ptr uint32): cint {.cdecl.} =
  # verify is the procedure called by mbedtls when receiving the remote
  # certificate. It's usually used to verify the validity of the certificate.
  # We use this procedure to store the remote certificate as it's mandatory
  # to have it for the Prologue of the Noise protocol, aswell as the localCertificate.
  var self = cast[DtlsConn](ctx)
  let cert = pcert[]

  self.remoteCert = newSeq[byte](cert.raw.len)
  copyMem(addr self.remoteCert[0], cert.raw.p, cert.raw.len)
  return 0

proc dtlsSend(ctx: pointer, buf: ptr byte, len: uint): cint {.cdecl.} =
  # dtlsSend is the procedure called by mbedtls when data needs to be sent.
  # As the StunConn's write proc is asynchronous and dtlsSend cannot be async,
  # we store the future of this write and await it after the end of the
  # function (see write or dtlsHanshake for example).
  var self = cast[DtlsConn](ctx)
  var toWrite = newSeq[byte](len)
  if len > 0:
    copyMem(addr toWrite[0], buf, len)
  trace "dtls send", len
  self.sendFuture = self.conn.write(self.raddr, toWrite)
  result = len.cint

proc dtlsRecv(ctx: pointer, buf: ptr byte, len: uint): cint {.cdecl.} =
  # dtlsRecv is the procedure called by mbedtls when data needs to be received.
  # As we cannot asynchronously await for data to be received, we use a data received
  # queue. If this queue is empty, we return `MBEDTLS_ERR_SSL_WANT_READ` for us to await
  # when the mbedtls proc resumed (see read or dtlsHandshake for example)
  let self = cast[DtlsConn](ctx)
  if self.dataRecv.len() == 0:
    return MBEDTLS_ERR_SSL_WANT_READ

  copyMem(buf, addr self.dataRecv[0], self.dataRecv.len())
  result = self.dataRecv.len().cint
  self.dataRecv = @[]
  trace "dtls receive", len, result

# -- Dtls Accept / Connect procedures --

proc cleanupDtlsConn(self: Dtls, conn: DtlsConn) {.async.} =
  # Waiting for a connection to be closed to remove it from the table
  await conn.join()
  self.connections.del(conn.raddr)

proc accept*(self: Dtls): Future[DtlsConn] {.async.} =
  ## Accept a Dtls Connection
  ##
  var res = DtlsConn.new(await self.transport.accept(), self.laddr)

  mb_ssl_init(res.ssl)
  mb_ssl_config_init(res.config)
  mb_ssl_cookie_init(res.cookie)
  mb_ssl_cache_init(res.cache)

  res.ctr_drbg = self.ctr_drbg
  res.entropy = self.entropy

  var pkey = self.serverPrivKey
  var srvcert = self.serverCert
  res.localCert = self.localCert

  mb_ssl_config_defaults(
    res.config,
    MBEDTLS_SSL_IS_SERVER,
    MBEDTLS_SSL_TRANSPORT_DATAGRAM,
    MBEDTLS_SSL_PRESET_DEFAULT
  )
  mb_ssl_conf_rng(res.config, mbedtls_ctr_drbg_random, res.ctr_drbg)
  mb_ssl_conf_read_timeout(res.config, 10000) # in milliseconds
  mb_ssl_conf_ca_chain(res.config, srvcert.next, nil)
  mb_ssl_conf_own_cert(res.config, srvcert, pkey)
  mb_ssl_cookie_setup(res.cookie, mbedtls_ctr_drbg_random, res.ctr_drbg)
  mb_ssl_conf_dtls_cookies(res.config, res.cookie)
  mb_ssl_set_timer_cb(res.ssl, res.timer)
  mb_ssl_setup(res.ssl, res.config)
  mb_ssl_session_reset(res.ssl)
  mb_ssl_set_verify(res.ssl, verify, res)
  mb_ssl_conf_authmode(res.config, MBEDTLS_SSL_VERIFY_OPTIONAL)
  mb_ssl_set_bio(res.ssl, cast[pointer](res), dtlsSend, dtlsRecv, nil)
  while true:
    try:
      self.connections[res.raddr] = res
      await res.dtlsHandshake(true)
      asyncSpawn self.removeConnection(res)
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

  mb_ssl_init(res.ssl)
  mb_ssl_config_init(res.config)

  res.ctr_drbg = self.ctr_drbg
  res.entropy = self.entropy

  var pkey = res.ctr_drbg.generateKey()
  var srvcert = res.ctr_drbg.generateCertificate(pkey)
  res.localCert = newSeq[byte](srvcert.raw.len)
  copyMem(addr res.localCert[0], srvcert.raw.p, srvcert.raw.len)

  mb_ctr_drbg_init(res.ctr_drbg)
  mb_entropy_init(res.entropy)
  mb_ctr_drbg_seed(res.ctr_drbg, mbedtls_entropy_func, res.entropy, nil, 0)

  mb_ssl_config_defaults(res.config,
                         MBEDTLS_SSL_IS_CLIENT,
                         MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                         MBEDTLS_SSL_PRESET_DEFAULT)
  mb_ssl_conf_rng(res.config, mbedtls_ctr_drbg_random, res.ctr_drbg)
  mb_ssl_conf_read_timeout(res.config, 10000) # in milliseconds
  mb_ssl_conf_ca_chain(res.config, srvcert.next, nil)
  mb_ssl_set_timer_cb(res.ssl, res.timer)
  mb_ssl_setup(res.ssl, res.config)
  mb_ssl_set_verify(res.ssl, verify, res)
  mb_ssl_conf_authmode(res.config, MBEDTLS_SSL_VERIFY_OPTIONAL)
  mb_ssl_set_bio(res.ssl, cast[pointer](res), dtlsSend, dtlsRecv, nil)

  try:
    self.connections[raddr] = res
    await res.dtlsHandshake(false)
    asyncSpawn self.removeConnection(res)
  except WebRtcError as exc:
    trace "Handshake fails", remoteAddress = raddr, error = exc.msg
    self.connections.del(raddr)
    raise exc

  return res
