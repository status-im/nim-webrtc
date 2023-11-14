# Nim-WebRTC
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import times, deques, tables
import chronos, chronicles
import ./utils, ../stun/stun_connection

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

# TODO: Check the viability of the add/pop first/last of the asyncqueue with the limit.
# There might be some errors (or crashes) in weird cases with the no wait option

const
  PendingHandshakeLimit = 1024

type
  DtlsError* = object of CatchableError
  DtlsConn* = ref object
    conn: StunConn
    laddr: TransportAddress
    raddr*: TransportAddress
    dataRecv: AsyncQueue[seq[byte]]
    sendFuture: Future[void]

    timer: mbedtls_timing_delay_context

    ssl: mbedtls_ssl_context
    config: mbedtls_ssl_config
    cookie: mbedtls_ssl_cookie_ctx
    cache: mbedtls_ssl_cache_context

    ctr_drbg: mbedtls_ctr_drbg_context
    entropy: mbedtls_entropy_context

    localCert: seq[byte]
    remoteCert: seq[byte]

proc dtlsSend*(ctx: pointer, buf: ptr byte, len: uint): cint {.cdecl.} =
  trace "dtls send", len
  var self = cast[DtlsConn](ctx)
  var toWrite = newSeq[byte](len)
  if len > 0:
    copyMem(addr toWrite[0], buf, len)
  self.sendFuture = self.conn.write(self.raddr, toWrite)
  result = len.cint

proc dtlsRecv*(ctx: pointer, buf: ptr byte, len: uint): cint {.cdecl.} =
  let self = cast[DtlsConn](ctx)
  if self.dataRecv.len() == 0:
    return MBEDTLS_ERR_SSL_WANT_READ

  var dataRecv = self.dataRecv.popFirstNoWait()
  copyMem(buf, addr dataRecv[0], dataRecv.len())
  result = dataRecv.len().cint
  trace "dtls receive", len, result

proc init*(self: DtlsConn, conn: StunConn, laddr: TransportAddress) {.async.} =
  self.conn = conn
  self.laddr = laddr
  self.dataRecv = newAsyncQueue[seq[byte]]()

proc write*(self: DtlsConn, msg: seq[byte]) {.async.} =
  var buf = msg
  discard mbedtls_ssl_write(addr self.ssl, cast[ptr byte](addr buf[0]), buf.len().uint)

proc read*(self: DtlsConn): Future[seq[byte]] {.async.} =
  var res = newSeq[byte](8192)
  while true:
    let tmp = await self.dataRecv.popFirst()
    self.dataRecv.addFirstNoWait(tmp)
    let length = mbedtls_ssl_read(addr self.ssl, cast[ptr byte](addr res[0]), res.len().uint)
    if length == MBEDTLS_ERR_SSL_WANT_READ:
      continue
    res.setLen(length)
    return res

proc close*(self: DtlsConn) {.async.} =
  discard

type
  Dtls* = ref object of RootObj
    connections: Table[TransportAddress, DtlsConn]
    pendingHandshakes: AsyncQueue[(TransportAddress, seq[byte])]
    conn: StunConn
    laddr: TransportAddress
    started: bool
    readLoop: Future[void]
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

proc start*(self: Dtls, conn: StunConn, laddr: TransportAddress) =
  if self.started:
    warn "Already started"
    return

  proc readLoop() {.async.} =
    while true:
      let (buf, raddr) = await self.conn.read()
      if self.connections.hasKey(raddr):
        self.connections[raddr].dataRecv.addLastNoWait(buf)
      else:
        self.pendingHandshakes.updateOrAdd(raddr, buf)

  self.connections = initTable[TransportAddress, DtlsConn]()
  self.pendingHandshakes = newAsyncQueue[(TransportAddress, seq[byte])](PendingHandshakeLimit)
  self.conn = conn
  self.laddr = laddr
  self.started = true
  self.readLoop = readLoop()

  mb_ctr_drbg_init(self.ctr_drbg)
  mb_entropy_init(self.entropy)
  mb_ctr_drbg_seed(self.ctr_drbg, mbedtls_entropy_func, self.entropy, nil, 0)

  self.serverPrivKey = self.ctr_drbg.generateKey()
  self.serverCert = self.ctr_drbg.generateCertificate(self.serverPrivKey)
  self.localCert = newSeq[byte](self.serverCert.raw.len)
  copyMem(addr self.localCert[0], self.serverCert.raw.p, self.serverCert.raw.len)

proc stop*(self: Dtls) =
  if not self.started:
    warn "Already stopped"
    return

  self.readLoop.cancel()
  self.started = false

proc serverHandshake(self: DtlsConn) {.async.} =
  var shouldRead = true
  while self.ssl.private_state != MBEDTLS_SSL_HANDSHAKE_OVER:
    if shouldRead:
      case self.raddr.family
      of AddressFamily.IPv4:
        mb_ssl_set_client_transport_id(self.ssl, self.raddr.address_v4)
      of AddressFamily.IPv6:
        mb_ssl_set_client_transport_id(self.ssl, self.raddr.address_v6)
      else:
        raise newException(DtlsError, "Remote address isn't an IP address")
      let tmp = await self.dataRecv.popFirst()
      self.dataRecv.addFirstNoWait(tmp)
    self.sendFuture = nil
    let res = mb_ssl_handshake_step(self.ssl)
    if not self.sendFuture.isNil(): await self.sendFuture
    shouldRead = false
    if res == MBEDTLS_ERR_SSL_WANT_WRITE:
      continue
    elif res == MBEDTLS_ERR_SSL_WANT_READ or
       self.ssl.private_state == MBEDTLS_SSL_CLIENT_KEY_EXCHANGE:
      shouldRead = true
      continue
    elif res == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED:
      mb_ssl_session_reset(self.ssl)
      shouldRead = true
      continue
    elif res != 0:
      raise newException(DtlsError, $(res.mbedtls_high_level_strerr()))
  # var remoteCertPtr = mbedtls_ssl_get_peer_cert(addr self.ssl)
  # let remoteCert = remoteCertPtr[]
  # self.remoteCert = newSeq[byte](remoteCert.raw.len)
  # copyMem(addr self.remoteCert[0], remoteCert.raw.p, remoteCert.raw.len)

proc remoteCertificate*(conn: DtlsConn): seq[byte] =
  conn.remoteCert

proc localCertificate*(self: Dtls): seq[byte] =
  self.localCert

proc verify(ctx: pointer, pcert: ptr mbedtls_x509_crt,
            state: cint, pflags: ptr uint32): cint {.cdecl.} =
  var self = cast[DtlsConn](ctx)
  let cert = pcert[]

  self.remoteCert = newSeq[byte](cert.raw.len)
  copyMem(addr self.remoteCert[0], cert.raw.p, cert.raw.len)
  return 0

proc accept*(self: Dtls): Future[DtlsConn] {.async.} =
  var
    selfvar = self
    res = DtlsConn()

  await res.init(self.conn, self.laddr)
  mb_ssl_init(res.ssl)
  mb_ssl_config_init(res.config)
  mb_ssl_cookie_init(res.cookie)
  mb_ssl_cache_init(res.cache)

  res.ctr_drbg = self.ctr_drbg
  res.entropy = self.entropy

  var pkey = self.serverPrivKey
  var srvcert = self.serverCert
  res.localCert = newSeq[byte](srvcert.raw.len)
  res.localCert = self.localCert

  mb_ssl_config_defaults(res.config,
                         MBEDTLS_SSL_IS_SERVER,
                         MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                         MBEDTLS_SSL_PRESET_DEFAULT)
  mb_ssl_conf_rng(res.config, mbedtls_ctr_drbg_random, res.ctr_drbg)
  mb_ssl_conf_read_timeout(res.config, 10000) # in milliseconds
  mb_ssl_conf_ca_chain(res.config, srvcert.next, nil)
  mb_ssl_conf_own_cert(res.config, srvcert, pkey)
  mb_ssl_cookie_setup(res.cookie, mbedtls_ctr_drbg_random, res.ctr_drbg)
  mb_ssl_conf_dtls_cookies(res.config, res.cookie)
  mb_ssl_set_timer_cb(res.ssl, res.timer)
  mb_ssl_setup(res.ssl, res.config)
  mb_ssl_session_reset(res.ssl)
  mbedtls_ssl_set_verify(addr res.ssl, verify, cast[pointer](res))
  mbedtls_ssl_conf_authmode(addr res.config, MBEDTLS_SSL_VERIFY_REQUIRED) # TODO: create template
  mb_ssl_set_bio(res.ssl, cast[pointer](res),
                 dtlsSend, dtlsRecv, nil)
  while true:
    let (raddr, buf) = await self.pendingHandshakes.popFirst()
    try:
      res.raddr = raddr
      res.dataRecv.addLastNoWait(buf)
      self.connections[raddr] = res
      await res.serverHandshake()
      break
    except CatchableError as exc:
      trace "Handshake fail", remoteAddress = raddr, error = exc.msg
      self.connections.del(raddr)
      continue
  return res

proc dial*(self: Dtls, raddr: TransportAddress): Future[DtlsConn] {.async.} =
  discard

#import ../udp_connection
#import stew/byteutils
#proc main() {.async.} =
#  let laddr = initTAddress("127.0.0.1:4433")
#  let udp = UdpConn()
#  await udp.init(laddr)
#  let stun = StunConn()
#  await stun.init(udp, laddr)
#  let dtls = Dtls()
#  dtls.start(stun, laddr)
#  let x = await dtls.accept()
#  echo "Recv: <", string.fromBytes(await x.read()), ">"
#
#waitFor(main())
