# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import chronos, chronicles
import ../errors, ../stun/[stun_connection]

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
  topics = "webrtc dtls_conn"

# -- DtlsConn --
# A Dtls connection to a specific IP address recovered by the receiving part of
# the Udp "connection"

type
  MbedTLSCtx* = object
    ssl*: mbedtls_ssl_context
    config*: mbedtls_ssl_config
    cookie*: mbedtls_ssl_cookie_ctx
    cache*: mbedtls_ssl_cache_context
    timer*: mbedtls_timing_delay_context

    ctr_drbg*: mbedtls_ctr_drbg_context
    entropy*: mbedtls_entropy_context

  DtlsConn* = ref object
    conn*: StunConn # The wrapper protocol Stun Connection
    laddr: TransportAddress # Local address
    raddr*: TransportAddress # Remote address
    dataRecv: seq[byte] # data received which will be read by SCTP
    sendFuture: Future[void].Raising([CancelledError, WebRtcError])
    # This future is set by synchronous Mbed-TLS callbacks and waited, if set, once
    # the synchronous functions ends

    # Close connection management
    closed: bool
    closeEvent: AsyncEvent

    # Local and Remote certificate, needed by wrapped protocol DataChannel
    # and by libp2p
    localCert*: seq[byte]
    remoteCert*: seq[byte]

    # Mbed-TLS contexts
    ctx*: MbedTLSCtx

proc new*(T: type DtlsConn, conn: StunConn, laddr: TransportAddress): T =
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

proc dtlsHandshake*(
    self: DtlsConn,
    isServer: bool
  ) {.async: (raises: [CancelledError, WebRtcError]).} =
  var shouldRead = isServer
  try:
    while self.ctx.ssl.private_state != MBEDTLS_SSL_HANDSHAKE_OVER:
      if shouldRead:
        if isServer:
          case self.raddr.family
          of AddressFamily.IPv4:
            mb_ssl_set_client_transport_id(self.ctx.ssl, self.raddr.address_v4)
          of AddressFamily.IPv6:
            mb_ssl_set_client_transport_id(self.ctx.ssl, self.raddr.address_v6)
          else:
            raise newException(WebRtcError, "DTLS - Remote address isn't an IP address")
        let (data, _) = await self.conn.read()
        self.dataRecv = data
      self.sendFuture = nil
      let res = mb_ssl_handshake_step(self.ctx.ssl)
      if not self.sendFuture.isNil():
        await self.sendFuture
      shouldRead = false
      if res == MBEDTLS_ERR_SSL_WANT_WRITE:
        continue
      elif res == MBEDTLS_ERR_SSL_WANT_READ:
        shouldRead = true
        continue
      elif res == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED:
        mb_ssl_session_reset(self.ctx.ssl)
        shouldRead = isServer
        continue
      elif res != 0:
        raise newException(WebRtcError, "DTLS - " & $(res.mbedtls_high_level_strerr()))
  except MbedTLSError as exc:
    trace "Dtls handshake error", errorMsg = exc.msg
    raise newException(WebRtcError, "DTLS - Handshake error", exc)

proc close*(self: DtlsConn) {.async: (raises: [CancelledError, WebRtcError]).} =
  ## Close a Dtls Connection
  ##
  if self.closed:
    debug "Try to close an already closed DtlsConn"
    return

  self.closed = true
  self.sendFuture = nil
  # TODO: proc mbedtls_ssl_close_notify => template mb_ssl_close_notify in nim-mbedtls
  let x = mbedtls_ssl_close_notify(addr self.ctx.ssl)
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
    let write = mb_ssl_write(self.ctx.ssl, buf)
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
    let (data, _) = await self.conn.read()
    self.dataRecv = data
    # TODO: Find a clear way to use the template `mb_ssl_read` without
    #       messing up things with exception
    let length = mbedtls_ssl_read(addr self.ctx.ssl, cast[ptr byte](addr res[0]), res.len().uint)
    if length == MBEDTLS_ERR_SSL_WANT_READ:
      continue
    if length < 0:
      raise newException(WebRtcError, "DTLS - " & $(length.cint.mbedtls_high_level_strerr()))
    res.setLen(length)
    return res

# -- Remote / Local certificate getter --

proc remoteCertificate*(conn: DtlsConn): seq[byte] =
  conn.remoteCert

proc localCertificate*(conn: DtlsConn): seq[byte] =
  conn.localCert

# -- MbedTLS Callbacks --

proc verify*(ctx: pointer, pcert: ptr mbedtls_x509_crt,
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

proc dtlsSend*(ctx: pointer, buf: ptr byte, len: uint): cint {.cdecl.} =
  # dtlsSend is the procedure called by mbedtls when data needs to be sent.
  # As the StunConn's write proc is asynchronous and dtlsSend cannot be async,
  # we store the future of this write and await it after the end of the
  # function (see write or dtlsHanshake for example).
  var self = cast[DtlsConn](ctx)
  var toWrite = newSeq[byte](len)
  if len > 0:
    copyMem(addr toWrite[0], buf, len)
  trace "dtls send", len
  self.sendFuture = self.conn.write(toWrite)
  result = len.cint

proc dtlsRecv*(ctx: pointer, buf: ptr byte, len: uint): cint {.cdecl.} =
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
