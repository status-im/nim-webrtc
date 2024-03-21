# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import tables, bitops, posix, strutils, sequtils
import chronos, chronicles, stew/[ranges/ptr_arith, byteutils, endians2]
import usrsctp
import dtls/dtls
import binary_serialization

export chronicles

logScope:
  topics = "webrtc sctp"

# Implementation of an Sctp client and server using the usrsctp library.
# Usrsctp is usable as a single thread but it's not the intended way to
# use it. There's a lot of callbacks calling each other in a synchronous
# way where we want to be able to call asynchronous procedure, but cannot.

# TODO:
# - Replace doAssert by a proper exception management
# - Find a clean way to manage SCTP ports

proc perror(error: cstring) {.importc, cdecl, header: "<errno.h>".}
proc printf(format: cstring) {.cdecl, importc: "printf", varargs, header: "<stdio.h>", gcsafe.}

type
  SctpError* = object of CatchableError

  SctpState = enum
    Connecting
    Connected
    Closed

  SctpMessageParameters* = object
    protocolId*: uint32
    streamId*: uint16
    endOfRecord*: bool
    unordered*: bool

  SctpMessage* = ref object
    data*: seq[byte]
    info: sctp_recvv_rn
    params*: SctpMessageParameters

  SctpConn* = ref object
    conn*: DtlsConn
    state: SctpState
    connectEvent: AsyncEvent
    acceptEvent: AsyncEvent
    readLoop: Future[void]
    sctp: Sctp
    udp: DatagramTransport
    address: TransportAddress
    sctpSocket: ptr socket
    dataRecv: AsyncQueue[SctpMessage]
    sentFuture: Future[void]

  Sctp* = ref object
    dtls: Dtls
    udp: DatagramTransport
    connections: Table[TransportAddress, SctpConn]
    gotConnection: AsyncEvent
    timersHandler: Future[void]
    isServer: bool
    sockServer: ptr socket
    pendingConnections: seq[SctpConn]
    pendingConnections2: Table[SockAddr, SctpConn]
    sentAddress: TransportAddress
    sentFuture: Future[void]

  # These three objects are used for debugging/trace only
  SctpChunk = object
    chunkType: uint8
    flag: uint8
    length {.bin_value: it.data.len() + 4.}: uint16
    data {.bin_len: it.length - 4.}: seq[byte]

  SctpPacketHeader = object
    srcPort: uint16
    dstPort: uint16
    verifTag: uint32
    checksum: uint32

  SctpPacketStructure = object
    header: SctpPacketHeader
    chunks: seq[SctpChunk]

const IPPROTO_SCTP = 132

proc getSctpPacket(buffer: seq[byte]): SctpPacketStructure =
  # Only used for debugging/trace
  result.header = Binary.decode(buffer, SctpPacketHeader)
  var size = sizeof(SctpPacketStructure)
  while size < buffer.len:
    let chunk = Binary.decode(buffer[size..^1], SctpChunk)
    result.chunks.add(chunk)
    size.inc(chunk.length.int)
    while size mod 4 != 0:
      # padding; could use `size.inc(-size %% 4)` instead but it lacks clarity
      size.inc(1)

# -- Asynchronous wrapper --

template usrsctpAwait(self: SctpConn|Sctp, body: untyped): untyped =
  # usrsctpAwait is template which set `sentFuture` to nil then calls (usually)
  # an usrsctp function. If during the synchronous run of the usrsctp function
  # `sendCallback` is called, then `sentFuture` is set and waited.
  self.sentFuture = nil
  when type(body) is void:
    body
    if self.sentFuture != nil: await self.sentFuture
  else:
    let res = body
    if self.sentFuture != nil: await self.sentFuture
    res

# -- SctpConn --

proc new(T: typedesc[SctpConn], conn: DtlsConn, sctp: Sctp): T =
  T(conn: conn,
    sctp: sctp,
    state: Connecting,
    connectEvent: AsyncEvent(),
    acceptEvent: AsyncEvent(),
    dataRecv: newAsyncQueue[SctpMessage]() # TODO add some limit for backpressure?
   )

proc read*(self: SctpConn): Future[SctpMessage] {.async.} =
  # Used by DataChannel, returns SctpMessage in order to get the stream
  # and protocol ids
  return await self.dataRecv.popFirst()

proc toFlags(params: SctpMessageParameters): uint16 =
  if params.endOfRecord:
    result = result or SCTP_EOR
  if params.unordered:
    result = result or SCTP_UNORDERED

proc write*(self: SctpConn, buf: seq[byte],
    sendParams = default(SctpMessageParameters)) {.async.} =
  # Used by DataChannel, writes buf on the Dtls connection.
  trace "Write", buf
  self.sctp.sentAddress = self.address

  var cpy = buf
  let sendvErr =
    if sendParams == default(SctpMessageParameters):
      # If writes is called by DataChannel, sendParams should never
      # be the default value. This split is useful for testing.
      self.usrsctpAwait:
        self.sctpSocket.usrsctp_sendv(cast[pointer](addr cpy[0]), cpy.len().uint, nil, 0,
                                      nil, 0, SCTP_SENDV_NOINFO.cuint, 0)
    else:
      var sendInfo = sctp_sndinfo(
        snd_sid: sendParams.streamId,
        # TODO: swapBytes => htonl?
        snd_ppid: sendParams.protocolId.swapBytes(),
        snd_flags: sendParams.toFlags)
      self.usrsctpAwait:
        self.sctpSocket.usrsctp_sendv(cast[pointer](addr cpy[0]), cpy.len().uint, nil, 0,
                                      cast[pointer](addr sendInfo), sizeof(sendInfo).SockLen,
                                      SCTP_SENDV_SNDINFO.cuint, 0)
  if sendvErr < 0:
    # TODO: throw an exception
    perror("usrsctp_sendv")

proc write*(self: SctpConn, s: string) {.async.} =
  await self.write(s.toBytes())

proc close*(self: SctpConn) {.async.} =
  self.usrsctpAwait:
    self.sctpSocket.usrsctp_close()
  usrsctp_deregister_address(cast[pointer](self))

# -- usrsctp receive data callbacks --

proc handleUpcall(sock: ptr socket, data: pointer, flags: cint) {.cdecl.} =
  # Callback procedure called when we receive data after
  # connection has been established.
  let
    conn = cast[SctpConn](data)
    events = usrsctp_get_events(sock)

  trace "Handle Upcall", events
  if bitand(events, SCTP_EVENT_READ) != 0:
    var
      message = SctpMessage(
        data: newSeq[byte](4096)
      )
      address: Sockaddr_storage
      rn: sctp_recvv_rn
      addressLen = sizeof(Sockaddr_storage).SockLen
      rnLen = sizeof(sctp_recvv_rn).SockLen
      infotype: uint
      flags: int
    let n = sock.usrsctp_recvv(cast[pointer](addr message.data[0]),
                               message.data.len.uint,
                               cast[ptr SockAddr](addr address),
                               cast[ptr SockLen](addr addressLen),
                               cast[pointer](addr message.info),
                               cast[ptr SockLen](addr rnLen),
                               cast[ptr cuint](addr infotype),
                               cast[ptr cint](addr flags))
    if n < 0:
      perror("usrsctp_recvv")
      return
    elif n > 0:
      # It might be necessary to check if infotype == SCTP_RECVV_RCVINFO
      message.data.delete(n..<message.data.len())
      trace "message info from handle upcall", msginfo = message.info
      message.params = SctpMessageParameters(
          protocolId: message.info.recvv_rcvinfo.rcv_ppid.swapBytes(),
          streamId: message.info.recvv_rcvinfo.rcv_sid
        )
      if bitand(flags, MSG_NOTIFICATION) != 0:
        trace "Notification received", length = n
      else:
        try:
          conn.dataRecv.addLastNoWait(message)
        except AsyncQueueFullError:
          trace "Queue full, dropping packet"
  elif bitand(events, SCTP_EVENT_WRITE) != 0:
    trace "sctp event write in the upcall"
  else:
    warn "Handle Upcall unexpected event", events

proc handleAccept(sock: ptr socket, data: pointer, flags: cint) {.cdecl.} =
  # Callback procedure called when accepting a connection.
  trace "Handle Accept"
  var
    sconn: Sockaddr_conn
    slen: Socklen = sizeof(Sockaddr_conn).uint32
  let
    sctp = cast[Sctp](data)
    # TODO: check if sctpSocket != nil
    sctpSocket = usrsctp_accept(sctp.sockServer, cast[ptr SockAddr](addr sconn), addr slen)

  let conn = cast[SctpConn](sconn.sconn_addr)
  conn.sctpSocket = sctpSocket
  conn.state = Connected
  var nodelay: uint32 = 1
  var recvinfo: uint32 = 1
  doAssert 0 == sctpSocket.usrsctp_set_non_blocking(1)
  doAssert 0 == conn.sctpSocket.usrsctp_set_upcall(handleUpcall, cast[pointer](conn))
  doAssert 0 == conn.sctpSocket.usrsctp_setsockopt(IPPROTO_SCTP, SCTP_NODELAY,
                                 addr nodelay, sizeof(nodelay).SockLen)
  doAssert 0 == conn.sctpSocket.usrsctp_setsockopt(IPPROTO_SCTP, SCTP_RECVRCVINFO,
                                 addr recvinfo, sizeof(recvinfo).SockLen)
  conn.acceptEvent.fire()

proc handleConnect(sock: ptr socket, data: pointer, flags: cint) {.cdecl.} =
  # Callback procedure called when connecting
  trace "Handle Connect"
  let
    conn = cast[SctpConn](data)
    events = usrsctp_get_events(sock)

  trace "Handle Upcall", events, state = conn.state
  if conn.state == Connecting:
    if bitand(events, SCTP_EVENT_ERROR) != 0:
      warn "Cannot connect", address = conn.address
      conn.state = Closed
    elif bitand(events, SCTP_EVENT_WRITE) != 0:
      conn.state = Connected
      doAssert 0 == usrsctp_set_upcall(conn.sctpSocket, handleUpcall, data)
    conn.connectEvent.fire()
  else:
    warn "should be connecting", currentState = conn.state

# -- usrsctp send data callback --

proc sendCallback(ctx: pointer,
                  buffer: pointer,
                  length: uint,
                  tos: uint8,
                  set_df: uint8): cint {.cdecl.} =
  let data = usrsctp_dumppacket(buffer, length, SCTP_DUMP_OUTBOUND)
  if data != nil:
    trace "sendCallback", sctpPacket = data.getSctpPacket(), length
    usrsctp_freedumpbuffer(data)
  let sctpConn = cast[SctpConn](ctx)
  let buf = @(buffer.makeOpenArray(byte, int(length)))
  proc testSend() {.async.} =
    try:
      trace "Send To", address = sctpConn.address
      await sctpConn.conn.write(buf)
    except CatchableError as exc:
      trace "Send Failed", message = exc.msg
  sctpConn.sentFuture = testSend()

# -- Sctp --

proc timersHandler() {.async.} =
  while true:
    await sleepAsync(500.milliseconds)
    usrsctp_handle_timers(500)

proc stopServer*(self: Sctp) =
  if not self.isServer:
    trace "Try to close a client"
    return
  self.isServer = false
  let pcs = self.pendingConnections
  self.pendingConnections = @[]
  for pc in pcs:
    pc.sctpSocket.usrsctp_close()
  self.sockServer.usrsctp_close()

proc init*(self: Sctp, dtls: Dtls, laddr: TransportAddress) =
  self.gotConnection = newAsyncEvent()
  self.timersHandler = timersHandler()
  self.dtls = dtls

  usrsctp_init_nothreads(laddr.port.uint16, sendCallback, printf)
  discard usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_NONE)
  discard usrsctp_sysctl_set_sctp_ecn_enable(1)
  usrsctp_register_address(cast[pointer](self))

proc stop*(self: Sctp) {.async.} =
  # TODO: close every connections
  discard self.usrsctpAwait usrsctp_finish()
  self.udp.close()

proc readLoopProc(res: SctpConn) {.async.} =
  while true:
    let
      msg = await res.conn.read()
      data = usrsctp_dumppacket(unsafeAddr msg[0], uint(msg.len), SCTP_DUMP_INBOUND)
    if not data.isNil():
      trace "Receive data", remoteAddress = res.conn.raddr,
            sctpPacket = data.getSctpPacket()
      usrsctp_freedumpbuffer(data)
    usrsctp_conninput(cast[pointer](res), unsafeAddr msg[0], uint(msg.len), 0)

proc accept*(self: Sctp): Future[SctpConn] {.async.} =
  if not self.isServer:
    raise newException(SctpError, "Not a server")
  var res = SctpConn.new(await self.dtls.accept(), self)
  usrsctp_register_address(cast[pointer](res))
  res.readLoop = res.readLoopProc()
  res.acceptEvent.clear()
  await res.acceptEvent.wait()
  return res

proc listen*(self: Sctp, sctpPort: uint16 = 5000) =
  if self.isServer:
    trace "Try to start the server twice"
    return
  self.isServer = true
  trace "Listening", sctpPort
  doAssert 0 == usrsctp_sysctl_set_sctp_blackhole(2)
  doAssert 0 == usrsctp_sysctl_set_sctp_no_csum_on_loopback(0)
  doAssert 0 == usrsctp_sysctl_set_sctp_delayed_sack_time_default(0)
  let sock = usrsctp_socket(AF_CONN, posix.SOCK_STREAM, IPPROTO_SCTP, nil, nil, 0, nil)
  var on: int = 1
  doAssert 0 == usrsctp_set_non_blocking(sock, 1)
  var sin: Sockaddr_in
  sin.sin_family = posix.AF_INET.uint16
  sin.sin_port = htons(sctpPort)
  sin.sin_addr.s_addr = htonl(INADDR_ANY)
  doAssert 0 == usrsctp_bind(sock, cast[ptr SockAddr](addr sin), SockLen(sizeof(Sockaddr_in)))
  doAssert 0 >= usrsctp_listen(sock, 1)
  doAssert 0 == sock.usrsctp_set_upcall(handleAccept, cast[pointer](self))
  self.sockServer = sock

proc connect*(self: Sctp,
              address: TransportAddress,
              sctpPort: uint16 = 5000): Future[SctpConn] {.async.} =
  let
    sctpSocket = usrsctp_socket(AF_CONN, posix.SOCK_STREAM, IPPROTO_SCTP, nil, nil, 0, nil)
    conn = SctpConn.new(await self.dtls.connect(address), self)

  trace "Create Connection", address
  conn.sctpSocket = sctpSocket
  conn.state = Connected
  var nodelay: uint32 = 1
  var recvinfo: uint32 = 1
  doAssert 0 == usrsctp_set_non_blocking(conn.sctpSocket, 1)
  doAssert 0 == usrsctp_set_upcall(conn.sctpSocket, handleConnect, cast[pointer](conn))
  doAssert 0 == conn.sctpSocket.usrsctp_setsockopt(IPPROTO_SCTP, SCTP_NODELAY,
                                 addr nodelay, sizeof(nodelay).SockLen)
  doAssert 0 == conn.sctpSocket.usrsctp_setsockopt(IPPROTO_SCTP, SCTP_RECVRCVINFO,
                                 addr recvinfo, sizeof(recvinfo).SockLen)
  var sconn: Sockaddr_conn
  sconn.sconn_family = AF_CONN
  sconn.sconn_port = htons(sctpPort)
  sconn.sconn_addr = cast[pointer](conn)
  self.sentAddress = address
  usrsctp_register_address(cast[pointer](conn))
  conn.readLoop = conn.readLoopProc()
  let connErr = self.usrsctpAwait:
    conn.sctpSocket.usrsctp_connect(cast[ptr SockAddr](addr sconn), SockLen(sizeof(sconn)))
  doAssert 0 == connErr or errno == posix.EINPROGRESS, ($errno)
  conn.state = Connecting
  conn.connectEvent.clear()
  await conn.connectEvent.wait()
  # TODO: check connection state, if closed throw an exception
  self.connections[address] = conn
  return conn
