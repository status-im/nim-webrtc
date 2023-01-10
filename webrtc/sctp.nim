# Nim-WebRTC
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import tables, bitops, posix, strutils, sequtils
import chronos, chronicles, stew/ranges/ptr_arith
import usrsctp

export chronicles

logScope:
  topics = "webrtc sctp"

type
  SctpError* = object of CatchableError

  SctpState = enum
    Connecting
    Connected
    Closed

  SctpConnection* = ref object
    state: SctpState
    connectEvent: AsyncEvent
    sctp: Sctp
    udp: DatagramTransport
    address: TransportAddress
    sctpSocket: ptr socket
    recvEvent: AsyncEvent
    dataRecv: seq[byte]

  Sctp* = ref object
    udp: DatagramTransport
    connections: Table[TransportAddress, SctpConnection]
    gotConnection: AsyncEvent
    timersHandler: Future[void]
    isServer: bool
    sockServer: ptr socket
    pendingConnections: seq[SctpConnection]
    sentFuture: Future[void]
    sentConnection: SctpConnection
    sentAddress: TransportAddress

const
  IPPROTO_SCTP = 132

proc newSctpError(msg: string): ref SctpError =
  result = newException(SctpError, msg)

template usrsctpAwait(sctp: Sctp, body: untyped): untyped =
  sctp.sentFuture = nil
  when type(body) is void:
    body
    if sctp.sentFuture != nil: await sctp.sentFuture
  else:
    let res = body
    if sctp.sentFuture != nil: await sctp.sentFuture
    res

proc perror(error: cstring) {.importc, cdecl, header: "<errno.h>".}
proc printf(format: cstring) {.cdecl, importc: "printf", varargs, header: "<stdio.h>", gcsafe.}

proc packetPretty(packet: cstring): string =
  let data = $packet
  let ctn = data[23..^16]
  result = data[1..14]
  if ctn.len > 30:
    result = result & ctn[0..14] & " ... " & ctn[^14..^1]
  else:
    result = result & ctn

proc new(T: typedesc[SctpConnection],
         sctp: Sctp,
         udp: DatagramTransport,
         address: TransportAddress,
         sctpSocket: ptr socket): T =
  T(sctp: sctp,
    state: Connecting,
    udp: udp,
    address: address,
    sctpSocket: sctpSocket,
    connectEvent: AsyncEvent(),
    recvEvent: AsyncEvent())

proc read*(self: SctpConnection): Future[seq[byte]] {.async.} =
  trace "Read"
  if self.dataRecv.len == 0:
    self.recvEvent.clear()
    await self.recvEvent.wait()
  let res = self.dataRecv
  self.dataRecv = @[]
  return res

proc write*(self: SctpConnection, buf: seq[byte]) {.async.} =
  trace "Write", buf
  self.sctp.sentConnection = self
  self.sctp.sentAddress = self.address
  let sendvErr = self.sctp.usrsctpAwait:
    self.sctpSocket.usrsctp_sendv(unsafeAddr buf[0], buf.len.uint,
                                  nil, 0, nil, 0,
                                  SCTP_SENDV_NOINFO, 0)

proc close*(self: SctpConnection) {.async.} =
  self.sctp.usrsctpAwait: self.sctpSocket.usrsctp_close()

proc handleUpcall(sock: ptr socket, data: pointer, flags: cint) {.cdecl.} =
  let
    events = usrsctp_get_events(sock)
    conn = cast[SctpConnection](data)
  trace "Handle Upcall", events
  if conn.state == Connecting:
    if bitand(events, SCTP_EVENT_ERROR) != 0:
      warn "Cannot connect", address = conn.address
      conn.state = Closed
    elif bitand(events, SCTP_EVENT_WRITE) != 0:
      conn.state = Connected
    conn.connectEvent.fire()
  elif bitand(events, SCTP_EVENT_READ) != 0:
    var
      buffer = newSeq[byte](4096)
      address: Sockaddr_storage
      rn: sctp_recvv_rn
      addressLen = sizeof(Sockaddr_storage).SockLen
      rnLen = sizeof(sctp_recvv_rn).SockLen
      infotype: uint
      flags: int
    let n = sock.usrsctp_recvv(cast[pointer](addr buffer[0]), buffer.len.uint,
                               cast[ptr SockAddr](addr address),
                               cast[ptr SockLen](addr addressLen),
                               cast[pointer](addr rn),
                               cast[ptr SockLen](addr rnLen),
                               cast[ptr cuint](addr infotype),
                               cast[ptr cint](addr flags))
    if n < 0:
      perror("usrsctp_recvv")
      return
    elif n > 0:
      if bitand(flags, MSG_NOTIFICATION) != 0:
        trace "Notification received", length = n
      else:
        conn.dataRecv = conn.dataRecv.concat(buffer[0..n])
        conn.recvEvent.fire()
  else:
    warn "Handle Upcall unexpected event", events

proc handleAccept(sock: ptr socket, data: pointer, flags: cint) {.cdecl.} =
  trace "Handle Accept"
  let
    sctp = cast[Sctp](data)
    sctpSocket = usrsctp_accept(sctp.sockServer, nil, nil)

  doAssert 0 == sctpSocket.usrsctp_set_non_blocking(1)
  let conn = SctpConnection.new(sctp, sctp.udp, sctp.sentAddress, sctpSocket)
  sctp.connections[sctp.sentAddress] = conn
  sctp.pendingConnections.add(conn)
  conn.state = Connected
  doAssert 0 == sctpSocket.usrsctp_set_upcall(handleUpcall, cast[pointer](conn))
  sctp.gotConnection.fire()

proc getOrCreateConnection(self: Sctp,
                           udp: DatagramTransport,
                           address: TransportAddress,
                           sctpPort: uint16 = 5000): Future[SctpConnection] {.async.} =
                           #TODO remove the = 5000
  if self.connections.hasKey(address):
    return self.connections[address]
  trace "Create Connection", address
  let
    sctpSocket = usrsctp_socket(AF_CONN, posix.SOCK_STREAM, IPPROTO_SCTP, nil, nil, 0, nil)
    conn = SctpConnection.new(self, udp, address, sctpSocket)
  var on: int = 1
  doAssert 0 == conn.sctpSocket.usrsctp_setsockopt(IPPROTO_SCTP,
                                                   SCTP_RECVRCVINFO,
                                                   addr on,
                                                   sizeof(on).SockLen)
  doAssert 0 == usrsctp_set_non_blocking(conn.sctpSocket, 1)
  doAssert 0 == usrsctp_set_upcall(conn.sctpSocket, handleUpcall, cast[pointer](conn))
  var sconn: Sockaddr_conn
  sconn.sconn_family = AF_CONN
  sconn.sconn_port = htons(sctpPort)
  sconn.sconn_addr = cast[pointer](self)
  self.sentConnection = conn
  self.sentAddress = address
  let connErr = self.usrsctpAwait:
    conn.sctpSocket.usrsctp_connect(cast[ptr SockAddr](addr sconn), SockLen(sizeof(sconn)))
  doAssert 0 == connErr or errno == EINPROGRESS, ($errno) # TODO raise
  self.connections[address] = conn
  return conn

proc sendCallback(address: pointer,
                  buffer: pointer,
                  length: uint,
                  tos: uint8,
                  set_df: uint8): cint {.cdecl.} =
  let data = usrsctp_dumppacket(buffer, length, SCTP_DUMP_OUTBOUND)
  if data != nil:
    trace "sendCallback", data = data.packetPretty(), length
    usrsctp_freedumpbuffer(data)
  let sctp = cast[Sctp](address)
  proc testSend() {.async.} =
    try:
      let
        buf = @(buffer.makeOpenArray(byte, int(length)))
        address = sctp.sentAddress
      trace "Send To", address
      await sendTo(sctp.udp, address, buf, int(length))
    except CatchableError as exc:
      trace "Send Failed", message = exc.msg
  sctp.sentFuture = testSend()

proc timersHandler() {.async.} =
  while true:
    await sleepAsync(500.milliseconds)
    usrsctp_handle_timers(500)

proc startServer*(self: Sctp, sctpPort: uint16 = 5000) =
  if self.isServer:
    trace "Try to start the server twice"
    return
  self.isServer = true
  doAssert 0 == usrsctp_sysctl_set_sctp_blackhole(2)
  doAssert 0 == usrsctp_sysctl_set_sctp_no_csum_on_loopback(0)
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

proc closeServer(self: Sctp) =
  if not self.isServer:
    trace "Try to close a client"
    return
  self.isServer = false
  let pcs = self.pendingConnections
  self.pendingConnections = @[]
  for pc in pcs:
    pc.sctpSocket.usrsctp_close()
  self.sockServer.usrsctp_close()

proc new*(T: typedesc[Sctp], port: uint16 = 9899): T =
  logScope: topics = "webrtc sctp"
  let sctp = T(gotConnection: newAsyncEvent())
  proc onReceive(udp: DatagramTransport, address: TransportAddress) {.async, gcsafe.} =
    let
      msg = udp.getMessage()
      data = usrsctp_dumppacket(unsafeAddr msg[0], uint(msg.len), SCTP_DUMP_INBOUND)
    if data != nil:
      if sctp.isServer:
        trace "onReceive (server)", data = data.packetPretty(), length = msg.len(), address
      else:
        trace "onReceive (client)", data = data.packetPretty(), length = msg.len(), address
      usrsctp_freedumpbuffer(data)

    if sctp.isServer:
      sctp.sentAddress = address
      usrsctp_conninput(cast[pointer](sctp), unsafeAddr msg[0], uint(msg.len), 0)
    else:
      let conn = await sctp.getOrCreateConnection(udp, address)
      sctp.sentConnection = conn
      sctp.sentAddress = address
      usrsctp_conninput(cast[pointer](sctp), unsafeAddr msg[0], uint(msg.len), 0)
  let
    localAddr = TransportAddress(family: AddressFamily.IPv4, port: Port(port))
    laddr = initTAddress("127.0.0.1:" & $port)
    udp = newDatagramTransport(onReceive, local = laddr)
  trace "local address", localAddr, laddr
  sctp.udp = udp
  sctp.timersHandler = timersHandler()

  usrsctp_init_nothreads(port, sendCallback, printf)
  discard usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_NONE)
  discard usrsctp_sysctl_set_sctp_ecn_enable(1)
  usrsctp_register_address(cast[pointer](sctp))

  return sctp

proc listen*(self: Sctp): Future[SctpConnection] {.async.} =
  if not self.isServer:
    raise newSctpError("Not a server")
  trace "Listening"
  if self.pendingConnections.len == 0:
    self.gotConnection.clear()
    await self.gotConnection.wait()
  let res = self.pendingConnections[0]
  self.pendingConnections.delete(0)
  return res

proc connect*(self: Sctp,
              address: TransportAddress,
              sctpPort: uint16 = 5000): Future[SctpConnection] {.async.} =
  trace "Connect", address
  let conn = await self.getOrCreateConnection(self.udp, address, sctpPort)
  try:
    await conn.connectEvent.wait()
  except CancelledError as exc:
    conn.sctpSocket.usrsctp_close()
    return nil
  if conn.state != Connected:
    raise newSctpError("Cannot connect to " & $address)
  return conn
