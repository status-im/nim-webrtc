# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import errors
import chronos, chronicles

logScope:
  topics = "webrtc udp"

# UdpConn is a small wrapper of the chronos DatagramTransport.
# It's the simplest solution we found to store the message and
# the remote address used by the underlying protocols (dtls/sctp etc...)

type
  WebRtcUdpError = object of WebRtcError

  UdpPacketInfo* = tuple
    message: seq[byte]
    raddr: TransportAddress

  UdpConn* = ref object
    laddr*: TransportAddress
    udp: DatagramTransport
    dataRecv: AsyncQueue[UdpPacketInfo]
    closed: bool

proc init*(self: UdpConn, laddr: TransportAddress) =
  ## Initialize an Udp Connection
  ##
  self.laddr = laddr
  self.closed = false

  proc onReceive(
      udp: DatagramTransport,
      raddr: TransportAddress
    ) {.async: (raises: []), gcsafe.} =
    # On receive Udp message callback, store the
    # message with the corresponding remote address
    try:
      trace "UDP onReceive"
      let msg = udp.getMessage()
      self.dataRecv.addLastNoWait((msg, raddr))
    except CatchableError as exc:
      raiseAssert(exc.msg)

  self.dataRecv = newAsyncQueue[UdpPacketInfo]()
  self.udp = newDatagramTransport(onReceive, local = laddr)

proc close*(self: UdpConn) =
  ## Close an Udp Connection
  ##
  if self.closed:
    debug "Trying to close an already closed UdpConn"
    return
  self.closed = true
  self.udp.close()

proc write*(
    self: UdpConn,
    raddr: TransportAddress,
    msg: seq[byte]
  ) {.async: (raises: [CancelledError, WebRtcUdpError]).} =
  ## Write a message on Udp to a remote address `raddr`
  ##
  if self.closed:
    debug "Try to write on an already closed UdpConn"
    return
  trace "UDP write", msg
  try:
    await self.udp.sendTo(raddr, msg)
  except TransportError as exc:
    raise newException(WebRtcUdpError,
      "Error when sending data on a DatagramTransport: " & exc.msg , exc)

proc read*(self: UdpConn): Future[UdpPacketInfo] {.async: (raises: [CancelledError]).} =
  ## Read the next received Udp message
  ##
  if self.closed:
    debug "Try to read on an already closed UdpConn"
    return
  trace "UDP read"
  return await self.dataRecv.popFirst()
