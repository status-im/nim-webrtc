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

# UdpTransport is a small wrapper of the chronos DatagramTransport.
# It's the simplest solution we found to store the message and
# the remote address used by the wrapped protocols (dtls/sctp...)

type
  UdpPacketInfo* = tuple
    message: seq[byte]
    raddr: TransportAddress

  UdpTransport* = ref object
    laddr*: TransportAddress
    udp: DatagramTransport
    dataRecv: AsyncQueue[UdpPacketInfo]
    closed: bool

const UdpTransportTrackerName* = "webrtc.udp.transport"

proc new*(T: type UdpTransport, laddr: TransportAddress): T =
  ## Initialize an Udp Transport
  ##
  var self = T(laddr: laddr, closed: false)

  proc onReceive(
      udp: DatagramTransport,
      raddr: TransportAddress
    ) {.async: (raises: []), gcsafe.} =
    # On receive Udp message callback, store the
    # message with the corresponding remote address
    try:
      let msg = udp.getMessage()
      self.dataRecv.addLastNoWait((msg, raddr))
    except CatchableError as exc:
      raiseAssert(exc.msg)

  self.dataRecv = newAsyncQueue[UdpPacketInfo]()
  self.udp = newDatagramTransport(onReceive, local = laddr)
  trackCounter(UdpTransportTrackerName)
  return self

proc stop*(self: UdpTransport) {.async: (raises: []).} =
  ## Close an Udp Transport
  ##
  if self.closed:
    debug "Trying to stop an already stopped UdpTransport"
    return
  self.closed = true
  await self.udp.closeWait()
  untrackCounter(UdpTransportTrackerName)

proc write*(
    self: UdpTransport,
    raddr: TransportAddress,
    msg: seq[byte]
  ) {.async: (raises: [CancelledError, WebRtcError]).} =
  ## Write a message on Udp to a remote address `raddr`
  ##
  if self.closed:
    debug "Try to write on an already closed UdpTransport"
    return
  trace "UDP write", msg
  try:
    await self.udp.sendTo(raddr, msg)
  except TransportError as exc:
    raise newException(WebRtcError,
      "UDP - Error when sending data on a DatagramTransport: " & exc.msg , exc)

proc read*(self: UdpTransport): Future[UdpPacketInfo] {.async: (raises: [CancelledError]).} =
  ## Read the next received Udp message
  ##
  if self.closed:
    debug "Try to read on an already closed UdpTransport"
    return
  trace "UDP read"
  return await self.dataRecv.popFirst()
