# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import chronos, chronicles

import udp_connection
import stun/stun_connection
import dtls/dtls
import sctp, datachannel

logScope:
  topics = "webrtc"

type
  WebRTC* = ref object
    udp*: UdpConn
    stun*: StunConn
    dtls*: Dtls
    sctp*: Sctp
    port: int

proc new*(T: typedesc[WebRTC], address: TransportAddress): T =
  result = T(udp: UdpConn(), stun: StunConn(), dtls: Dtls(), sctp: Sctp())
  result.udp.init(address)
  result.stun.init(result.udp, address)
  result.dtls.init(result.stun, address)
  result.sctp.init(result.dtls, address)

proc listen*(self: WebRTC) =
  self.sctp.listen()

proc connect*(self: WebRTC, raddr: TransportAddress): Future[DataChannelConnection] {.async.} =
  let sctpConn = await self.sctp.connect(raddr) # TODO: Port?
  result = DataChannelConnection.new(sctpConn)

proc accept*(w: WebRTC): Future[DataChannelConnection] {.async.} =
  let sctpConn = await w.sctp.accept()
  result = DataChannelConnection.new(sctpConn)
