# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import tables
import chronos, chronicles, bearssl
import stun_connection, stun_message, ../udp_connection

logScope:
  topics = "webrtc stun stun_transport"

type
  Stun* = ref object
    connections: Table[TransportAddress, StunConn]
    pendingConn: AsyncQueue[StunConn]
    readingLoop: Future[void]
    conn: UdpConn
    rng: ref HmacDrbgContext

proc accept*(self: Stun): Future[StunConn] {.async: (raises: [CancelledError]).} =
  ## Accept a Stun Connection
  ##
  var res: StunConn
  while true:
    res = await self.pendingConn.popFirst()
    if res.closed != true: # The connection could be closed before being accepted
      break
  return res

proc connect*(
    self: Stun,
    raddr: TransportAddress
  ): Future[StunConn] {.async: (raises: []).} =
  ## Connect to a remote address, creating a Stun Connection
  ##
  self.connections.withValue(raddr, res):
    return res
  do:
    let res = StunConn.init(self.conn, raddr, false, self.rng)
    self.connections[raddr] = res
    return res

proc cleanupStunConn(self: Stun, conn: StunConn) {.async: (raises: []).} =
  # Waiting for a connection to be closed to remove it from the table
  try:
    await conn.join()
    self.connections.del(conn.raddr)
  except CancelledError as exc:
    warn "Error cleaning up Stun Connection", error=exc.msg

proc stunReadLoop(self: Stun) {.async: (raises: [CancelledError]).} =
  while true:
    let (buf, raddr) = await self.conn.read()
    var stunConn: StunConn
    if not self.connections.hasKey(raddr):
      stunConn = StunConn.init(self.conn, raddr, true, self.rng)
      self.connections[raddr] = stunConn
      await self.pendingConn.addLast(stunConn)
      asyncSpawn self.cleanupStunConn(stunConn)
    else:
      try:
        stunConn = self.connections[raddr]
      except KeyError as exc:
        doAssert(false, "Should never happen")

    if isStunMessage(buf):
      await stunConn.stunMsgs.addLast(buf)
    else:
      await stunConn.dataRecv.addLast(buf)

proc stop(self: Stun) =
  ## Stop the Stun transport and close all the connections
  ##
  for conn in self.connections.values():
    conn.close()
  self.readingLoop.cancelSoon()

proc init*(
    T: type Stun,
    conn: UdpConn,
    rng: ref HmacDrbgContext = HmacDrbgContext.new()
  ): T =
  ## Initialize the Stun transport
  ##
  var self = T(conn: conn, rng: rng)
  self.readingLoop = stunReadLoop()
  self.pendingConn = newAsyncQueue[StunConn]()
  return self
