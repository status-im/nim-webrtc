# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import strutils
import bearssl, chronos, chronicles, stew/[objects, byteutils]
import ../[udp_transport, errors], stun_message, stun_attributes

logScope:
  topics = "webrtc stun stun_connection"

# TODO:
# - Need to implement ICE-CONTROLL(ED|ING) for browser to browser (not critical)

const
  StunConnectionTracker* = "webrtc.stun.connection"
  StunMaxQueuingMessages = 1024
  StunBindingRequest* = 0x0001'u16
  StunBindingResponse* = 0x0101'u16
  StunBindingErrorResponse* = 0x0111'u16

type
  StunUsernameProvider* = proc(): string {.raises: [], gcsafe.}
  StunUsernameChecker* = proc(username: seq[byte]): bool {.raises: [], gcsafe.}
  StunPasswordProvider* = proc(username: seq[byte]): seq[byte] {.raises: [], gcsafe.}

  StunConn* = ref object
    udp*: UdpTransport # The wrapper protocol: UDP Transport
    laddr*: TransportAddress # Local address
    raddr*: TransportAddress # Remote address
    dataRecv*: AsyncQueue[seq[byte]] # data received which will be read by DTLS
    stunMsgs*: AsyncQueue[seq[byte]] # stun messages received and to be
                                     # processed by the stun message handler
    handlesFut*: Future[void] # Stun Message handler
    closeEvent: AsyncEvent
    closed*: bool

    # Is ice-controlling and iceTiebreaker, not fully implemented yet.
    iceControlling: bool
    iceTiebreaker: uint32

    # Specified by the user
    usernameProvider: StunUsernameProvider
    usernameChecker: StunUsernameChecker
    passwordProvider: StunPasswordProvider

    rng: ref HmacDrbgContext

# - Create Binding Messages (Request / Response / Error)
# Those procedures should be private. They're public for testing purpose.

proc getBindingResponse*(self: StunConn, msg: StunMessage): StunMessage =
  ## Creates a Binding Response StunMessage using a BindingRequest as input.
  ##
  result = StunMessage(msgType: StunBindingResponse,
                        transactionId: msg.transactionId)
  result.attributes.add(XorMappedAddress.encode(self.raddr, msg.transactionId))

proc calculatePriority(self: StunConn): uint32 =
  # https://datatracker.ietf.org/doc/html/rfc8445#section-5.1.2.1
  # Calculate Ice priority. At the moment, we assume we're a publicly available server.
  let typePreference = 126'u32
  let localPreference = 65535'u32
  let componentID = 1'u32
  return (1 shl 24) * typePreference + (1 shl 8) * localPreference + (256 - componentID)

proc getBindingRequest*(self: StunConn): StunMessage =
  ## Creates a Binding Request.
  ##
  result = StunMessage(msgType: StunBindingRequest)
  self.rng[].generate(result.transactionId)

  let username = self.usernameProvider()
  if username != "":
    result.attributes.add(UsernameAttribute.encode(username))

  if self.iceControlling:
    result.attributes.add(IceControlling.encode(self.iceTiebreaker))
  else:
    result.attributes.add(IceControlled.encode(self.iceTiebreaker))
  result.attributes.add(Priority.encode(self.calculatePriority()))

proc checkForError*(self: StunConn, msg: StunMessage): Option[StunMessage] =
  # Check for error from a BindingRequest message.
  # Returns an option with some BindingErrorResponse if there is an error.
  # Returns none otherwise.
  # https://datatracker.ietf.org/doc/html/rfc5389#section-10.1.2
  var res = StunMessage(msgType: StunBindingErrorResponse,
                        transactionId: msg.transactionId)
  if msg.getAttribute(MessageIntegrity).isNone() or
     msg.getAttribute(UsernameAttribute).isNone():
    res.attributes.add(ErrorCode.encode(ECBadRequest))
    return some(res)

  let usernameAttr = msg.getAttribute(UsernameAttribute).get()
  if not self.usernameChecker(usernameAttr.username):
    res.attributes.add(ErrorCode.encode(ECUnauthorized))
    return some(res)

  # https://datatracker.ietf.org/doc/html/rfc5389#section-15.9
  var unknownAttr: seq[uint16]
  for attr in msg.attributes:
    let typ = attr.attributeType
    if typ.isRequired() and typ notin StunAttributeEnum:
      unknownAttr.add(typ)
  if unknownAttr.len() > 0:
    res.attributes.add(ErrorCode.encode(ECUnknownAttribute))
    res.attributes.add(UnknownAttributes.encode(unknownAttr))
    return some(res)

  return none(StunMessage)

proc isFingerprintValid*(msg: StunMessage): bool =
  # Returns true if Fingerprint is missing or if it's valid.
  # Returns false otherwise.
  let fingerprint = msg.getAttribute(Fingerprint)
  if fingerprint.isNone():
    return true
  if msg.attributes[^1].attributeType != AttrFingerprint:
    # Fingerprint should always be the last attribute.
    return false
  let
    copyWithoutFingerprint = StunMessage(
      msgType: msg.msgType,
      transactionId: msg.transactionId,
      attributes: msg.attributes[0 ..< ^1]
    )
    encodedCopy = copyWithoutFingerprint.encode(@[])
  return fingerprint == StunMessage.decode(encodedCopy).getAttribute(Fingerprint)

# - Stun Messages Handler -

proc stunMessageHandler(self: StunConn) {.async: (raises: [CancelledError]).} =
  # Read indefinitely Stun messages from stunMsgs queue.
  # Sends a BindingResponse or BindingResponseError after receiving a BindingRequest.
  while true:
    let message = await self.stunMsgs.popFirst()
    try:
      let decoded = StunMessage.decode(await self.stunMsgs.popFirst())
      if not decoded.isFingerprintValid():
        # Fingerprint is invalid, the StunMessage received might be a false positive.
        # Move this message to the `dataRecv` queue
        await self.dataRecv.addLast(message)
        continue
      if decoded.msgType == StunBindingErrorResponse:
        trace "Received a STUN error", decoded, remote = self.raddr
        continue
      elif decoded.msgType == StunBindingResponse:
        # TODO: Process StunBindingResponse doesn't seem necessary for libp2p-webrtc-direct.
        # Some browsers could be uncooperative. In that case, it should be implemented.
        # It should be implemented for libp2p-webrtc.
        continue
      elif decoded.msgType == StunBindingRequest:
        let errorOpt = self.checkForError(decoded)
        if errorOpt.isSome():
          let error = errorOpt.get()
          await self.udp.write(self.raddr, error.encode(@[]))
          continue

        let
          bindingResponse = self.getBindingResponse(decoded)
          usernameAttr = decoded.getAttribute(UsernameAttribute).get()
          password = self.passwordProvider(usernameAttr.username)
        await self.udp.write(
          self.raddr,
          bindingResponse.encode(password)
        )
    except SerializationError as exc:
      debug "Failed to decode the Stun message", error=exc.msg, message
    except WebRtcError as exc:
      trace "Failed to write the Stun response", error=exc.msg

proc new*(
    T: type StunConn,
    udp: UdpTransport,
    raddr: TransportAddress,
    iceControlling: bool,
    usernameProvider: StunUsernameProvider,
    usernameChecker: StunUsernameChecker,
    passwordProvider: StunPasswordProvider,
    rng: ref HmacDrbgContext
  ): T =
  ## Initialize a Stun Connection
  ## `udp` the wrapper protocol: Udp Transport
  ## `raddr` the remote address observed while receiving message with Udp
  ## `iceControlling` flag to know if we're supposed to act as a "client"
  ##   (controlling) or a "server" (controlled)
  ## `usernameProvider` callback to get a username for the Username attribute
  ## `usernameChecker` callback to let the user check if the Username received
  ##   is valid or not
  ## `passwordProvider` callback to get a key password for the
  ##   Message-integrity sha1 encryption
  ##
  var self = T(
    udp: udp,
    laddr: udp.laddr,
    raddr: raddr,
    closed: false,
    closeEvent: newAsyncEvent(),
    dataRecv: newAsyncQueue[seq[byte]](StunMaxQueuingMessages),
    stunMsgs: newAsyncQueue[seq[byte]](StunMaxQueuingMessages),
    iceControlling: iceControlling,
    iceTiebreaker: rng[].generate(uint32),
    usernameProvider: usernameProvider,
    usernameChecker: usernameChecker,
    passwordProvider: passwordProvider,
    rng: rng
  )
  self.handlesFut = self.stunMessageHandler()
  trackCounter(StunConnectionTracker)
  return self

proc join*(self: StunConn) {.async: (raises: [CancelledError]).} =
  ## Wait for the Stun Connection to be closed
  ##
  await self.closeEvent.wait()

proc close*(self: StunConn) =
  ## Close a Stun Connection
  ##
  if self.closed:
    debug "Try to close an already closed StunConn"
    return
  self.closeEvent.fire()
  self.handlesFut.cancelSoon()
  self.closed = true
  untrackCounter(StunConnectionTracker)

proc write*(
    self: StunConn,
    msg: seq[byte]
  ) {.async: (raises: [CancelledError, WebRtcError]).} =
  ## Write a message on Udp to a remote `raddr` using
  ## the underlying Udp Connection
  ##
  if self.closed:
    debug "Try to write on an already closed StunConn"
    return
  await self.udp.write(self.raddr, msg)

proc read*(self: StunConn): Future[UdpPacketInfo] {.async: (raises: [CancelledError]).} =
  ## Read the next received non-Stun Message
  ##
  if self.closed:
    debug "Try to read on an already closed StunConn"
    return
  return (await self.dataRecv.popFirst(), self.raddr)
