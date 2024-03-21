# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import bitops, strutils, random
import chronos,
       chronicles,
       binary_serialization,
       stew/objects,
       stew/byteutils
import stun_attributes

export binary_serialization

logScope:
  topics = "webrtc stun"

const
  msgHeaderSize = 20
  magicCookieSeq = @[ 0x21'u8, 0x12, 0xa4, 0x42 ]
  magicCookie = 0x2112a442
  BindingRequest = 0x0001'u16
  BindingResponse = 0x0101'u16

proc decode(T: typedesc[RawStunAttribute], cnt: seq[byte]): seq[RawStunAttribute] =
  const pad = @[0, 3, 2, 1]
  var padding = 0
  while padding < cnt.len():
    let attr = Binary.decode(cnt[padding ..^ 1], RawStunAttribute)
    result.add(attr)
    padding += 4 + attr.value.len()
    padding += pad[padding mod 4]

type
#  Stun Header
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |0 0|     STUN Message Type     |         Message Length        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Magic Cookie                          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# |                     Transaction ID (96 bits)                  |
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# Message type:
#   0x0001: Binding Request
#   0x0101: Binding Response
#   0x0111: Binding Error Response
#   0x0002: Shared Secret Request
#   0x0102: Shared Secret Response
#   0x0112: Shared Secret Error Response

  RawStunMessage = object
    msgType: uint16
    length* {.bin_value: it.content.len().}: uint16
    magicCookie: uint32
    transactionId: array[12, byte] # Down from 16 to 12 bytes in RFC5389
    content* {.bin_len: it.length.}: seq[byte]

  StunMessage* = object
    msgType*: uint16
    transactionId*: array[12, byte]
    attributes*: seq[RawStunAttribute]

  Stun* = object
    iceTiebreaker: uint64

proc generateRandomSeq(size: int): seq[byte] =
  result = newSeq[byte](size)
  for i in 0..<size:
    result[i] = rand(255).uint8

proc getAttribute(attrs: seq[RawStunAttribute], typ: uint16): Option[seq[byte]] =
  for attr in attrs:
    if attr.attributeType == typ:
      return some(attr.value)
  return none(seq[byte])

proc isMessage*(T: typedesc[Stun], msg: seq[byte]): bool =
  msg.len >= msgHeaderSize and msg[4..<8] == magicCookieSeq and bitand(0xC0'u8, msg[0]) == 0'u8

proc addLength(msgEncoded: var seq[byte], length: uint16) =
  let
    hi = (length div 256'u16).uint8
    lo = (length mod 256'u16).uint8
  msgEncoded[2] = msgEncoded[2] + hi
  if msgEncoded[3].int + lo.int >= 256:
    msgEncoded[2] = msgEncoded[2] + 1
    msgEncoded[3] = ((msgEncoded[3].int + lo.int) mod 256).uint8
  else:
    msgEncoded[3] = msgEncoded[3] + lo

proc decode*(T: typedesc[StunMessage], msg: seq[byte]): StunMessage =
  let smi = Binary.decode(msg, RawStunMessage)
  return T(msgType: smi.msgType,
           transactionId: smi.transactionId,
           attributes: RawStunAttribute.decode(smi.content))

proc encode*(msg: StunMessage, userOpt: Option[seq[byte]] = none(seq[byte])): seq[byte] =
  const pad = @[0, 3, 2, 1]
  var smi = RawStunMessage(msgType: msg.msgType,
                           magicCookie: magicCookie,
                           transactionId: msg.transactionId)
  for attr in msg.attributes:
    smi.content.add(Binary.encode(attr))
    smi.content.add(newSeq[byte](pad[smi.content.len() mod 4]))

  result = Binary.encode(smi)

  if userOpt.isSome():
    let username = string.fromBytes(userOpt.get())
    let usersplit = username.split(":")
    if usersplit.len() == 2 and usersplit[0].startsWith("libp2p+webrtc+v1/"):
      result.addLength(24)
      result.add(Binary.encode(MessageIntegrity.encode(result, toBytes(usersplit[0]))))

  result.addLength(8)
  result.add(Binary.encode(Fingerprint.encode(result)))

proc getPong*(
    T: typedesc[Stun],
    msg: seq[byte],
    ta: TransportAddress
  ): Option[seq[byte]] =
  if ta.family != AddressFamily.IPv4 and ta.family != AddressFamily.IPv6:
    return none(seq[byte])
  let sm =
    try:
      StunMessage.decode(msg)
    except CatchableError as exc:
      return none(seq[byte])

  if sm.msgType != BindingRequest:
    return none(seq[byte])

  var res = StunMessage(msgType: BindingResponse,
                        transactionId: sm.transactionId)

  var unknownAttr: seq[uint16]
  for attr in sm.attributes:
    let typ = attr.attributeType
    if typ.isRequired() and typ notin StunAttributeEnum:
      unknownAttr.add(typ)
  if unknownAttr.len() > 0:
    res.attributes.add(ErrorCode.encode(ECUnknownAttribute))
    res.attributes.add(UnknownAttribute.encode(unknownAttr))
    return some(res.encode(sm.attributes.getAttribute(AttrUsername.uint16)))

  res.attributes.add(XorMappedAddress.encode(ta, sm.transactionId))
  return some(res.encode(sm.attributes.getAttribute(AttrUsername.uint16)))

proc getPing*(
    T: typedesc[Stun],
    ta: TransportAddress,
    username: seq[byte] = @[],
    iceControlling: bool = true
  ): seq[byte] =
  var res = StunMessage(msgType: BindingRequest,
                        transactionId: generateRandomSeq(12))
  if username != @[]:
    res.attributes.add(UsernameAttribute.encode(username))

proc new*(T: typedesc[Stun]): T =
  result = T(iceTiebreaker: rand(uint64))
