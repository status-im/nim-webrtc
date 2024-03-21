# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import sequtils, typetraits, random, system, std/[md5, sha1]
import binary_serialization,
       stew/byteutils,
       chronos

# -- Utils --

const charset = toSeq("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".items)
proc genUfrag*(size: int): seq[byte] =
  # https://github.com/libp2p/specs/blob/master/webrtc/webrtc-direct.md?plain=1#L73-L77
  result = newSeq[byte](size)
  for i in 0..<size:
    result[i] = charset[rand(0..<charset.len())].ord().uint8

proc createCrc32Table(): array[0..255, uint32] =
  for i in 0..255:
    var rem = i.uint32
    for j in 0..7:
      if (rem and 1) > 0:
        rem = (rem shr 1) xor 0xedb88320'u32
      else:
        rem = rem shr 1
    result[i] = rem

proc crc32(s: seq[byte]): uint32 =
  # CRC-32 is used for the fingerprint attribute
  # See https://datatracker.ietf.org/doc/html/rfc5389#section-15.5
  const crc32table = createCrc32Table()
  result = 0xffffffff'u32
  for c in s:
    result = (result shr 8) xor crc32table[(result and 0xff) xor c]
  result = not result

proc hmacSha1(key: seq[byte], msg: seq[byte]): seq[byte] =
  # HMAC-SHA1 is used for the message integrity attribute
  # See https://datatracker.ietf.org/doc/html/rfc5389#section-15.4
  let
    keyPadded =
      if len(key) > 64:
        @(secureHash(key.mapIt(it.chr)).distinctBase)
      elif key.len() < 64:
        key.concat(newSeq[byte](64 - key.len()))
      else:
        key
    innerHash = keyPadded.
                  mapIt(it xor 0x36'u8).
                  concat(msg).
                  mapIt(it.chr).
                  secureHash()
    outerHash = keyPadded.
                  mapIt(it xor 0x5c'u8).
                  concat(@(innerHash.distinctBase)).
                  mapIt(it.chr).
                  secureHash()
  return @(outerHash.distinctBase)

# -- Attributes --
# There are obviously some attributes implementation that are missing,
# it might be something to do eventually if we want to make this
# repository work for other project than nim-libp2p
#
# Stun Attribute
# 0                   1                   2                   3
# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Type                  |            Length             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Value (variable)                ....
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

type
  StunAttributeEncodingError* = object of CatchableError

  RawStunAttribute* = object 
    attributeType*: uint16
    length* {.bin_value: it.value.len.}: uint16
    value* {.bin_len: it.length.}: seq[byte]

  StunAttributeEnum* = enum
    AttrMappedAddress = 0x0001
    AttrChangeRequest = 0x0003 # RFC5780 Nat Behavior Discovery
    AttrSourceAddress = 0x0004 # Deprecated
    AttrChangedAddress = 0x0005 # Deprecated
    AttrUsername = 0x0006
    AttrMessageIntegrity = 0x0008
    AttrErrorCode = 0x0009
    AttrUnknownAttributes = 0x000A
    AttrChannelNumber = 0x000C # RFC5766 TURN
    AttrLifetime = 0x000D # RFC5766 TURN
    AttrXORPeerAddress = 0x0012 # RFC5766 TURN
    AttrData = 0x0013 # RFC5766 TURN
    AttrRealm = 0x0014
    AttrNonce = 0x0015
    AttrXORRelayedAddress = 0x0016 # RFC5766 TURN
    AttrRequestedAddressFamily = 0x0017 # RFC6156
    AttrEvenPort = 0x0018 # RFC5766 TURN
    AttrRequestedTransport = 0x0019 # RFC5766 TURN
    AttrDontFragment = 0x001A # RFC5766 TURN
    AttrMessageIntegritySHA256 = 0x001C # RFC8489 STUN (v2)
    AttrPasswordAlgorithm = 0x001D # RFC8489 STUN (v2)
    AttrUserhash = 0x001E # RFC8489 STUN (v2)
    AttrXORMappedAddress = 0x0020
    AttrReservationToken = 0x0022 # RFC5766 TURN
    AttrPriority = 0x0024 # RFC5245 ICE
    AttrUseCandidate = 0x0025 # RFC5245 ICE
    AttrPadding = 0x0026 # RFC5780 Nat Behavior Discovery
    AttrResponsePort = 0x0027 # RFC5780 Nat Behavior Discovery
    AttrConnectionID = 0x002a # RFC6062 TURN Extensions
    AttrPasswordAlgorithms = 0x8002 # RFC8489 STUN (v2)
    AttrAlternateDomain = 0x8003 # RFC8489 STUN (v2)
    AttrSoftware = 0x8022
    AttrAlternateServer = 0x8023
    AttrCacheTimeout = 0x8027 # RFC5780 Nat Behavior Discovery
    AttrFingerprint = 0x8028
    AttrICEControlled = 0x8029 # RFC5245 ICE
    AttrICEControlling = 0x802A # RFC5245 ICE
    AttrResponseOrigin = 0x802b # RFC5780 Nat Behavior Discovery
    AttrOtherAddress = 0x802C # RFC5780 Nat Behavior Discovery
    AttrOrigin = 0x802F

proc isRequired*(typ: uint16): bool = typ <= 0x7FFF'u16
proc isOptional*(typ: uint16): bool = typ >= 0x8000'u16

# Username
# https://datatracker.ietf.org/doc/html/rfc5389#section-15.3

type
  UsernameAttribute* = object

proc encode(T: typedesc[UsernameAttribute], username: seq[byte]): RawStunAttribute =
  result = RawStunAttribute(attributeType: AttrUsername.uint16,
                            length: username.len().uint16,
                            value: username)

# Error Code
# https://datatracker.ietf.org/doc/html/rfc5389#section-15.6

type
  ErrorCodeEnum* = enum
    ECTryAlternate = 300
    ECBadRequest = 400
    ECUnauthenticated = 401
    ECUnknownAttribute = 420
    ECStaleNonce = 438
    ECServerError = 500
  ErrorCode* = object
    reserved1: uint16 # should be 0
    reserved2 {.bin_bitsize: 5.}: uint8 # should be 0
    class {.bin_bitsize: 3.}: uint8
    number: uint8
    reason: seq[byte]

proc encode*(T: typedesc[ErrorCode], code: ErrorCodeEnum, reason: string = ""): RawStunAttribute =
  let
    ec = T(class: (code.uint16 div 100'u16).uint8,
                   number: (code.uint16 mod 100'u16).uint8,
                   reason: reason.toBytes())
    value = Binary.encode(ec)
  result = RawStunAttribute(attributeType: AttrErrorCode.uint16,
                            length: value.len().uint16,
                            value: value)

# Unknown Attribute
# https://datatracker.ietf.org/doc/html/rfc5389#section-15.9

type
  UnknownAttribute* = object
    unknownAttr: seq[uint16]

proc encode*(T: typedesc[UnknownAttribute], unknownAttr: seq[uint16]): RawStunAttribute =
  let
    ua = T(unknownAttr: unknownAttr)
    value = Binary.encode(ua)
  result = RawStunAttribute(attributeType: AttrUnknownAttributes.uint16,
                            length: value.len().uint16,
                            value: value)

# Fingerprint
# https://datatracker.ietf.org/doc/html/rfc5389#section-15.5

type
  Fingerprint* = object
    crc32: uint32

proc encode*(T: typedesc[Fingerprint], msg: seq[byte]): RawStunAttribute =
  let value = Binary.encode(T(crc32: crc32(msg) xor 0x5354554e'u32))
  result = RawStunAttribute(attributeType: AttrFingerprint.uint16,
                            length: value.len().uint16,
                            value: value)

# Xor Mapped Address
# https://datatracker.ietf.org/doc/html/rfc5389#section-15.2

type
  MappedAddressFamily {.size: 1.} = enum
    MAFIPv4 = 0x01
    MAFIPv6 = 0x02

  XorMappedAddress* = object
    reserved: uint8 # should be 0
    family: MappedAddressFamily
    port: uint16
    address: seq[byte]

proc encode*(T: typedesc[XorMappedAddress], ta: TransportAddress,
             tid: array[12, byte]): RawStunAttribute =
  const magicCookie = @[ 0x21'u8, 0x12, 0xa4, 0x42 ]
  let
    (address, family) =
      if ta.family == AddressFamily.IPv4:
        var s = newSeq[uint8](4)
        for i in 0..3:
          s[i] = ta.address_v4[i] xor magicCookie[i]
        (s, MAFIPv4)
      else:
        let magicCookieTid = magicCookie.concat(@tid)
        var s = newSeq[uint8](16)
        for i in 0..15:
          s[i] = ta.address_v6[i] xor magicCookieTid[i]
        (s, MAFIPv6)
    xma = T(family: family, port: ta.port.distinctBase xor 0x2112'u16, address: address)
    value = Binary.encode(xma)
  result = RawStunAttribute(attributeType: AttrXORMappedAddress.uint16,
                            length: value.len().uint16,
                            value: value)

# Message Integrity
# https://datatracker.ietf.org/doc/html/rfc5389#section-15.4

type
  MessageIntegrity* = object
    msgInt: seq[byte]

proc encode*(T: typedesc[MessageIntegrity], msg: seq[byte], key: seq[byte]): RawStunAttribute =
  let value = Binary.encode(T(msgInt: hmacSha1(key, msg)))
  result = RawStunAttribute(attributeType: AttrMessageIntegrity.uint16,
                            length: value.len().uint16, value: value)
