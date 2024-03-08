import options
import ../webrtc/stun/stun
import ../webrtc/stun/stun_attributes
import ./asyncunit

suite "Stun message encoding/decoding":
  test "Stun decoding":
    let msg = @[ 0x00'u8, 0x01, 0x00, 0xa4, 0x21, 0x12, 0xa4, 0x42, 0x75, 0x6a, 0x58, 0x46, 0x42, 0x58, 0x4e, 0x72, 0x6a, 0x50, 0x4d, 0x2b, 0x00, 0x06, 0x00, 0x63, 0x6c, 0x69, 0x62, 0x70, 0x32, 0x70, 0x2b, 0x77, 0x65, 0x62, 0x72, 0x74, 0x63, 0x2b, 0x76, 0x31, 0x2f, 0x62, 0x71, 0x36, 0x67, 0x69, 0x43, 0x75, 0x4a, 0x38, 0x6e, 0x78, 0x59, 0x46, 0x4a, 0x36, 0x43, 0x63, 0x67, 0x45, 0x59, 0x58, 0x58, 0x2f, 0x78, 0x51, 0x58, 0x56, 0x4c, 0x74, 0x39, 0x71, 0x7a, 0x3a, 0x6c, 0x69, 0x62, 0x70, 0x32, 0x70, 0x2b, 0x77, 0x65, 0x62, 0x72, 0x74, 0x63, 0x2b, 0x76, 0x31, 0x2f, 0x62, 0x71, 0x36, 0x67, 0x69, 0x43, 0x75, 0x4a, 0x38, 0x6e, 0x78, 0x59, 0x46, 0x4a, 0x36, 0x43, 0x63, 0x67, 0x45, 0x59, 0x58, 0x58, 0x2f, 0x78, 0x51, 0x58, 0x56, 0x4c, 0x74, 0x39, 0x71, 0x7a, 0x00, 0xc0, 0x57, 0x00, 0x04, 0x00, 0x00, 0x03, 0xe7, 0x80, 0x2a, 0x00, 0x08, 0x86, 0x63, 0xfd, 0x45, 0xa9, 0xe5, 0x4c, 0xdb, 0x00, 0x24, 0x00, 0x04, 0x6e, 0x00, 0x1e, 0xff, 0x00, 0x08, 0x00, 0x14, 0x16, 0xff, 0x70, 0x8d, 0x97, 0x0b, 0xd6, 0xa3, 0x5b, 0xac, 0x8f, 0x4c, 0x85, 0xe6, 0xa6, 0xac, 0xaa, 0x7a, 0x68, 0x27, 0x80, 0x28, 0x00, 0x04, 0x79, 0x5e, 0x03, 0xd8 ]
    let stunmsg = StunMessage.decode(msg)
    check:
      stunmsg.msgType == 1
      stunmsg.transactionId.len() == 12
      stunmsg.attributes.len() == 6
      stunmsg.attributes[0].attributeType == 6 # AttrUsername
      stunmsg.attributes[^1].attributeType == 0x8028 # AttrFingerprint

  test "Stun encoding":
    let transactionId: array[12, byte] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    var msg = StunMessage(msgType: 0x0001'u16, transactionId: transactionId)
    msg.attributes.add(ErrorCode.encode(ECUnknownAttribute))
    let encoded = msg.encode()
    let decoded = StunMessage.decode(encoded)
    # cannot do `check msg == decoded` because encode add a Fingerprint
    # attribute at the end
    check:
      decoded.msgType == 1
      decoded.transactionId == transactionId
      decoded.attributes.len() == 2
      decoded.attributes[0].attributeType == 9 # AttrErrorCode
      decoded.attributes[^1].attributeType == 0x8028 # AttrFingerprint

  test "Error while decoding":
    let msgLengthFailed = @[ 0x00'u8, 0x01, 0x00, 0xa4, 0x21, 0x12, 0xa4, 0x42, 0x75, 0x6a, 0x58, 0x46, 0x42, 0x58, 0x4e, 0x72, 0x6a, 0x50, 0x4d ]
    expect AssertionDefect: discard StunMessage.decode(msgLengthFailed)
    let msgAttrFailed = @[ 0x00'u8, 0x01, 0x00, 0x08, 0x21, 0x12, 0xa4, 0x42, 0x75, 0x6a, 0x58, 0x46, 0x42, 0x58, 0x4e, 0x72, 0x6a, 0x50, 0x4d, 0x2b, 0x28, 0x00, 0x05, 0x79, 0x5e, 0x03, 0xd8 ]
    expect AssertionDefect: discard StunMessage.decode(msgAttrFailed)
