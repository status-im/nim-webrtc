import ../webrtc/datachannel
import chronos/unittest2/asynctests
import binary_serialization

suite "DataChannel encoding":
  test "DataChannelOpenMessage":
    let msg = @[
        0x03'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x03, 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]
    check msg == Binary.encode(Binary.decode(msg, DataChannelMessage))
    check Binary.decode(msg, DataChannelMessage).openMessage ==
        DataChannelOpenMessage(
          channelType: Reliable,
          priority: 0,
          reliabilityParameter: 0,
          labelLength: 3,
          protocolLength: 3,
          label: @[102, 111, 111],
          protocol: @[98, 97, 114]
        )

  test "DataChannelAck":
    let msg = @[0x02'u8]
    check msg == Binary.encode(Binary.decode(msg, DataChannelMessage))
    check Binary.decode(msg, DataChannelMessage).messageType == Ack
