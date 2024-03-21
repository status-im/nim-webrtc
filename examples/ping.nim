import chronos, stew/byteutils
import ../webrtc/udp_connection
import ../webrtc/stun/stun_connection
import ../webrtc/dtls/dtls
import ../webrtc/sctp

proc main() {.async.} =
  let laddr = initTAddress("127.0.0.1:4244")
  let udp = UdpConn()
  udp.init(laddr)
  let stun = StunConn()
  stun.init(udp, laddr)
  let dtls = Dtls()
  dtls.init(stun, laddr)
  let sctp = Sctp()
  sctp.init(dtls, laddr)
  let conn = await sctp.connect(initTAddress("127.0.0.1:4242"), sctpPort = 13)
  while true:
    await conn.write("ping".toBytes)
    let msg = await conn.read()
    echo "Received: ", string.fromBytes(msg.data)
    await sleepAsync(1.seconds)

waitFor(main())
