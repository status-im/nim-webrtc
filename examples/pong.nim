import chronos, stew/byteutils
import ../webrtc/udp_connection
import ../webrtc/stun/stun_connection
import ../webrtc/dtls/dtls
import ../webrtc/sctp

proc sendPong(conn: SctpConn) {.async.} =
  var i = 0
  while true:
    let msg = await conn.read()
    echo "Received: ", string.fromBytes(msg.data)
    await conn.write(("pong " & $i).toBytes)
    i.inc()

proc main() {.async.} =
  let laddr = initTAddress("127.0.0.1:4242")
  let udp = UdpConn()
  await udp.init(laddr)
  let stun = StunConn()
  await stun.init(udp, laddr)
  let dtls = Dtls()
  dtls.start(stun, laddr)
  let sctp = Sctp.new(dtls, laddr)
  await sctp.listen(13)
  while true:
    let conn = await sctp.accept()
    asyncSpawn conn.sendPong()

waitFor(main())
