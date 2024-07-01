when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import chronos
import unittest2
export unittest2

const
  DgramTransportTrackerName = "datagram.transport"
  UdpTransportTrackerName = "webrtc.udp.transport"
  StunTransportTrackerName = "webrtc.stun.transport"
  StunConnectionTrackerName = "webrtc.stun.connection"


  trackerNames = [
    DgramTransportTrackerName,
    UdpTransportTrackerName,
    StunTransportTrackerName,
    StunConnectionTrackerName,
  ]

template checkTrackers*() =
  var didTrackersLeaked = false
  for name in trackerNames:
    if name.isCounterLeaked():
      checkpoint(name & " leaked: " & $(name.getTrackerCounter()))
      didTrackersLeaked = true
  # Also test the GC is not fooling with us
  try:
    GC_fullCollect()
  except:
    discard
  if didTrackersLeaked:
    fail()
