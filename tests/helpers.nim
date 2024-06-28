when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import chronos
import unittest2
export unittest2

const
  StreamTransportTrackerName = "stream.transport"
  StreamServerTrackerName = "stream.server"
  DgramTransportTrackerName = "datagram.transport"

  trackerNames = [
    StreamTransportTrackerName,
    StreamServerTrackerName,
    DgramTransportTrackerName,
  ]

template asyncTest*(name: string, body: untyped): untyped =
  test name:
    waitFor((proc () {.async, gcsafe.} = body)())

template checkTrackers*() =
  for name in trackerNames:
    if name.isCounterLeaked():
      echo name, ": ", name.getTrackerCounter()
      fail()
  # Also test the GC is not fooling with us
  try:
    GC_fullCollect()
  except:
    discard
