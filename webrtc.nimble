packageName = "webrtc"
version = "0.0.1"
author = "Status Research & Development GmbH"
description = "Webrtc stack"
license = "MIT"
installDirs = @["webrtc"]

requires "nim >= 1.6.0",
         "chronicles >= 0.10.2",
         "chronos >= 3.0.6",
         "https://github.com/status-im/nim-binary-serialization.git",
         "https://github.com/status-im/nim-mbedtls.git",
         "https://github.com/status-im/nim-usrsctp.git"

let nimc = getEnv("NIMC", "nim") # Which nim compiler to use
let lang = getEnv("NIMLANG", "c") # Which backend (c/cpp/js)
let flags = getEnv("NIMFLAGS", "") # Extra flags for the compiler
let verbose = getEnv("V", "") notin ["", "0"]

let cfg =
  " --styleCheck:usages --styleCheck:error" &
  (if verbose: "" else: " --verbosity:0 --hints:off") &
  " --skipParentCfg --skipUserCfg -f" &
  " --threads:on --opt:speed"

import hashes

proc buildExample(filename: string, run = false, extraFlags = "") =
  var excstr = nimc & " " & lang & " " & flags & " -p:. " & extraFlags
  excstr.add(" examples/" & filename)
  exec excstr
  if run:
    exec "./examples/" & filename.toExe
  rmFile "examples/" & filename.toExe

proc runTest(filename: string) =
  var excstr = nimc & " " & lang & " -d:debug " & cfg & " " & flags
  excstr.add(" -d:nimOldCaseObjects") # TODO: fix this in binary-serialization
  if getEnv("CICOV").len > 0:
    excstr &= " --nimcache:nimcache/" & filename & "-" & $excstr.hash
  exec excstr & " -r " & " tests/" & filename
  rmFile "tests/" & filename.toExe

task test, "Runs the test suite":
  # runTest("runalltests")
  exec "nimble build_example"

task build_example, "Build the examples":
  buildExample("ping")
  buildExample("pong")
