package com.BigBrainSecurity.vol

/** This is the main class used to automate volatility */
object AutomateVolatility extends App {

  val os = "Windows7x64"
  val memFile = "/Users/glassCodeBender/Documents/memdump.mem"

  val discovery = AutomateVolDiscovery.run(os, memFile)

  /** After we have the results, we need to interrogate each process */




} // END AutomateVolatility object
