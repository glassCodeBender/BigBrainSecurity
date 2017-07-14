package com.BigBrainSecurity.vol.windows

/**
  * Program Purpose: Takes the results from AutomateVolDiscovery.scala
  * and inputs them into other volatility modules.
  */
import sys.process._
import scala.io.Source

class VolProcDiscoveryWindows(pid: String, memFile: String, os: String ) {

  def run = {
    // Stores domain name we’ll search for in processes.
    val domainName = "windows-update-http.com"

    // Make sure the filenames in the details and the filenames for each process match (182)
    val fileNameDiscrepancies = s"python vol.py -f $memFile --profile=$os -p $pid handles -t File, Mutant --silent" !!

    // Dump handles for the System process to see all open handles to kernel modules

    // Do a yara scan PROBABLY NEED TO MOVE TO DIFFERENT CLASS
    val yaraByDomain = s"python vol.py -f $memFile yarascan --profile=$os --yara-rules=$domainName" !!


    // Look through getSid for SIDs with nothing after SID is displayed. Then pass SID to printkey plugin.

    // Allows us to determine which privilege the process enabled (list on 171-172)
    val priv = s"python vol.py -f $memFile --profile=$os privs -p $pid" !!

    // NOTE: We don't really need to use the command below, but might be easier than manually parsing.
    // Count the times that Enabled occurs.
    // Would be nice to store in Vector for quick access, but we need indexed sequence.
    // IGNORE UNDOCK PRIV: explorer.exe always enables undock priv.

    // Only gives privileges that a process specifically enabled.
    val enabledPriv = s"python vol.py -f $memFile --profile=$os privs --silent" !!


    // SEE PAGE 168 for example of "printkey -K *" command based off output of getsid
    val getSID = s"python vol.py -f $memFile --profile=$os getsid -p $pid" !!

  } // END run()


} // END VolDiscoveryPart2 class
