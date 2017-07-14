package com.BigBrainSecurity.vol.windows

/**
  * Program Purpose: Takes the results from AutomateVolDiscovery.scala
  * and inputs them into other volatility modules.
  */
import sys.process._
import scala.io.Source

class VolDiscoveryPart2Windows(pid: String, memFile: String, os: String ) {

  def run = {
    // Stores domain name we’ll search for in processes.
    val domainName = "windows-update-http.com"

    // Make sure the filenames in the details and the filenames for each process match (182)
    val fileNameDiscrepancies = s"python vol.py -f $memFile --profile=$os -p $pid handles -t File, Mutant --silent" !!

    // Do a yara scan PROBABLY NEED TO MOVE TO DIFFERENT CLASS
    val yaraByDomain = s"python vol.py -f $memFile yarascan --profile=$os --yara-rules=$domainName" !!


  } // END run()


} // END VolDiscoveryPart2 class
