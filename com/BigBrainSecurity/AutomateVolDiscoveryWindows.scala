package com.BigBrainSecurity.vol.windows

/**
  * @author J. Alexander
  * @date July 13, 2017
  * @version 1.0
  *
  *      Program Purpose: Automate volatility discovery commands and
  *      store them in variables that we can parse and use in another program.
  */

import scala.collection.LinearSeq
import sys.process._
import scala.io.Source

/********************************* CASE CLASSES ************************/
/** Store raw information about processes in memory  */
case class Process(psxview: String, psScan: String, psList: String, execInProcList: String)

/** Store information about memory Pools*/
case class Pool(bigPools: String, bigPoolByFreq: String )

/** Store History info discovered in memory */
case class History(cmdScan: String, svcScan: String, envVars: String, priv: String)

/** Stores all the processes we need to audit. */
case class ToAudit(pid: Vector[Int], name: Vector[String], hexAD: Vector[String], info: Vector[String])

/** Stores all of the raw data we discovered. This class will be returned from main. */
case class Discovery(proc: Process, pool: Pool, history: History, audit: ToAudit)

object AutomateVolDiscoveryWindows extends App{

  /**
    * NOTE: This is the information discovery script.
    * After the information is discovered, we need another script that
    * passes each PID into another program
    * Example: `python vol.py getsids -p @pid`
    */
  def run(os: String, memFile: String): Discovery = {

    /** ************************ PERFORM VOLATILITY SCANS **************************/

    // Locate the debugger data block so we can walk the active processes (64-65)
    val validDebugBlock = s"python vol.py -f $memFile --profile=$os kdgbscan" !!

    // Use validDebugBlock to locate PsActiveProcessHead w/ active processes so
    // that we can go back through the results and locate the correct Offset mem location.

    // Used to determine which processes are included in paged and nonpaged memory.
    val objTypeScan = s"python vol.py -f $memFile --profile=$os objtypescan" !!

    // Look for the signature names (Key) of Token and Process then note them.
    // This allows us to make sure that the processes are located in Nonpaged memory.


    /** DO VARIETY OF PROCESS SCANS */
    // If you see False in the splits column, there’s a problem.
    val psxview = s"python vol.py -f $memFile --profile=$os psxview —apply-rules" !!

    // Once we find a False value, save the Offset, Name, and PID for further interrogation.

    // list processes in memory.
    val psList = s"python vol.py -f $memFile --profile=$os pslist" !!

    // List information about all processes that were running on the system.
    // HELPFUL for finding PIDs, PPIDS, offset address, and Start datetime.
    val psScan = s"python vol.py -f $memFile --profile=$os psscan" !!

    // Look in time exited column for processes that were terminated. (140)
    // Run regex from BigBrainSecurity over all values in name column.

    /** Big Pool Scans */

      /** NOT A PRIORITY UNTIL OTHER ANALYSIS SECTIONS ARE COMPLETE */
    // Make list of big pool allocations and sort based on tag frequency (145)
    // It's likely that bigPoolCSV will be the most useful.
    val bigPoolCSV = s"python vol.py -f $memFile --profile=$os bigpools --tags" !!

    val bigPools = s"python vol.py -f $memFile --profile=$os bigpools" !!
    val scanByFreq = "awk '{print  $2}'" + s"$bigPools | sort | uniq -c | sort -rn"
    val bigPoolsByFreq = scanByFreq !!

    // NOTE: We need to use a find replace to include descriptions of pooltags from pooltag.txt
    // if we decided to filter by freq. I'm not 100% this will be worth my time if my time yet.

    // find command histories
    val cmdScan = s"python vol.py -f $memFile --profile=$os cmdscan" !!
    val cmdOutput = s"python vol.py -f $memFile --profile=$os consoles" !!

    // locate windows service records
    val svcScan = s"python vol.py -f $memFile --profile=$os svcscan" !!

    // environmental variables scan
    val envVars = s"python vol.py -f $memFile --profile=$os envars" !!

    // Only gives privileges that a process specifically enabled
    val priv = s"python vol.py -f $memFile --profile=$os privs --silent" !!

    // Find hidden and injected code
    val malfind = s"python vol.py -f $memFile --profile=$os malfind" !!

    // Scans for and parses potential Master Boot Records (MBRs)
    val mbr = s"python vol.py -f $memFile --profile=$os mbrparser" !!

    // scan for connections and sockets
    val socketsAndConnections = s"python vol.py -f $memFile --profile=$os netscan" !!

    /** Extract all executables in the active process
      * This can also be written with a regex flag */
    val execInProcList = s"python vol.py -f $memFile --profile=$os procdump" !!


  } // END run()

  /************* UTILITY METHODS TO MAKE VALUES IN MODULE OUTPUTS ACCESSIBLE ***********/
  /**
    * parseOutput()
    * Remove the stuff we don't need from the output
    * @param volStr
    * @return Some[List[String]]
    */
  def parseOutput(volStr: String): Some[List[String]] = {
    Some( Source.fromString(volStr)
      .getLines
      .dropWhile( !_.contains("------") )
      .dropWhile( _.contains("-----") )
      .toList
    )
  } // END parseOutput()

  def parseOutputAsterisks(volStr: String): Some[List[String]] = {
    Some( Source.fromString(volStr)
      .getLines
      .dropWhile( !_.contains("************") )
      .dropWhile( _.contains("************") )
      .toList
    )
  } // END parseOutput()

  def parseOutputDropHead(volStr: String): Some[List[String]] = {
    Some( Source.fromString(volStr)
      .getLines
      .toList
      .tail
    )
  } // END parseOutput()
  /**
    * seqParse()
    * Take an IndexedSeq, split each and we get get a Seq of Seqs.
    * @param volStrVector
    * @return Some[List[Vector[String]]]
    */
  def seqParse( volStrVector: List[String] ): Option[ List[Vector[String]] ] = {
    val splitResult = volStrVector.map( _.split("\\s+" ).toVector )

    return Some(splitResult)
  } // END seqParse()


} // END AutomateVolDiscovery object
