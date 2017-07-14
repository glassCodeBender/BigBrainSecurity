package com.BigBrainSecurity.vol.windows

/**
  * @author J. Alexander
  * @date July 13, 2017
  * @version 1.0
  *
  *      Program Purpose: Automate volatility discovery commands and
  *      store them in variables that we can parse and use in another program.
  */

/**
  * @author J. Alexander
  * @date July 13, 2017
  * @version 1.0
  *
  *      Program Purpose: Automate volatility discovery commands and
  *      store them in variables that we can parse and use in another program.
  */

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
case class ToAudit(pid: List[Int], name: List[String], hexAD: List[String], info: List[String])

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
    // DO VARIETY OF PROCESS SCANS
    // If you see False in the splits column, there’s a problem.
    val psxview = s"python vol.py -f $memFile --profile=$os psxview —apply-rules" !!

    // list processes in memory.
    val psList = s"python vol.py -f $memFile --profile=$os pslist" !!
    val psScan = s"python vol.py -f $memFile --profile=$os psscan" !!

    // Make list of big pool allocations and sort based on tag frequency (145)
    val bigPools = s"python vol.py -f $memFile --profile=$os bigpools" !!
    val bigPoolsByFreq = s"awk '{print  $2}' $bigPools | sort | uniq -c | sort -rn" !!

    // find command histories
    val cmdScan = s"python vol.py -f $memFile --profile=$os cmdscan" !!
    val cmdOutput = s"python vol.py -f $memFile --profile=$os consoles" !!

    // locate windows service records
    val svcScan = s"python vol.py -f $memFile --profile=$os svcscan" !!

    // environmental variables scan
    val envVars = s"python vol.py -f $memFile --profile=$os envars" !!

    // Only gives privileges that a process specifically enabled
    val priv = s"python vol.py -f $memFile --profile=$os privs --silent" !!

    /** Extract all executables in the active process
      * This can also be written with a regex flag */
    val execInProcList = s"python vol.py -f $memFile --profile=$os procdump" !!




  } // END run()


} // END AutomateVolDiscovery object


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
case class ToAudit(pid: List[Int], name: List[String], hexAD: List[String], info: List[String])

/** Stores all of the raw data we discovered. This class will be returned from main. */
case class Discovery(proc: Process, pool: Pool, history: History, audit: ToAudit)

object AutomateVolDiscovery extends App{

  /**
    * NOTE: This is the information discovery script.
    * After the information is discovered, we need another script that
    * passes each PID into another program
    * Example: `python vol.py getsids -p @pid`
    */
  def run(os: String, memFile: String): Discovery = {

    /** ************************ PERFORM VOLATILITY SCANS **************************/
    // DO VARIETY OF PROCESS SCANS
    // If you see False in the splits column, there’s a problem.
    val psxview = s"python vol.py -f $memFile --profile=$os psxview —apply-rules" !!

    // list processes in memory.
    val psList = s"python vol.py -f $memFile --profile=$os pslist" !!
    val psScan = s"python vol.py -f $memFile --profile=$os psscan" !!

    // Make list of big pool allocations and sort based on tag frequency (145)
    val bigPools = s"python vol.py -f $memFile --profile=$os bigpools" !!
    val bigPoolsByFreq = s"awk '{print  $2}' $bigPools | sort | uniq -c | sort -rn" !!

    // find command histories
    val cmdScan = s"python vol.py -f $memFile --profile=$os cmdscan" !!
    val cmdOutput = s"python vol.py -f $memFile --profile=$os consoles" !!

    // locate windows service records
    val svcScan = s"python vol.py -f $memFile --profile=$os svcscan" !!

    // environmental variables scan
    val envVars = s"python vol.py -f $memFile --profile=$os envars" !!

    // Only gives privileges that a process specifically enabled
    val priv = s"python vol.py -f $memFile --profile=$os privs --silent" !!

    /** Extract all executables in the active process
      * This can also be written with a regex flag */
    val execInProcList = s"python vol.py -f $memFile --profile=$os procdump" !!




  } // END run()


} // END AutomateVolDiscovery object
