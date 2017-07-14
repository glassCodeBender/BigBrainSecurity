package com.BigBrainSecurity.vol

/**
  * Program Purpose: Analyzes volatility results and returns useful info.
  */

import scala.io.Source

class AnalyzeVolResults( val discovery: Discovery ) {

  /** Stores each individual object from Discovery case class */
  val process: Process = discovery.proc    // (psxview, psScan, psList, execInProcList)
  val pool: Pool = discovery.pool          // (bigPools, bigPoolByFreq)
  val history: History = discovery.history // (cmdScan, svcScan, envVars)
  val audit: ToAudit = discovery.audit     // (pid, name, hexAD, info) Each is List

  /**
    * Look through each row of processes and look for one that contains False
    * NOTE: Might need to convert to CSV first (Replace tabs w/ commas to make
    * CSV so it's easier to look for specific values in columns)
    */
  val foundProcDiscrepancies = Source.fromString( process.psxview )
    .getLines
    .map( _.contains( "False" ) )
    .toArray
    .par



} // END AnalyzeVolResults class
