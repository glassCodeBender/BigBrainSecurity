package com.BigBrainSecurity

/**
  * @author j. Alexander
  * @date 7/5/17
  * @version 1.0
  *
  *      Program Purpose: Implements Big Brain Security on Windows 8 and later.
  */
class BBSWindows10(val configMap: Map[String, Option[String]]) {

  /* Clean up MFT csv with CleanMFT.scala*/
  val cleanedMFT = new CleanMFT(spark, configMap)
  cleanedMFT.runCleanMFT

} // END BBSWindows10 class
