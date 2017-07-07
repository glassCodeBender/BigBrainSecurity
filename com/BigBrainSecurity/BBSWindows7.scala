package com.BigBrainSecurity

/**
  * @author j. Alexander
  * @date 7/5/17
  * @version 1.0
  *      Program Purpose: Implements Big Brain Security on Windows 7 or earlier.
  */
class BBSWindows7(val configMap: Map[String, Option[String]]) {

  /* Find file locations from config.txt */
  val prefetchDirectory = configMap("prefetch_csv_directory_location").get
  val safePrefetchList = configMap("safe_prefetch_list").get

  /* Generate an Array of filenames that the user should check for tampering */
  private val analyzePrefResult: PrefResults = new AnalyzePrefetch(id,
    prefetchDirectory,
    safePrefetchList).analyze

  println("WARNING: Prefetch files from Windows 8 and 10 will give inaccurate results.\n"
    + "Only files from Windows 7 systems and earlier will give accurate results. ")
  analyzePrefResult.scaryFiles.foreach(println)

  /* Clean up MFT csv with CleanMFT.scala*/
  val cleanedMFT = new CleanMFT(spark, configMap)
  cleanedMFT.runCleanMFT
} // END BBSWindows7 class
