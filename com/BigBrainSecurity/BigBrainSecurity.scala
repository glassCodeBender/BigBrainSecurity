package com.BigBrainSecurity

/**
  * (@)Author: J. Alexander
  * (#)Version: 1.0
  * (#)Date: 6/11/2017
	*
  * PROGRAM PURPOSE: This is the driver program for Big Brain Security
	* forensics and IDS software.
	*
	* CONTAINS MAIN METHOD!
  */

/* Spark Imports */
import org.apache.hadoop.yarn.webapp.hamlet.HamletSpec.SELECT
import org.apache.spark.sql.functions._
import org.apache.spark.storage.StorageLevel
import org.apache.spark.sql.SparkSession

import scala.io.Source
import scala.collection.parallel.mutable.ParArray
import com.BigBrainSecurity.{ AnalyzePrefetch, CleanMFT, IntegrityCheck }
import org.apache.spark._

class BigBrainSecurity extends Setup {

	val spark = SparkSession.builder()
		.master("local")
		.appName("Big Brain Security")
		.enableHiveSupport()
		.getOrCreate()

	def main(args: Array[String]): Unit = run() // END main()

	/*************************FUNCTIONAL MAIN METHOD**************************/
	private def run(): Unit = {

		/***********************VARIABLE DECLARATIONS***************************/
		/* Create map of values from config file. */
		val configMap = super.getConfig()

		/* Find file locations from config.txt */
		val prefetchDirectory = configMap("prefetch_csv_directory_location").get
		val safePrefetchList = configMap("safe_prefetch_list").get

		/****************************MAIN METHOD CALLS***************************/

		/* Generate an Array of filenames that the user should check for tampering */
		private val analyzePrefResult: ParArray[String] = new AnalyzePrefetch(prefetchDirectory, safePrefetchList).analyze


		println("WARNING: Prefetch files from Windows 8 and 10 will give inaccurate results.\n"
		+ "Only files from Windows 7 systems and earlier will give accurate results. ")
		analyzePrefResult.foreach(println)

		/* Clean up MFT csv with CleanMFT.scala*/
		val cleanedMFT = new CleanMFT(spark, configMap)
		cleanedMFT.runCleanMFT

		/* IntegrityCheck.scala depends on the user's OS */

		/**
	  	* Analyze MFT - NEEDS IT'S OWN CLASS
	  	*/

		/*
		 * AnalyzeIntegrity - NEEDS IT'S OWN CLASS
		 */

		/**
	  	* Analyze Prefetch CSVs Directly  - NEEDS IT'S OWN CLASS
		  */

		/**
		  * Update JSON and dependent files Checksum.
	  	*/

		/**
			* JSON Functionality should be added to FileFun.scala
		  */

  } // END run()

} // END BigBrainSecurity class
