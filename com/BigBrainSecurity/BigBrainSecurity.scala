package com.BigBrainSecurity

/**
  * (@)Author: J. Alexander
  * (#)Version: 1.0
  * (#)Date: 7/3/2017
	*
	* CASE CLASSES:
	* Brain
	* Findings
	* Registration
	* User
	* Technical
	*
	* MAIN CLASS BigBrainSecurity
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

/**
	* case class Brain
	* Purpose: Contains the raw data from a single time the program run.
	* This is the data that is sent over from the client.
	* Eventually the brain will communicate w/ a program that analyzes
	* raw memory dumps.
	* @param id primary key
	* @param dateTime primary key Stores current date.
	* @param name contains user's name
	* @param mftCSV contains the mft in csv format
	* @param regCSV contains registry in csv format.
	* @param prefResults Contains a newline separated list of scary files
	*/
case class Brain( id: Int,                                   // primary key
                  dateTime: java.util.Date = java.util.Date, // primary key
                  name: String,                              // contains user's name
                  mftCSV: String,                            // contains the mft in csv format
                  regCSV: String,                            // contains registry in csv format.
                  prefResults: String                        // contains any extra information.
                ){}

/**
	* case class Findings
	* Purpose: Contains information discovered from the assessment
	* of the raw data.
	* @param id primary key
	* @param dateTime primary key Stores current date.
	* @param mft MFTAssessment Data resulting from assessment.
	* @param registry RegAssessment Data from registry assesment
	* @param prefetch PrefAssessment Data from prefetch assessment
	*/

case class Findings( id: Int,                                   // primary key
                     dateTime: java.util.Date = java.util.Date, // primary key
                     mft: MFTAssessment,                        // contains result of MFTAssessment
                     registry: RegAssessment,                   // contains result of Registry Assessment
                     prefetch: PrefAssessment                   // contains result of Prefetch Assessment
                   ){}

/**
	* case class Registration
	* Purpose: Contains information about the client
	* @param id primary key
	* @param dateTime primary key Stores current date.
	* @param user User A String name of the user/organization.
	* @param tech Int The IP address & tech info about client
	* @param dir String Stores location of BigBrainSecurity on client.
	*/
case class Registration( id: Int,                               // primary key
                         dateTime: java.util.Date = java.util.Date, // primary key
												 user: User,                            // name of user/organization
                         tech: Technical,                       // client's technical details
											   dir: String                            // location where user runs program from.
												){}

/**
	* case class User
	* Purpose: Contains information about the client
	* @param id Primary key Integer ID
	* @param address Array[String] user/organization address
	* @param phone Int Client's
	*/
case class User( id: Int,                       // primary key
                 address: Array[String],        // name of user/organization
                 phone: Int,                    // client's technical details
                 badStatus: Boolean = false     // location where user runs program from.
                       ){}
/**
	* case class Technical
	* Purpose: Contains technical information about the client
	* @param id Primary key Integer ID
	* @param ip Int The IP address of the client
	* @param port Int The port the client receives at.
	*/
case class Technical( val id: Int,
                      val ip: Int,
                      val port: Int,
                      val whateverelse: String){}

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
