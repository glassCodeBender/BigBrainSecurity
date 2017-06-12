package com.BigBrainSecurity

/**
  * (@)Author: glassCodeBender
  * (#)Version: 1.0
  * (#)Date: 6/11/2016
  *
	* CONTAINS MAIN METHOD!!
	*
  * PROGRAM PURPOSE: This is the driver program for Big Brain Security
	* forensics and IDS software.
  */

import org.apache.hadoop.yarn.webapp.hamlet.HamletSpec.SELECT
import org.apache.spark.sql.SQLContext
import org.apache.spark.sql.functions._ // needed to do a lot of things (unix_timestamp)
import org.apache.spark.storage.StorageLevel
/* Example: df.persist(StorageLevel.MEMORY_AND_DISK) */

import scala.io.Source
import org.apache.spark.sql.SparkSession

class BigBrainSecurity extends Setup {

	val spark = SparkSession
		.builder
		.appName("Big Brain Security")
		.getOrCreate()

	def main(args: Array[String]): Unit = {

		/* Create map of values from config file. */
	  val configMap = super.getConfig()

		/* Find file locations from config.txt */
		val mftTable = configMap("mft_csv_location")
		val regexTxtFile = configMap("text_file_with_values_to_include_in_output")
		val prefetchDirectory = configMap("prefetch_csv_directory_location")
		val outputCSVName = configMap("filtered_csv_output_location")
		val allCSVDir = configMap("all_csv_output_destination_directory")

		/* Take config.txt input and place values in variables.  */
		val createIntIndex: Boolean =  configMap("create_integer_index").toBoolean
		val filterSupicious: Boolean = configMap("filter_suspicious").toBoolean
		val defaultFilter: Boolean = configMap("default_filter").toBoolean

		// This is how this program will be used in the rest of the program.
		val startIndex = configMap("start_index")
		val endIndex = configMap("end_index")
		val startTime = configMap("start_time")
		val endTime = configMap("end_time")

	/** Import and update variables using config file */
	run()

	} // END main()

	def run(): Unit = {

	/** Run Integrity Check */

	/** Check Prefetch Files */

	/** Clean MFT Table */

	/** Analyze MFT */

	/** Analyze Prefetch Files Directly */

	/** Update JSON and dependent files Checksums */

  } // END run()




} // END BigBrainSecurity class
