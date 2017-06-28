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

/* Imports for web client */
import org.apache.commons.httpclient.NameValuePair
import java.io._
import org.apache.commons
import org.apache.http._
import org.apache.http.client._
import org.apache.client.methods.HttpPost
import org.apache.impl.client.DefaultHttpClient
import java.util.ArrayList
import org.apache.http.message.BasicNameValuePair
import org.apache.http.client.entity.UrlEncodedFormEntity
import org.google.gson.Gson
	
class BigBrainSecurity extends Setup {

	val spark = SparkSession
		.builder()
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
		val mftTable = configMap("mft_csv_location")
		val regexTxtFile = configMap("text_file_with_values_to_include_in_output")
		val prefetchDirectory = configMap("prefetch_csv_directory_location")
		val outputCSVName = configMap("filtered_csv_output_location")
		val allCSVDir = configMap("all_csv_output_destination_directory")
		val safePrefetchList = configMap("safe_prefetch_list")

		/* Take config.txt input and place values in variables.  */
		val createIntIndex: Boolean =  configMap("create_integer_index").toBoolean
		val filterSupicious: Boolean = configMap("filter_suspicious").toBoolean
		val defaultFilter: Boolean = configMap("default_filter").toBoolean

		// This is how this program will be used in the rest of the program.
		lazy val startIndex = configMap("start_index")
		lazy val endIndex = configMap("end_index")
		lazy val startTime = configMap("start_time")
		lazy val endTime = configMap("end_time")

		/****************************MAIN METHOD CALLS***************************/

		/* Generate an Array of filenames that the user should check for tampering */
		private val analyzePrefResult: ParArray[String] = AnalyzePrefetch.analyze(prefetchDirectory, safePrefetchList)

		/* Clean up MFT csv with CleanMFT.scala*/
		val cleanedMFT = new CleanMFT(spark)
		cleanedMFT.runCleanMFT()

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
/*
object HttpJsonPost extends App {

	/**
		*
		* Will probably need to use Lift-JSON library instead of GSON
		* because classes are complex. Maybe...
		*
		* What do we need to send to the client for processing?
		* Logs
		* MFT CSV
		*
	  */

	// create object as a JSON String
	val bbs = BBSWeb()
	val testAsJson = new Gson().toJson(information)

	// add name value pairs to a post object
	val post = new HttpPost("http://localhost:8080/posttest")
	val nameValuePairs = new ArayList[NameValuePair]()
	nameValuePairs.add(new BasicNameValuePair("JSON", testAsJson))
	post.setEntity(new UrlEncodedFormEntity(nameValuePairs))

	// send the post request
	val client = new DefaultHttpClient
	val response = client.execute(post)
	println("--- HEADERS ---")
	response.getAllHeaders.foreach(args => println(args))

} // END HttpJsonPost class
*/
