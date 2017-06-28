package com.BigBrainSecurity

import java.io.{ FileNotFoundException, IOException }

import org.apache.hadoop.yarn.webapp.hamlet.HamletSpec.SELECT
import org.apache.spark
import org.apache.spark.sql.functions._
import org.apache.spark.sql.SQLContext
import org.apache.spark.sql.SparkSession
import org.apache.spark.storage.StorageLevel // needed to change how persist() caches data.
/* Example: df.persist(StorageLevel.MEMORY_AND_DISK) or MEMORY_ONLY */

import scala.io.Source

/**
	* @author: J. Alexander
	* @date: June 10, 2017
	* @version: 1.0
	*
	*          Program Purpose: This program takes the cleanMFT.py
	*          project I wrote with pandas DataFrames and applies
	*          the program's principals to large scale big data
	*          environments with Apache Spark.
	*/

class CleanMFT extends Setup {

	/**
		* runCleanMFT()
		* This method does all the work.
		* @return Unit
		*/
	def runCleanMFT (spark: SparkSession): Unit = {

		/** Get a map of configurations for the program from Setup.scala */
	  val configMap = super.getConfig()

		/* Find file locations from config.txt */
		val importFile = configMap("mft_csv_location")
		val regexFile = configMap("text_file_with_values_to_include_in_output")
		val outputName = configMap("filtered_csv_output_location")
		val allCSVDir = configMap("all_csv_output_destination_directory")

		/* Take config.txt input and place values in variables.  */
		val filterIndex: Boolean =  configMap("create_integer_index").toBoolean
		val suspicious: Boolean = configMap("filter_suspicious").toBoolean
		val defFilter: Boolean = configMap("default_filter").toBoolean

		/* Locations to filter by */
		lazy val startIndex = configMap("start_index")
		lazy val endIndex = configMap("end_index")
		lazy val startTime = configMap("start_time")
		lazy val endTime = configMap("end_time")
		lazy val startDate = configMap("start_date")
		lazy val endDate = configMap("end_date")

		// Need to check and make sure that the importFile exists

		/* import csv file and convert it into a DataFrame */
		val csvDF = spark.read.format ( "com.databricks.spark.csv" )
			.option ( "delimiter", "|" )
			.option ( "header", true )
			.option ( "inferSchema", true )
			.load ( importFile )

		/* Concatenate Date and Time to create timestamps. Retain columns w/ useful information. */
		csvDF.createOrReplaceTempView("DataFrame")
		val df = spark.sql("""
				SELECT CONCAT(Date, Time) AS Date_Time, MACB, Filename,
				Desc, Type, Source, Short, SourceType, Inode, Timezone, User
				FROM DataFrame
		  	""" )

		/**
			* TIMESTOMPING CHECKER CALL!!!
			*/

		/* Filter DataFrame by index location */
		if ( startIndex != None || endIndex != None )
		val indexDF = indexFilter( df, startIndex, endIndex )

		/* Filter DataFrame to only include EXEs outside System32 or Program Files */
		if ( suspicious == true ) {
			val suspiciousDF = {
				if ( indexDF != None ) filterSuspicious( indexDF )
				else filterSuspicious( df )
			} // END val suspiciousDF
		} // END if (suspicious)

		/* Filter DataFrame by list of Strings (Regex) */
		if ( !regexFile.isEmpty ) {
			val regDF = {
				if ( suspiciousDF != None ) filterByFilename( suspiciousDF )
				else if ( indexDF != None ) indexDF
				else df
			} // END val regDF
		} // END if(regexFile)

		/* Stores the current state of the DataFrame */
		val theDF: DataFrame = {
			if ( regDF != None ) regDF
			else if ( suspiciousDF != None ) suspiciousDF
			else if ( indexDF != None ) indexDF
			else df
		} // END theDF

		/* Take user input and convert it into a timestamp(s) */
		if ( startDate != None || endDate != None || startTime != None || endTime != None ) {

			/* Create Start and Stop Timestamps for filtering */
			val (startStamp, endStamp) = makeTimeStamp( startDate.mkString, endDate.mkString, startTime.mkString, endTime.mkString )
      /* generate current state of DataFrame when filtering by timestamp. */
			val dateDF = filterByDate( theDF, startStamp, endStamp )
		} // END if statement filter by date

	  /* Filter DataFrame with default filter */
	  if (defFilter) {
			if(dateDF != None) val finalDf = defaultFilter(dateDF)
			else val finalDF = defaultFilter(theDF)
	} // END if

		/*
		 * THIS PROGRAM NEEDS TO OUTPUT CSV FILES AT SOME POINT.
		 */

		/* Save the processed Data to a compressed file. */
		if (finalDF.isEmpty) {
			if (dateDF != None) dateDF.saveAsSequenceFile(allCSVDir)
			else theDF.saveAsSequenceFile(allCSVDir)
			System.exit(0)
		} // END finalDF.isEmpty
		finalDF.saveAsSequenceFile(allCSVDir)

	} // END runCleanMFT()
	/********************************END OF THE DRIVER PROGRAM *********************************/
	/*******************************************************************************************/
	/*******************************************************************************************/

	/**
		* makeTimeStamp()
		* Takes data with separate time and date columns and converts them into unix_timestamps
		*
		* @param startDate starting date
		* @param endDate   end date
		* @param startTime start time
		* @param endTime   end time
		* @return (unix_timestamp, unix_stamp) - Tuple with both timestamps
		*/
	def makeTimeStamp ( startDate: String, // starting date
	                    endDate: String, // end date
	                    startTime: String, // start time
	                    endTime: String // end time
	                  ) = {
		val start = ( startDate.mkString + " " + startTime.mkString )
		val end = ( endDate.mkString + " " + endTime.mkString )

		/*Create Start and Stop Timestamps for filtering */
		val startStamp: unix_timestamp = start
		val endStamp: unix_timestamp = end

		return (startStamp, endStamp) // returns tuple with start and end timestamps
	} // END makeTimeStamp()

	/**
		* indexFilter()
		* Filters a DataFrame based on start and ending index locations.
		*
		* @param df     DataFrame
		* @param sIndex Start Index
		* @param eIndex End Index
		* @return DataFrame
		*/
	def indexFilter ( df: DataFrame, // Accepts a DataFrame.
	                  sIndex: Int,   // Integer value that represents starting index.
	                  eIndex: Int    // Integer value that represents the end index.
	                ): DataFrame = {

		df.registerTempTable("DataFrame")

		val indexDF = spark.sql (
			"""SELECT * FROM DataFrame WHERE Index > sIndex && Index < eIndex""")

		return indexDF
	} // END indexFilter()

	/**
		* defaultFilter()
		* Filters DataFrame to only include the following extensions: .exe|.dll|.rar|.sys|.jar.
		* Program also remove rows that are not helpful for forensics.
		* @param DataFrame
		* @return DataFrame
		*/
	def defaultFilter(df: DataFrame): DataFrame = {
		val regexExt = ".exe$|.dll$|.rar$|.sys$|.jar$|.ps1$|.psd1$|" +
									 ".psm1$|.vb$|.cs$|.vbs$|.cpp$|.cp$|.sh$"

		val updatedDF = df.filter( $"Type" === "File Modified")
			.filter( $"Type" === "MFT Entry" )
			.filter($"Desc" rlike regexExt)
	  return updatedDF
} // END defaultFilter()

	/**
		* filterByFilename()
		* Filters a MFT csv file that was converted into a DataFrame to only include relevant extensions.
		*
		* @param df DataFrame
		* @return DataFrame - Filter df to only include relevant file extensions.
		* @throws IOException explains why certain common behaviors occurs
		*/
	def filterByFilename ( df: DataFrame ): DataFrame = {
		val pattern = updateReg ( regexFile )  // String pattern => Regex
		val filteredDF = df.filter( $"Desc" rlike pattern )

		return filteredDF
	} // END filterByFilename()

	/**
		* filterSuspicious()
		* Filters a MFT so that only the executables that were run outside Program Files are
		* included in the table.
		*
		* @param df DataFrame
		* @return DataFrame - Filtered to only include relevant file extensions.
		*/
	def filterSuspicious ( df: DataFrame ): DataFrame = {

		/* matches all Strings that ran in Program Files or System32 */
		// val regexSys32 = """^.+(Program\sFiles|System32).+[.exe]$"""

    /* Filter the table based on the suspicious criteria. */
		val filterDF = df.filterNot( $"Desc" rlike "^.+(Program\sFiles|System32).+[.exe]$" )
			.filter( $"Desc" rlike ".exe$" )

		return filterDF
	} // END filterSuspicious()

	/**
		* findTimestomp()
		* Filter to locate Timestomp
		* @param df DataFrame
		* @return DataFrame - Filtered to only include relevant file extensions.
		*/
	def findTimestomping ( df: DataFrame ): DataFrame = {
	  // Add Index
		/* matches all Strings that ran in Program Files or System32 */
		val regexSys32 = "^.+(Program\sFiles|System32).+[.exe]$"
	  /* Filter so only files that were born are included. */
		val filteredDF = df.filter($"MACB" === "B")
			.filterNot($"Short" === "FN2")
			.filterNot($"Desc" rlike regexSys32)
			.filter($"Desc" rlike ".exe$")

		return filteredDF
} // END findTimestomping()

	/**
		* filterByDate()
		* Filters a MFT csv file that was converted into a Dataframe to only include the
		* occurrences of certain dates and/or times.
		*
		* @param df    DataFrame
		* @param sDate String - Start Date
		* @param eDate String - End Date
		* @return DataFrame - Filtered to only include relevant virus names.
		*/
	def filterByDate ( df: DataFrame,
	                   sDate: unix_timestamp,
	                   eDate: unix_timestamp
	                 ): DataFrame = {
    /* Create SQL Table*/
		df.registerTempTable("DataFrame")

	/* Filter by Query */
		val dateDF = spark.sql ( """
														SELECT * FROM DataFrame
														WHERE Date_Time >= sDate AND Date_Time =< eDate
		                         """)
		return dateDF
	} // END filterByDate()

	/**
		* updateReg()
		* Filters a list of words and concatenate them into a regex.
		*
		* @param fileName String made up of words provided by users to filter table with.
		* @forExample Concatenates each line of a text file into a regular expression.
		* @return Regex
		*/
	def updateReg ( fileName: String ): String = {

		/* import file - this can also be imported directly into a DataFrame */
		val regArray = Source.fromFile ( fileName )
				.getLines
				.toArray
				.map ( _.trim )
				.par

		/* concatenate each member of the array to make String */
		val regexString = regArray.fold ( "" )( ( first, second ) => first + "|" + second ).par

	  return regexString.mkString
	} // END updateReg()

} // END CleanMFT.scala
