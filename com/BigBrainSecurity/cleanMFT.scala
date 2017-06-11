package com.BigBrainSecurity

import java.io.IOException
import java.sql.Timestamp

import org.apache.hadoop.yarn.webapp.hamlet.HamletSpec.SELECT
import org.apache.spark.sql.SQLContext
import org.apache.spark.sql.functions._ // needed to do a lot of things (unix_timestamp)

import scala.io.Source

/**
	* @author: glassCodeBender
	* @date: June 10, 2017
	* @version: 1.0
	*
	*          Program Purpose: This program takes the cleanMFT.py
	*          project I wrote with pandas DataFrames and applies
	*          the program's principals to large scale big data
	*          environments with Apache Spark.
	*/

class CleanMFT extends Setup (val sqlContext: SQLContext,
													    val iFile: String,
                              val regFile: String,
                              val oFile: String ){

	/* Class will accept a SQLContext through it's constructor */
	val spark = sqlContext

	/* Read pre-written config file. The config file allows user to customize program. */
	val config = Source.fromFile("Users/CodeStalkersRUS/Documents/ConfigFileStorage/config.txt")
		.getLines
		.toArray
		.filterNot(_.contains("#"))

	/* Stores all the file locations the program uses. */
	private val importFile: String = iFile  // The fully qualified file name for the MFT Dump CSV.
	private val regexFile: String = regFile // A text file with different items on each line to use for filter.
	private val outputFile: String = oFile  // What should the csv file that is generated be named?

	/**
		* run()
		* This method does all the work.
		* @return Unit
		**/
	def run (): Unit = {

		/* String Filenames of different user input values. */
		val tableFile = importFile     // stores the csv file location
		val filterForRFile = regexFile // stores the user created list file location.
		val destFileName = outputFile  // stores the name the user wants to use for the destination file.

		/* Booleans to determine how the table should be filtered. */
		val filterIndex = false // Filter the index for some reason?
		val startIndex = None   // Value of the field that user wants to start filtering from.
		val endIndex = None     // Value of the field that user wants to stop filtering at.
		val indexBool = true    // Does the user want toadd
		val suspicious = false  // Filter any exe that ran outside of System32 or Program Files.

		/* These are used to create unix_timestamp objects. */
		val startDate = None // Filter from this start date.
		val endDate = None   // Filter until this end date.
		val startTime = None // Filter from this start time
		val endTime = None   // Filter until this end time.

		// WARNING!!!
		// No concatenation to create timestamps.
		/* import csv file and convert it into a DataFrame */
		val df = spark.read.format ( "com.databricks.spark.csv" )
			.option ( "delimiter", "|" )
			.option ( "header" = true )
			.option ( "inferSchema", true )
			.load ( importFile ).cache ( )

		/* Filter DataFrame by index location */
		if ( startIndex != None || endIndex != None )
		val indexDF = indexFilter ( df, startIndex, endIndex )

		/* Filter DataFrame to only include EXEs outside System32 or Program Files */
		if ( suspicious == true )
		val suspiciousDF = filterSuspicious (
			if ( indexDF != None ) filterSuspicious ( indexDF )
			else filterSuspicious ( df ) )

		/* Filter DataFrame by list of Strings (Regex) */
		if ( !regexFile.isEmpty ) {
			val regDF = {
				if ( suspiciousDF != None ) filterByFilename ( suspiciousDF )
				else if ( indexDF != None ) indexDF
				else df
			}
		} // END if regexFile

		/* Stores the current state of the DataFrame */
		val theDF: DataFrame = {
			if ( regDF != None ) regDF
			else if ( suspiciousDF != None ) suspiciousDF
			else if ( indexDF != None ) indexDF
			else df
		} // END theDF

		/* Take user input and convert it into a timestamp(s) */
		if ( startDate != None || endDate != None || startTime != None || endTime != None ) {

			/*Create Start and Stop Timestamps for filtering */
			val timeStamp = makeTimeStamp ( startDate.mkString, endDate.mkString, startTime.mkString, endTime.mkString )
      /* generate current state of DataFrame when filtering by timestamp. */
			val dateDF = filterByDate ( theDF, timeStamp._1, timeStamp._2 )
		} // END if statement filter by date

		/* Save the processed Data to a compressed file. */
		if ( dateDF != None ) dateDF.saveAsSequenceFile ( "Users/lupefiascoisthebestrapper/Documents/MFT" )
		else theDF.saveAsSequenceFile ( "Users/lupefiascoisthebestrapper/Documents/MFT" )

		// if option to filter by index is true where do we get the index locations?
		// probably a method.

	} // END run()
	/** ******************************END OF THE DRIVER PROGRAM **********************************/
	/** *****************************************************************************************/
	/** *****************************************************************************************/

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
	                  sIndex: Int, // Integer value that represents starting index.
	                  eIndex: Int // Integer value that represents the end index.
	                ): DataFrame = {

		df.registerTempTable("DataFrame")

		val indexDF = spark.sql ( SELECT * FROM DataFrame)

		return indexDF
		// DO SQL

	} // END indexFilter()

	def defaultFilter(df): DataFrame = {
	  reg = """Entry$|Modified$""".r
		updatedDF = df.map( reg.findAllIn($"Type") )

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
		val pattern = updateReg ( regexFile ).r  // String pattern => Regex
		val filteredDF = df.map ( pattern.findAllIn($"Desc") )

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
		val regexSys32 = """^.+(Program\sFiles|System32).+[.exe]$""".r
		val regexExe = """.exe$""".r // matches all Strings that end with .exe

    /* Filter the table based on the suspicious criteria. */
		val filtDF = df.map ( regexSys32.findAllIn($"Desc") ).cache()
		val filteredDF = filtDF.map(regexExe.findAllIn($"Desc" || $"File") )

		return filteredDF
	} // END filterSuspicious()

	/**
		* findTimestomp()
		* Filter to locate Timestomp
		* @param df DataFrame
		* @return DataFrame - Filtered to only include relevant file extensions.
		*/
	def findTimestomping ( df: DataFrame ): DataFrame = {
	  // Add Index
	  // Filter for Born
	  // Filter
	  /* matches all Strings that ran in Program Files or System32 */
  	val regexSys32 = """^.+(Program\sFiles|System32).+[.exe]$""".r
	  val regexExe = """.exe$""".r // matches all Strings that end with .exe

} // END findTimestomping()


	/**
		* filterByDate()
		* Filters a MFT csv file that was converted into a Dataframe to only include the
		* occurrences of certain dates and/or times.
		*
		* @param df    DataFrame
		* @param sDate String
		* @param eDate String
		* @return DataFrame - Filtered to only include relevant virus names.
		*/
	def filterByDate ( df: DataFrame,
	                   sDate: unix_timestamp,
	                   eDate: unix_timestamp
	                 ): DataFrame = {
    /* Create SQL Table*/
		df.registerTempTable("DataFrame")

	/* Filter by Query */
		val dateDF = spark.sql ( SELECT *
	                           FROM DataFrame
	                           WHERE $Date_Time >= sDate AND $Date_Time =< eDate )

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
		// import file - this can also be imported directly into a DataFrame
		val regArray = Source.fromFile ( fileName )
			.getLines.toArray
			.map ( _.trim )
			.par

		// concatenate each member of the array to make String
		val regexString = regArray.fold ( "" )( ( first, second ) => first + "|" + second ).par

	  return regexString.mkString
	} // END updateReg()

} // END CleanMFT.scala

	/*****************************************************************************************/
	/*****************************************************************************************/
	/*****************************************************************************************/
	/*****************************************************************************************/
	/*****************************************************************************************/
	/*************************** THIS IS THE END OF THE PROGRAM ******************************/
	/*****************************************************************************************/
	/*****************************************************************************************/
	/*****************************************************************************************/
	/*****************************************************************************************/
	/*****************************************************************************************/
	/*****************************************************************************************/
	/*****************************************************************************************/
	/*****************************************************************************************/
	/*****************************************************************************************