package com.BigBrainSecurity

import scala.annotation.tailrec

// Needed to create a custom schema for program.
import org.apache.spark.sql.types.{ IntegerType, StringType, StructField, StructType }

import org.apache.spark.sql
import org.apache.spark.sql.functions.lit // used for creating columns

/**
	* @author J. Alexander
	* @version 1.0
	* @date 2017-6-20
	*
	*      NOTE: This program was written to interact w/ log files output by a
	*      popular forensics program. The CSV files I wrote the schema for were
	*      given to me for a forensics competition.
	*
	*      Description: Program reads a list of csv log files from a directory and
	*      combines the files into a single file so that they can be processed
	*      as a single table.
	*
	*      This program is a part of Big Brain Security, a digital forensics
	*      automation program and intrusion detection system.
	*/

class ConcatNCACLogs extends FileFun {

	/**
		* concatDF()
		* Description: Does all the work
		* @param dirName Directory location of log CSVs
		* @return DataFrame made up of all CSV logs
		*/
	def concatDF(dirName: String) = {

		val logSchema = new StructType ( Array ( StructField ( "Message", StringType, true ),
			StructField ( "Id", StringType, true ),
			StructField ( "Version", StringType, true ),
			StructField ( "Qualifiers", StringType, true ),
			StructField ( "Level", StringType, true ),
			StructField ( "Task", StringType, true ),
			StructField ( "Opcode", StringType, true ),
			StructField ( "Keywords", StringType, true ),
			StructField ( "RecordId", StringType, true ),
			StructField ( "ProviderName", StringType, true ),
			StructField ( "ProviderId", StringType, true ),
			StructField ( "LogName", StringType, true ),
			StructField ( "ProcessId", StringType, true ),
			StructField ( "ThreadId", StringType, true ),
			StructField ( "MachineName", StringType, true ),
			StructField ( "UserId", StringType, true ),
			StructField ( "TimeCreated", StringType, true ),
			StructField ( "ActivityId", StringType, true ),
			StructField ( "RelatedActivityId", StringType, true ),
			StructField ( "ContainerLog", StringType, true ),
			StructField ( "MatchedQueryIds", StringType, true ),
			StructField ( "Bookmark", StringType, true ),
			StructField ( "LevelDisplayName", StringType, true ),
			StructField ( "OpcodeDisplayName", StringType, true ),
			StructField ( "TaskDisplayName", StringType, true ),
			StructField ( "KeywordsDisplayNames", StringType, true ),
			StructField ( "Properties", StringType, true ) ) )

		/*
		val appDF = spark.read.format ( "com.databricks.spark.csv" )
			.option ( "header", "true" )
			.option ( "mode", "DROPMALFORMED" )
			.schema ( logSchema )
			.load ( "/FileStore/tables/o9j9x9su1498013687588/Application.csv" )

		val sysDF = spark.read.format ( "com.databricks.spark.csv" )
			.option ( "header", "true" )
			.option ( "mode", "DROPMALFORMED" )
			.schema ( logSchema )
			.load ( "/FileStore/tables/o9j9x9su1498013687588/System.csv" )
		*/

		/* Create an array of event log CSV files. */
		val logCSVs = super.getFileArray ( dirName )
		/* Take every log file and turn it into a single DataFrame */
		val fullDF = concatDF(logSchema, logCSVs: _*)

		return fullDF
} // END concatDF()

	/**
		* concatDF()
		* Creates a single DataFrame by reading in all files in a directory.
		* @param schema StructType Used to make sure all CSVs have same schema.
		* @param logs accepts Array of Strings
		* @example concatDF(logCSVs: _*)
		* @return
		*/
	def concatDF(schema: StructType, logs: String*): DataFrame = {

		/* convert from sequence to array. */
		val logArray = logs.toArray

		/* take first member of array and create DataFrame */
		val df = spark.read.format ( "com.databricks.spark.csv" )
			.option ( "header", "true" )
			.option ( "mode", "DROPMALFORMED" )
			.schema ( schema )
			.load ( logArray.head )
		/* Add a column to df to make it easier to join. */
		val baseDF = df.withColumn("Project", lit("BBS"))

		/** Recursive helper function for concatDF */
		@tailrec
		def loop(accDF: DataFrame, logArray: Array[String]): DataFrame = {
			/* Create a DataFrame for the csv we want to join */
			val loopDF = spark.read.format ( "com.databricks.spark.csv" )
				.option ( "header", "true" )
				.option ( "mode", "DROPMALFORMED" )
				.schema ( schema )
				.load ( logArray.head )

			/* This is the DataFrame we want to join w/ original on "Project" */
			val rightDF = loopDF.withColumn("Project", lit("BBS"))

			// need to filter rightDF to remove innocuous entries before join.

			if (logArray.isEmpty) accDF
			else {
				val updateDF = accDF join(rightDF, accDF("Project") === nextDF("Project") )
				loop(updateDF, logArray.tail)
			} // END if/else
		} // END loop()
		loop(baseDF, logArray.tail)
	} // END concatDF()

	/** For most analysis we can use groupBy($"LogName") */

} // END ConcatLogs class
