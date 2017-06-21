package com.BigBrainSecurity

// Needed to create a custom schema for program.
import org.apache.spark.sql.types.{StructType, StructField, StringType, IntegerType}

/**
	* @author J. Alexander
	* @version 1.0
	* @date 2017-6-20
	*
	*      Description: Program reads a list of csv log files from a directory and
	*      combines the files into a single file so that they can be processed
	*      as a single table.
	*      
	*      This program is a part of Big Brain Security. A digital forensics 
	*      automation program and intrusion detection system.
	*/
class ConcatLogs extends FileFun {

	// Needed to create a custom schema for program.
	import org.apache.spark.sql.types.{StructType, StructField, StringType, IntegerType}

	val logSchema = new StructType( Array(StructField("Message", StringType, true),
			StructField("Id", StringType, true),
			StructField("Version", StringType, true),
			StructField("Qualifiers", StringType, true),
			StructField("Level", StringType, true),
			StructField("Task", StringType, true),
			StructField("Opcode", StringType, true),
			StructField("Keywords", StringType, true),
			StructField("RecordId", StringType, true),
			StructField("ProviderName", StringType, true),
			StructField("ProviderId", StringType, true),
			StructField("LogName", StringType, true),
			StructField("ProcessId", StringType, true),
			StructField("ThreadId", StringType, true),
			StructField("MachineName", StringType, true),
			StructField("UserId", StringType, true),
			StructField("TimeCreated", StringType, true),
			StructField("ActivityId", StringType, true),
			StructField("RelatedActivityId", StringType, true),
			StructField("ContainerLog", StringType, true),
			StructField("MatchedQueryIds", StringType, true),
			StructField("Bookmark", StringType, true),
			StructField("LevelDisplayName", StringType, true),
			StructField("OpcodeDisplayName", StringType, true),
			StructField("TaskDisplayName", StringType, true),
			StructField("KeywordsDisplayNames", StringType, true),
			StructField("Properties", StringType, true)) )

	val appDF = spark.read.format("com.databricks.spark.csv")
			.option("header", "true")
			.option("mode", "DROPMALFORMED")
			.schema(logSchema)
			.load("/FileStore/tables/o9j9x9su1498013687588/Application.csv")

	val sysDF = spark.read.format("com.databricks.spark.csv")
			.option("header", "true")
			.option("mode", "DROPMALFORMED")
			.schema(logSchema)
			.load("/FileStore/tables/o9j9x9su1498013687588/System.csv")

	/** Add a new column to each DataFrame called "Project" w/ a String project name */

	/**
		* Create a method that accepts a variable number of args from Array format.
		* The method will then loop through the arguments and create new DataFrames
		* and then join them w/ the other DataFrames to create one large DF.
		*
		* Must include way of generating new variable names for each DF unless we
		* recursively loop through the log files and join the previous DF to the
		* main DF.
		*/

	/** For most analysis we can use groupBy($"LogName") */

} // END ConcatLogs class
