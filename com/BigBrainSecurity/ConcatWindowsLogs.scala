package com.BigBrainSecurity

import scala.annotation.tailrec
import scala.io.Source

import org.apache.spark.sql
import org.apache.spark.sql.functions.lit // used for creating columns

/**
  * @author J. Alexander
  * @version 1.0
  * @date 2017-6-20
  *
  *      Description: Program reads a list of csv log files from a directory and
  *      combines the files into a single file so that they can be processed
  *      as a single table.
  *
  *      This program is a part of Big Brain Security, a digital forensics
  *      automation program and intrusion detection system.
  */

class ConcatWindowsLogs extends FileFun {

  /**
    * concatDF()
    * Description: Does all the work
    * @param dirName Directory location of log CSVs
    * @return DataFrame made up of all CSV logs
    */
  def concatDF(dirName: String) = {

    /* Create an array of event log CSV files. */
    val logCSVs = super.getFileArray ( dirName )
    /* Take every log file and turn it into a single DataFrame */
    val fullDF = concatDF(logCSVs: _*)

    return fullDF
  } // END concatDF()

  /**
    * concatDF()
    * Creates a single DataFrame by reading in all files in a directory.
    * @param logs accepts Array of Strings
    * @example concatDF(logCSVs: _*)
    * @return
    */
  def concatDF(logs: String*): DataFrame = {

    /* convert from sequence to array. */
    val logList = logs.toList

    /* take first member of array and create DataFrame */
    val df = spark.read.format ( "com.databricks.spark.csv" )
      .option ( "header", "true" )
      .option ( "inferSchema", "true")
      .load ( logList.head )
    /* Add a column to df to make it easier to join. */
    val baseDF = df.withColumn("Project", lit("BBS"))

    /** Recursive helper function for concatDF */
    @tailrec
    def loop(accDF: DataFrame, logList: List[String]): DataFrame = {
      val updateCSV = addMessageHeader(logList.head)
      /* Create a DataFrame for the csv we want to join */
      val loopDF = spark.read.format ( "com.databricks.spark.csv" )
        .option ( "header", "true" )
        .option ( "inferSchema", "true")
        .load ( updateCSV )

      /* This is the DataFrame we want to join w/ original on "Project" */
      val rightDF = loopDF.withColumn("Project", lit("BBS"))

      // need to filter rightDF to remove innocuous entries before join.

      if (logList.isEmpty) accDF
      else {
        val updateDF = accDF join(rightDF, accDF("Project") === nextDF("Project") )
        loop(updateDF, logList.tail)
      } // END if/else
    } // END loop()

    loop(baseDF, logList.tail)
  } // END concatDF()

  /**
    * addMessageHeader()
    * Description: Add "Message" column header to standard log output.
    * @param fileName
    * @return
    */
  def addMessageHeader(fileName: String): List[String] = {
    val logList: List[String] = Source.fromFile(fileName).getLines.toList
    val updatedHead: String = logList.head + ",Message"
    val updatedList: List[String] = updatedHead :: logList.tail

    return updatedList
  } // END addMessageHeader()

  /** For most analysis we can use groupBy($"LogName") */

} // END ConcatLogs class
