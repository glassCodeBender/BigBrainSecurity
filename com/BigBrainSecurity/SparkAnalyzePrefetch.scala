package com.BigBrainSecurity

import java.sql.Timestamp

import org.apache.spark.sql.SQLContext

/**
	* Created by xan0 on 6/1/17.
	*/
trait CleanMFT {

	val importFile = "Aria/Users/Xan0/Downloads/supers.csv"
	val indexBool = true
	val filterIndex =
  val regexFile = "Aria/Users/Xan0/Downloads/files-to-filter.txt"
	val suspicious = false
	val startDate = None
	val endDate = None
	val startTime = None
	val endTime = None


	/*
	 * Variables other program requires:
        self.__suspicious = suspicious
        self.__start_date = start_date  # accepts a date to filter
        self.__end_date = end_date
        self.__start_time = start_time  # accepts a time to filter
        self.__end_time = end_time
        self.__output_file = output_filename
        self.__index_bool = index_bool          # a boolean to determine if a numbered index should be added.
        self.__filter_index = filter_index
	 *
	 */

	val pd = new SQLContext(sc)
	val df = pd.read.format("com.databricks.spark.csv").option("header" = true).option("inferSchema", true).load(fullyQualifiedFileLoc)


}
