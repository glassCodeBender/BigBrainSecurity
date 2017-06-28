package com.BigBrainSecurity

import java.io.{ FileNotFoundException, IOException }

import scala.io.Source

/**
	* @author J. Alexander
	* @date 2017-6-10
	* @version 1.0
	*
	*          Program Purpose: A utility program used to configure the
	*          Intrusion Detection System (IDS) setting. This program reads
	*          a config file and returns package com.BigBrainSecurity

import java.io.{ FileNotFoundException, IOException }

import scala.io.Source

/**
	* @author J. Alexander
	* @date 2017-6-10
	* @version 1.0
	*
	*          Program Purpose: A utility program used to configure the
	*          Intrusion Detection System (IDS) setting. This program reads
	*          a config file and returns a map made up of keys and values.
	*/

trait Setup {

	/**
		* getConfig()
		* This section of the program does most of the work.
		* @return Map[String, String]
		*/
	def getConfig(): Map[String, Some[String]] = {

		/* Stores location of the config file for program*/
		val configLoc = "Users/glassCodeBender/Documents/BigBrainSecurity/config.txt"

		/* Read pre-written config file from disk */
		val config: Option[Array[ String ]] = try {
			Some(Source.fromFile ( configLoc )
				.getLines
				.toArray
				.filterNot (_.contains ( "#" )) )
		} 	catch{
			case ioe: IOException =>
				println(ioe + s"There was a problem importing the file $configLoc.")
				None
			case fnf: FileNotFoundException =>
				println(fnf + s"The file you tried to $configLoc import could not be found")
				None
		} // END try/catch

		val configData = config.get

    /* compares hash value of past and current config file. Returns boolean. */
		val integrityConfirmed: Boolean = checkConfigIntegrity(configLoc)

		val configArray: Array[String] = configData.flatMap(x => x.split ( "~>" )).map(_.trim)

		/* Populate Map with variables that correspond to program settings */
		var counter: Int = 0
		var configMap = Map[String, Some[String]]()

		while (configArray.length > counter){
				configMap += ( configArray ( counter ) -> Some(configArray (counter + 1)) )
			  counter = counter + 2
		} // END while populate configMap

		return configMap
	} // END getConfig()

	/**
		* checkConfigIntegrity()
		* Evaluate checksum for config file and compare it to previous checksum
		* @param configLoc: String - config.txt location in filesystem.
		* @return Boolean
		*/

	def checkConfigIntegrity(configLoc: String): Boolean = {

		var matchBool = false // This is the value the method returns

		// Current config.txt file checksum:
		// WARNING: THIS IS WRONG! THIS IS THE MD5 CHECKSUM. Sorry. No Internet.
		// Maybe the program should ask the user if they updated the config file.

		/* Stores current and previous checksums for config.txt */
		/* NEED TO FIND A WAY TO UPDATE CHECKSUM. Once value is set, it stays set. */
		val previousChecksum = "d3fc163cb17a50c8d2352cb39269d28c" // SAMPLE: THIS IS MD5
		val configNewChecksum = HashGenerator.generate(configLoc)

		/*
		 * This doesn't help the program if there is no way to update previousChecksum.
		 * Can we set up a password protected file and write a program to access the protected
		 * file. Inside the protected file we can store previous checksums in JSON files.
		 */

		if (configNewChecksum.equals(previousChecksum)){
			println("No changes were made to the config file since the previous configuration.")
			matchBool = true
		}
		else{
			println("A change was made in the configuration file since the last time you ran this program.")
			println("If you did not change the config.txt file, please review your settings here: " + configLoc )
			matchBool = false
		} // END if/else

		return matchBool
	} // END checkConfigIntegrity()

} // END Setup traita map made up of keys and values.
	*/

trait Setup {

	/**
		* getConfig()
		* This section of the program does most of the work.
		* @return Map[String, String]
		*/
	def getConfig(): Some[Map[String, String]] = {

		/* Stores location of the config file for program*/
		val configLoc = "Users/glassCodeBender/Documents/BigBrainSecurity/config.txt"

		/* Read pre-written config file from disk */
		val config: Option[Array[ String ]] = try {
			Some(Source.fromFile ( configLoc )
				.getLines
				.toArray
				.filterNot (_.contains ( "#" )) )
		} 	catch{
			case ioe: IOException =>
				println(ioe + s"There was a problem importing the file $configLoc.")
				None
			case fnf: FileNotFoundException =>
				println(fnf + s"The file you tried to $configLoc import could not be found")
				None
		} // END try/catch

		val configData = config.getOrElse( Array[String]() )

    /* compares hash value of past and current config file. Returns boolean. */
		val integrityConfirmed: Boolean = checkConfigIntegrity(configLoc)

		val configArray: Array[String] = configData.flatMap(x => x.split ( "~>" )).map(_.trim)

		/* Populate Map with variables that correspond to program settings */
		var counter: Int = 0
		var configMap = Map[String, String]()

		while (configArray.length > counter){
				configMap += ( configArray ( counter ) -> configArray ( counter + 1 ) )
			  counter = counter + 2
		} // END while populate configMap

		return Some(configMap)
	} // END getConfig()

	/**
		* checkConfigIntegrity()
		* Evaluate checksum for config file and compare it to previous checksum
		* @param configLoc: String - config.txt location in filesystem.
		* @return Boolean
		*/

	def checkConfigIntegrity(configLoc: String): Boolean = {

		var matchBool = false // This is the value the method returns

		// Current config.txt file checksum:
		// WARNING: THIS IS WRONG! THIS IS THE MD5 CHECKSUM. Sorry. No Internet.
		// Maybe the program should ask the user if they updated the config file.

		/* Stores current and previous checksums for config.txt */
		/* NEED TO FIND A WAY TO UPDATE CHECKSUM. Once value is set, it stays set. */
		val previousChecksum = "d3fc163cb17a50c8d2352cb39269d28c" // SAMPLE: THIS IS MD5
		val configNewChecksum = HashGenerator.generate(configLoc)

		/*
		 * This doesn't help the program if there is no way to update previousChecksum.
		 * Can we set up a password protected file and write a program to access the protected
		 * file. Inside the protected file we can store previous checksums in JSON files.
		 */

		if (configNewChecksum.equals(previousChecksum)){
			println("No changes were made to the config file since the previous configuration.")
			matchBool = true
		}
		else{
			println("A change was made in the configuration file since the last time you ran this program.")
			println("If you did not change the config.txt file, please review your settings here: " + configLoc )
			matchBool = false
		} // END if/else

		return matchBool
	} // END checkConfigIntegrity()

} // END Setup trait
