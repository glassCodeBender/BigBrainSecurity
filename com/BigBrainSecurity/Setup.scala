package com.BigBrainSecurity

import scala.io.Source

/**
	* @author glassCodeBender
	* @date 2017-June-10
	* @version 1.0
	*
	*          Program Purpose: A utility program used to configure the
	*          Intrusion Detection System (IDS) setting.
	*
	*          This program will be used by many BigBrainSecurity classes.
	*/

trait Setup {

	/**
		* getConfig()
		* This section of the program does most of the work.
		* @return Unit
		*/
	def getConfig(): Map[String, String] = {

		/* Stores location of the config file for program*/
		val configLoc = "Users/glassCodeBender/Documents/ConfigFileStorage/config.txt"

		/* Read pre-written config file from disk */
		val config: Array[ String ] = Source.fromFile(configLoc)
			.getLines
			.toArray
			.filter( _.contains("#") )

		val integrityConfirmed: Boolean = checkConfigIntegrity(configLoc)

		var configMap = Map[String, String]
		for { value <- config
		      configMap += value.split ( "~>" ).map(_.trim).mkString
		} // END for (populate configMap)
		val finalMap = configMap.asInstanceOf[Map[String, String]]

		return finalMap // END for fullConfigMap val
	} // END getConfig()

	/**
		* checkConfigIntegrity()
		* Evaluate checksum for config file and compare it to previous checksum
		* @param String config.txt location in filesystem.
		* @return Boolean
		*/

	def checkConfigIntegrity(configLoc: String): Boolean = {

		var matchBool = false // This is the value the method returns

		// Current config.txt file checksum:
		// WARNING: THIS IS WRONG! THIS IS THE MD5 CHECKSUM. Sorry. No Internet.
		// Maybe the program should ask the user if they updated the config file.

		/* Stores current and previous checksums for config.txt */
		val previousChecksum = "d3fc163cb17a50c8d2352cb39269d28c"
		val configNewChecksum = HashGenerator.generate(configLoc)

		/* This doesn't help the program if there is no way to update previousChecksum.
		 * Can we set up a password protected file and write a program to access the protected
		 * file. Inside the protected file we can store previous checksums in JSON files.
		 */

		if (configNewChecksum.equals(previousChecksum)){
			println("No changes were made to the config file sense the previous configuration.")
			matchBool = true
		}
		else{
			println("A change was made in the configuration file since the last time you ran this program.")
			println("If you did not change the config.txt file, please review your settings here: " + configLoc )
			matchBool = false
		} // END if/else

		return matchBool
	} // END checkConfigIntegrity()

	/*
	* What should be configured?
	* Everything but file locations.
	* */

} // END Setup trait
