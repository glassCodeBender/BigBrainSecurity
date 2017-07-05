package com.BigBrainSecurity

import java.nio.file.Paths
import java.security.MessageDigest

import com.twitter.hashing.KeyHasher

import scala.collection.immutable.{ HashMap, List, TreeMap, Vector }

/**
	* (@)Author: J. Alexander
	* (#)Version: 1.0
	* (#)Date: 5/8/2017
	*
	* MAIN CLASS: MacIntegrityCheck.scala
	* case class IntegrityResults
	* Helper Object: HashGenerator.scala
	*
	* PROGRAM PURPOSE: To test critical files and see if changes have been made.
	*/

/**
	* case class IntegrityResults
	* Description: Stores information about changes to the file system.
	* @param id Integer Primary Key
	* @param date java.util.Date Primary Key
	* @param changedFiles Vector[String] Contains all files whose hashes didn't match
	* @param changedDirs Vector[String] Contains all directories that changed.
	* @param removedFiles Vector[String] Contains all files that were removed.
	* @param suspiciousChanges List[String] Contains all irregular file changes.
	*/
case class IntegrityResults( id: Int,
                             date: java.util.Date = java.util.Date,
                             changedFiles: Vector[String],
                             changedDirs: Vector[String],
                             removedFiles: Vector[String],
                             suspiciousChanges: List[String])
// THIS WORKS. Only change checksum method.


class IntegrityCheck(config: Map[ String, Option[String] ]) extends FileFun {
	val os = config("operating_system").map(_.toUpperCase)

	/* Run IntegrityCheck based on the client's OS. */
	val result = os match {
		case Some("WINDOWS") => WinIntegrityCheck.run()
		case Some("WINDOWS10") => Win10IntegrityCheck.run()
		case Some("MAC") => MacIntegrityCheck.run()
		case None => {
			println("The user must input an operating system type if they wish to check\n" +
			"the integrity of their operating system's file system.\n" +
			"Please review config.txt to ensure that there is no # sign before the operating" +
			"system they wish to have analyzed. ")
			System.exit(0)
		}
	} // END result (OS match)

} // END IntegrityCheck class
object Win10IntegrityCheck extends FileFun {
	def run():Unit ={

	} // END run()
}  // END Win10IntegrityCheck object

object WinIntegrityCheck extends FileFun {
	def run(): Unit = {

	}
} // END WinIntegrityCheck object

object MacIntegrityCheck extends FileFun {

	/** ********************************************RUN METHOD **************************************************/
	def run ( ): Unit = {

		/* Get all directories on MacOS */
		val userList = super.getAllDirs ( "/Users" )
		val systemList = super.getAllDirs ( "/System" )
		val appList = super.getAllDirs ( "/Applications" )
		val libList = super.getAllDirs ( "/Library" )

		/* Create a single Array  */
		val fullDirArray: Array[ String ] = ( ( userList ++ systemList ) ++ ( appList ++ libList ) )

		val newDirHashes: TreeMap[ String, Some[String] ] = genTreeMap( fullDirArray )
		// If this program is going to run on parallel cores, one of the TreeMaps needs to get split up and
		// the other other TreeMap should stay intact. This ensures that all of the comparisons work.
		// During the comparisons we should extract the values that were not presents or that do not match into new Tree.

		/* Generate hash values and store them in a TreeMap or HashMap. Both methods are shown so I can compare time. */

		/* Import previous JSON file and store previous values in a Map */

		/* Compare the previous Map's hash values to the new Map's values */

		/* Import main.com.paranoidking.BigBrainSecurity config file and check the file's checksum to ensure integrity. */

		/* Import main.com.paranoidking.BigBrainSecurity Log File and date for previous log based on data in the config file. */

		/* Export new Map and concatenate the result of Integrity Check. */
	} // END run()
		// DO NOT CHANGE!!!!
		def getAllFiles (directories: Array[String]): Array[String] = {
			def loop (dir: Array[String], accArray: Array[String] ): Array[String] = {
				if ( dir.isEmpty ) accArray
				else loop ( dir.tail, accArray ++ super.getFileArray( dir.head ).getOrElse( Array[String]() ))
			}
			loop ( directories, Array [String]() )
		} // END getAllFiles()

		/** ***************************** STORE IN DATA STRUCTURE *************************************/
		/*
		 * Methods to create Maps from filename Strings to their hash values.
		 * Currently SHA-256 is used for the checksums, but the algorithm might change.
		 */
		def genMap (fileSet: Seq[String]): HashMap[ String, Some[String] ] = {
			def loop (fileSet: Seq[String], accMap: HashMap[ String, Some[String] ]): HashMap[ String, Some[String] ] = {
				// val hashMapAcc = new HashMap(fileSet.head -> makeHash(fileSet.head))
				if ( fileSet.isEmpty ) accMap
				else loop ( fileSet.tail, accMap + ( fileSet.head -> Some( HashGenerator.generate(fileSet.head) )))
			} // END loop()
			loop ( fileSet, new HashMap[ String, Some[String] ]( ) )
		} // END genMap()

		def genTreeMap (fileSet: Seq[String])(implicit ord: Ordering[String]): TreeMap[ String, Some[String] ] = {
			def loop (fileSet: Seq[String], accTreeMap: TreeMap[ String, Some[String] ]): TreeMap[ String, Some[String] ] = {
				if ( fileSet.isEmpty ) accTreeMap
				else loop ( fileSet.tail, accTreeMap + ( fileSet.head -> Some( HashGenerator.generate(fileSet.head) )))
			} // END loop()
			loop ( fileSet, new TreeMap[ String, Some[String] ]( ) )
		} // END genTreeMap()

		def genTreeMapTwitter ( fileSet: Seq[ String ] )( implicit ord: Ordering[String] ): TreeMap[ String, Some[Long] ] = {
			def loop ( fileSet: Seq[ String ], accTreeMap: TreeMap[ String, Some[Long] ] ): TreeMap[ String, Some[Long] ] = {
				if ( fileSet.isEmpty ) accTreeMap
				else loop ( fileSet.tail, accTreeMap + ( fileSet.head -> Some( HashGenerator.makeTwitterHash(fileSet.head) )))
			} // END loop()
			loop ( fileSet, new TreeMap[ String, Some[Long] ]( ) )
		} // END genTreeMapTwitter()

}// END MacIntegrityCheck.scala class

/**
	* object HashGenerator
	* Used to generate either SHA-256 hash or hash value using Twitter API.
	*/
object HashGenerator{
	def generate( fileName: String ): String = {
		val byteArray = java.nio.file.Files.readAllBytes( Paths get fileName )
		val checksum = MessageDigest.getInstance( "SHA-256" ) digest byteArray
		checksum.map( "%02X" format _ ).mkString
	} // END generate()
	def makeTwitterHash( fileName: String ): Long = {
		// in order to do this method, the genMap method must change back
		// to (new File(*))
		val byteArray = java.nio.file.Files.readAllBytes( Paths get fileName )
		KeyHasher.FNV1_32.hashKey(byteArray)
	} // END makeTwitterHash()
} // END HashGenerator
