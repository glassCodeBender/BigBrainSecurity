package com.BigBrainSecurity

/**
	* (@)Author: glassCodeBender
	* (#)Version: 1.0
	* (#)Date: 5/8/2017
	*
	* PROGRAM PURPOSE: Test critical files and see if changes have been made.
	*/

import com.twitter.hashing.KeyHasher
import java.nio.file.{Files, Paths}
import java.security.MessageDigest

import scala.collection.immutable.{HashMap, TreeMap}
import scala.collection.parallel.mutable.ParArray
import scala.math.Ordering

// THIS WORKS. Only change checksum method.
object HashGenerator{
	def generate( path: String ): String = {
		val byteArray = Files.readAllBytes( Paths get path )
		val checksum = MessageDigest.getInstance( "SHA-256" ) digest byteArray
		checksum.map( "%02X" format _ ).mkString
	}
	def makeTwitterHash( fileName: String ): Long = {
		// in order to do this method, the genMap method must change back
		// to (new File(*))
		val byteArray = Files.readAllBytes(Paths get fileName)
		KeyHasher.FNV1_32.hashKey(byteArray) } // this is a test. The algorithm was not chosen yet.
} // END HashGenerator

object IntegrityCheck extends FileFun {

	/** ********************************************RUN METHOD **************************************************/
	def run ( ): Unit = {

		/* These values should be set by the configuration files */
		val userList = getAllDirs ( "/Users" )
		val systemList = getAllDirs ( "/System" )
		val appList = getAllDirs ( "/Applications" )
		val libList = getAllDirs ( "/Library" )

		val fullDirArray: Array[ String ] = ( ( userList ++ systemList ) ++ ( appList ++ libList ) )
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

		def getAllFiles ( directories: Array[ String ] ): Array[ String ] = {
			def loop ( dir: Array[ String ], accArray: Array[ String ] ): Array[ String ] = {
				if ( dir.isEmpty ) accArray
				else loop ( dir.tail, accArray ++ super.getFileArray ( dir.head ) )
			}
			loop ( directories, Array [ String ]( ) )
		} // END getAllFiles()

		/** ****************************************STORE IN Hash Table *******************************************************/
		/**
		 * Methods to create Maps from filename Strings to their SHA-256 hash values.
		 */
		def genMap ( fileSet: Seq[ String ] ): HashMap[ String, String ] = {
			def loop ( fileSet: Seq[ String ], accMap: HashMap[ String, String ] ): HashMap[ String, String ] = {
				// val hashMapAcc = new HashMap(fileSet.head -> makeHash(fileSet.head))
				if ( fileSet.isEmpty ) accMap
				else loop ( fileSet.tail, accMap + ( fileSet.head -> HashGenerator.generate ( fileSet.head ) ) )
			} // END loop()
			loop ( fileSet, new HashMap[ String, String ]( ) )
		} // END genMap()

		def genTreeMap ( fileSet: Seq[ String ] )( implicit ord: Ordering[ String ] ): TreeMap[ String, String ] = {
			def loop ( fileSet: Seq[ String ], accTreeMap: TreeMap[ String, String ] ): TreeMap[ String, String ] = {
				if ( fileSet.isEmpty ) accTreeMap
				else loop ( fileSet.tail, accTreeMap + ( fileSet.head -> HashGenerator.generate ( fileSet.head ) ) )
			} // END loop()
			loop ( fileSet, new TreeMap[ String, String ]( ) )
		} // END genTreeMap()
  
		def genTreeMapTwitter ( fileSet: Seq[ String ] )( implicit ord: Ordering[ String ] ): TreeMap[ String, Long ] = {
			def loop ( fileSet: Seq[ String ], accTreeMap: TreeMap[ String, Long ] ): TreeMap[ String, Long ] = {
				if ( fileSet.isEmpty ) accTreeMap
				else loop ( fileSet.tail, accTreeMap + ( fileSet.head -> HashGenerator.makeTwitterHash ( fileSet.head ) ) )
			} // END loop()
			loop ( fileSet, new TreeMap[ String, Long ]( ) )
		} // END genTreeMapTwitter()

}// END IntegrityCheck.scala
