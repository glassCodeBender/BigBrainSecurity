package com.BigBrainSecurity

import java.io.{ FileNotFoundException, IOException }

import scala.io.Source
import scala.collection.parallel.mutable.ParArray

/**
	* @Author: J. Alexander
	* @Date 6/6/2017
	* @Version 1.0
	*
	* IMPORTANT NOTE: This program only works for Windows 7 and earlier. I'm not sure which
	* version of Windows Server this goes up to.
	*
	* Program Purpose: This program looks at a directory full of prefetch files and locates
	* inconsistencies.
	*
	* NOTE: The list of safe prefetch filenames was obtained here:
	* http://www.hexacorn.com/blog/2012/06/13/prefetch-hash-calculator-a-hash-lookup-table-xpvistaw7w2k3w2k8/
	*/

object AnalyzePrefetch extends FileFun {

	/**
		* analyze()
		* Functional MAIN Method
		* @param prefetchDir: String - Stores the directory that contains the prefetchfiles.
		*         lookupFile: String - Stores the full qualified domain name connected to the
	  *         text file with the huge list of possible file names (from hexacorn.com).
	  * @return ParArray[String] : Also prints to console.
		*/

	def analyze(prefetchDir: String, // Stores the directory that contains the prefetch files.
	            lookupFile: String): ParArray[String] = { // Stores the file with the huge list of possible file names.

		val prefetchDirectory = prefetchDir  // stores prefetch directory location

		/** Generate an Array made up of legitimate prefetch filenames. */
		val safePrefetchArray = processPrefFile(lookupFile).getOrElse(ParArray[String]())

		/* Create an Array made up of common system filenames. */
		val otherReg = """[A-Z0-9.]+""".r
		val commonFiles = safePrefetchArray.map(otherReg.findFirstIn(_).mkString)
			.distinct
			.toArray
			.par

		/*  import all of the prefetch files from a directory. */
		val systemPrefetchFiles = super.getAllFiles(Array(prefetchDirectory)).par

		/* filter out the prefetch files that we have hash values for. */
		val matchArray = systemPrefetchFiles.filter(x => commonFiles.exists(y => x.contains(y))).par

		/* filter out the prefetch files that are not in the safePrefetchList */
		val scaryFiles = matchArray.filter(x => safePrefetchArray.exists(y => x.contains(y))).par

		// Use the scaryFiles Array to determine which csv files need to be queried and appended to one another
		// for further assessment.

		/* For solo use, the program prints results to a console. */
		println("Go to the prefetch directory and examine the following prefetch files:")
		println()
		scaryFiles.foreach(println)

		return scaryFiles
	} // END analyze()
	/**
		* processPrefFile()
		* Imports file and runs a regex over it to extract prefetch file names
		* @param lookupFile
		* @return
		*/
	def processPrefFile(lookupFile: String): Option[ParArray[String]] ={
		val reg = """[A-Z0-9]+.\w[-A-Z0-9]+.pf""".r
		try {
			Some(Source.fromFile ( lookupFile )
				.getLines
				.toArray
				.map ( reg.findFirstIn ( _ ).mkString )
				.par)
		} catch {
			case ioe: IOException =>
				println(ioe + s"There was a problem importing the file $lookupFile")
				None
			case fnf: FileNotFoundException =>
				println(fnf + s"The file you tried to $lookupFile import could not be found")
				None
			} // END try/catch
		} // END processPrefFile()

} // END AnalyzePrefetch
