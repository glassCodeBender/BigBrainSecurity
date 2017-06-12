package com.BigBrainSecurity

import scala.io.Source
import scala.collection.parallel.mutable.ParArray

/**
	* @Author: glassCodeBender
	* @Date 6/6/2017
	* @Version 1.0
	*
	* Note: This program only works for Windows 7 and earlier. I'm not sure which
	* version of Windows Server this goes up to.
	*
	* Other note: This class should almost exclusively use collections made up of
	* String objects.
	*
	* Program Purpose: This program looks at a directory full of prefetch files and locates
	* inconsistencies.
	*
	* Note: The list of safe prefetch filenames was obtained here:
	* http://www.hexacorn.com/blog/2012/06/13/prefetch-hash-calculator-a-hash-lookup-table-xpvistaw7w2k3w2k8/
	*/

object AnalyzePrefetch extends FileFun with Setup {

	/**
		* MAIN METHOD
		* @params prefetchDir: String - Stores the directory that contains the prefetchfiles.
		*         lookupFile: String - Stores the full qualified domain name connected to the
	  *         text file with the huge list of possible file names (from hexacorn.com).
	  * @return Unit : prints to console.
		* */

	def analyze(prefetchDir: String, // Stores the directory that contains the prefetch files.
	            lookupFile: String): ParArray[String] = { // Stores the file with the huge list of possible file names.

		val prefetchDirectory = prefetchDir  // stores prefetch directory location

		/** Generate an Array made up of legitimate prefetch filenames.
			* An array is used because arrays are good for parallel processing. */
		val reg = """[A-Z0-9]+.\w[-A-Z0-9]+.pf""".r
		val safePrefetchArray = {
			Source.fromFile(lookupFile)
				.getLines
				.toArray
				.map(reg.findFirstIn(_).mkString)
				.par
		}

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
} // END AnalyzePrefetch
