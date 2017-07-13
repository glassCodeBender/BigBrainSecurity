import java.io.{FileNotFoundException, IOException}

import com.BigBrainSecurity.FileFun

import scala.collection.mutable.ArrayBuffer
import scala.collection.parallel.mutable.ParArray
import scala.io.Source

/**
  * @author J. Alexander
  * @date July 13, 2017
  *      Program Purpose: Create an Array made up of Strings that will be
  *      converted to regular expressions that test for variations of common
  *      filenames.
  */

package com.BigBrainSecurity

import java.io.{ FileNotFoundException, IOException }

import scala.io.Source
import scala.collection.parallel.mutable.ParArray

object CommonFileVariations extends App with FileFun {

  /**
    * createArr()
    * Functional MAIN Method
    * @return ParArray[String] : An Array of Strings we'll convert to regex for testing filesystem.
    */
  def createArr(lookupFilename: String = "/Users/glassCodeBender/Documents/common_files.txt"): ParArray[String] = {

    val lookupFile = lookupFilename // Stores the file that contains the huge list of filenames

    /** Generate an Array made up of legitimate prefetch filenames. */
    val safePrefetchArray = processPrefFile(lookupFile).getOrElse(Array[String]())

    /** Create an Array made up of common system filenames. */
    val otherReg = """[A-Z0-9.]+""".r
    val commonFiles = safePrefetchArray.map(otherReg.findFirstIn(_).mkString).distinct

    // NOTE: Check the commonFiles Array and make sure the names aren't FQDNs.
    // If they are, write a regex to parse Array.

    /** Now we need to find all variations of the common filenames. Using a find replace on each String.
        We will use an ArrayBuffer that'll allow us to append the filenames quickly. */

    val commonFileVariationsArr = ArrayBuffer[String]()

    /** Create an array Buffer made up of Strings that we'll convert to regular expression.
      * We replace each character in each word w/ a regex that tests for variations of that word.
      * When we use the regexs, we'll need to make sure none of the results match any of
      * the strings in commonFiles ParArray after the test.
      */
    var i = 0
    while (i < commonFiles.length){
      var j = 0
      while(j < commonFiles(i).length){
        val str = commonFiles(i).charAt(j).toString
        // we might need to change this regex slightly to include more than one value
        commonFileVariationsArr +: commonFiles(i).replaceAll(str, "[0-9a-zA-Z]")
        j += 1
      } // END while
      i += 1
    } // END while to popular commonFileVariationsArr ArrayBuffer

    return commonFileVariationsArr.toParArray

    // Now we need to use this array to test against the MFT

  } // END createArr()
  /**
    * processPrefFile()
    * Imports file and runs a regex over it to extract prefetch file names
    * @param lookupFile
    * @return
    */
  def processPrefFile(lookupFile: String): Option[Array[String]] ={

    val reg = """[A-Z0-9]+.\w[-A-Z0-9]+.pf""".r

    try {
      Some( Source.fromFile ( lookupFile )
        .getLines
        .toArray
        .map ( reg.findFirstIn ( _ ).mkString )
      )
    } catch {
      case ioe: IOException =>
        println(ioe + s"There was a problem importing the file $lookupFile")
        None
      case fnf: FileNotFoundException =>
        println(fnf + s"The file you tried to $lookupFile import could not be found")
        None
    } // END try/catch
  } // END processPrefFile()

} // END CommonFileVariations object
