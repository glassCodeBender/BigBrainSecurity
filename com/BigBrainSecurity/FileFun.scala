package com.BigBrainSecurity

import java.io.{BufferedWriter, File, FileWriter}
import java.nio.file.{Paths}
import java.time.LocalDate
import com.google.common.io.Files
import scala.io.Source

/**
	* Purpose: This program will be used in other classes for common file operations.
	*/
trait FileFun {
	/*******Function takes a single String and writes it to a file that is generated based on the fileTreeMap***********/
	def writeToTxtFile(txt: String, fileName: String): Unit = {
		val file = new File( fileName )            // Create a file where we'll store hash values.
		val bw = new BufferedWriter(new FileWriter(file))
		bw.write(txt)
		bw.close()
	} // END writeToTxtFile()

	/*********************************Method reads txt file and converts it into a String*******************************/
	def readTxtFromFile(filename: String): String = {
		Source.fromFile(filename)
			.getLines
			.mkString   // read all of the lines from the file as one String.
		// this technique does not close the file.
	} // END readTxtFromFile()

	/********************CONVERT DIRECTORY TO LIST OF SUB-ITEMS****************************
		*       Methods accept a String directory name & converts to List or Seq of Strings.      *                                                       *
		**************************************************************************************/
  // DO NOT CHANGE!!!
	def getDirArray(directoryName: String): Array[String] = {
		( new File(directoryName) ).listFiles.filter(_.isDirectory).map(_.getAbsolutePath)
	}

	// DO NOT CHANGE!!!
	def getDirList(directoryName: String): List[String] = {
		( new File(directoryName) ).listFiles.filter(_.isDirectory).map(_.getAbsolutePath).toList
	}

	// DO NOT CHANGE!!!
	def getDirVector(directoryName: String): Array[String] = {
		( new File(directoryName) ).listFiles.filter(_.isDirectory).map(_.getAbsolutePath).toVector
	}
	// I'm removing the filter so that this method will get a list of all directories and files.
	def getFileList(dirName: String): List[String] = {
		( new File(dirName) ).listFiles.map(_.getAbsolutePath).toList
	}
  // DO NOT CHANGE!!!!
	def getFileArray(directoryName: String): Array[String] = {
		( new File(directoryName) ).listFiles.filter(_.isFile).map(_.getAbsolutePath)
	}

	/**
		* Need a method that goes through a list of directories, makes a list of directories,
		* and appends it to the main list of directories.
		* If this method is difficult to write, write it as a for loop and then change it to recursion.
		* @param dir: Accepts a directory to start from.
		*/

  // DO NOT CHANGE!!!
	def getAllDirs(dir: String): Array[String] = {
		val dirList = getDirArray(dir)
		def loop(directories: Array[String], accList: Array[String]): Array[String] = {
			if(directories.isEmpty) accList
			else loop(directories.tail, accList ++: getDirArray(directories.head))
		}
		loop(dirList, Array[String]())
	}
  // DO NOT CHANGE!!!
	def getAllFiles(directories: Seq[String]): Array[String] = {
		def loop(dir: Seq[String], accArray: Array[String]): Array[String] = {
			if (dir.isEmpty) accArray
			else loop(dir.tail, accArray ++: getFileArray(directories.head))
		}
		loop(directories, Array[String]())
	} // END getFullFileList

	def fullFileList(directories: Array[String]) = directories.fold(Array[String]()){ (x, y) => x ++= getFileArray(y) }

	/***************GENERATE STRING TO USE FOR FILENAMES***************************
		*   Each time a method calls one of the methods below, they should also     *
		*   increment a counter and add that number to the beginning of the String. *
		******************************************************************************/
	def generateJSONFileName(str: String): String = {
		// This filename generation technique makes it difficult to compare imported files.
		val dateGen = new LocalDate()
		return String.format("JSON%s", dateGen.toString)
	} // END generateFileName()

	def generateTxtFileName(str: String): String = {
		// This filename generation technique makes it difficult to compare imported files.
		val dateGen = new LocalDate()

		return String.format("Txt%s", dateGen.toString)
	} // END generateFileName()

	// convert a file to a Byte Array
	def fileToByteArray(file: String): Array[Byte] = Files.toByteArray(new File(file) )

} // END FileFun.scala
