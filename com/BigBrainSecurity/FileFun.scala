package com.BigBrainSecurity

import java.io._
import java.time.LocalDate

import java.nio.file.Files

import scala.io.Source

/**
  * trait FileFun.scala
  * Purpose: This program will be used in other classes for common file operations.
  */
trait FileFun {
  /*******Function takes a single String and writes it to a file that is generated based on the fileTreeMap***********/
  def writeToTxtFile(txt: String, fileName: String): Unit = {
    val file = new File( fileName )            // Create a file where we'll store hash values.
    val bw = new BufferedWriter( new FileWriter(file) )
    bw.write(txt)
    bw.close()
  } // END writeToTxtFile()

  /*********************************Method reads txt file and converts it into a String*******************************/
  def readTxtFromFile(fileName: String): Option[String] = {
    try {
      Some(Source.fromFile ( fileName ).getLines.mkString) // read all of the lines from the file as one String.
    } catch {
      case ioe: IOException =>
        println ( s"There was a problem importing the file $fileName.\n" + ioe )
        None
      case fnf: FileNotFoundException =>
        println ( s"The file you tried to $fileName import could not be found\n" + fnf )
        None
    } // END try/catch
  } // END readTxtFromFile()

  /********************CONVERT DIRECTORY TO LIST OF SUB-ITEMS****************************
    *    Methods accept a String directory name & converts to List or Seq of Strings    *
    *************************************************************************************/
  // DO NOT CHANGE!!!
  def getDirArray(directoryName: String): Option[Array[String]] = {
    try {
      Some( ( new File ( directoryName ) ).listFiles
        .filter ( _.isDirectory )
        .map ( _.getAbsolutePath ) )
    }
    catch{
      case ioe: IOException =>
        println(ioe + s"There was a problem importing the file $directoryName.")
        None
      case fnf: FileNotFoundException =>
        println(fnf + s"The file you tried to $directoryName import could not be found")
        None
    } // END try/catch
  } // END getDirArray()

  // DO NOT CHANGE!!!
  def getDirList(directoryName: String): Option[List[String]] = {
    try {
      Some(( new File ( directoryName ) ).listFiles
        .filter ( _.isDirectory )
        .map ( _.getAbsolutePath )
        .toList)
    } catch{
      case ioe: IOException =>
        println(ioe + s"There was a problem importing the file $directoryName.")
        None
      case fnf: FileNotFoundException =>
        println(fnf + s"The file you tried to $directoryName import could not be found")
        None
    }  // END try/catch
  }

  // DO NOT CHANGE!!!
  def getDirVector(directoryName: String): Option[Vector[String]] = {
    try{
      Some(( new File(directoryName) ).listFiles
        .filter(_.isDirectory)
        .map(_.getAbsolutePath)
        .toVector)
    }
    catch{
      case ioe: IOException =>
        println(ioe + s"There was a problem importing the file $directoryName.")
        None
      case fnf: FileNotFoundException =>
        println(fnf + s"The file you tried to $directoryName import could not be found")
        None
    }  // END try/catch
  }
  // I'm removing the filter so that this method will get a list of all directories and files.
  def getFileList(dirName: String): Option[List[String]] = {
    try{
      Some(( new File(dirName) ).listFiles
        .map(_.getAbsolutePath)
        .toList)
    } catch{
      case ioe: IOException =>
        println(ioe + s"There was a problem importing the file $dirName.")
        None
      case fnf: FileNotFoundException =>
        println(fnf + s"The file you tried to $dirName import could not be found")
        None
    } // END try/catch

  }
  // DO NOT CHANGE!!!!
  def getFileArray(directoryName: String): Option[Array[String]] = {
    try {
      Some ( ( new File ( directoryName ) ).listFiles
        .filter ( _.isFile )
        .map ( _.getAbsolutePath ) )
    }  catch{
      case ioe: IOException =>
        println(ioe + s"There was a problem importing the file $directoryName.")
        None
      case fnf: FileNotFoundException =>
        println(fnf + s"The file you tried to $directoryName import could not be found")
        None
    } // END try/catch
  }

  def getFileVector(directoryName: String): Option[Vector[String]] = {
    try {
      Some ( ( new File ( directoryName ) ).listFiles
        .filter ( _.isFile )
        .map ( _.getAbsolutePath )
        .toVector )
    }	catch{
      case ioe: IOException =>
        println(ioe + s"There was a problem importing the file $directoryName")
        None
      case fnf: FileNotFoundException =>
        println(fnf + s"The file you tried to $directoryName import could not be found")
        None
    } // END try/catch
  } // getFileVector()

  /**
    * Need a method that goes through a list of directories, makes a list of directories,
    * and appends it to the main list of directories.
    * If this method is difficult to write, write it as a for loop and then change it to recursion.
    * @param dir: Accepts a directory to start from.
    */

  // DO NOT CHANGE!!!
  // SEE IntegrityCheck.scala to add Options to these methods.
  def getAllDirs(dir: String): Array[String] = {
    val dirList = getDirArray(dir).getOrElse(Array[String]())
    def loop(directories: Array[String], accList: Array[String]): Array[String] = {
      if(directories.isEmpty) accList
      else loop(directories.tail, accList ++: getDirArray(directories.head).get)
    }
    loop( dirList, Array[String]() )
  } // END getAllDirs()

  // DO NOT CHANGE!!!
  def getAllDirsList(dir: String): List[String] = {
    val dirList = getDirList ( dir ).getOrElse(List[String]())

    def loop ( directories: List[ String ], accList: List[ String ] ): List[ String ] = {
      if ( directories.isEmpty ) accList
      else loop ( directories.tail, accList ++: getDirList ( directories.head ).getOrElse( List[String]() ))
    }

    loop ( dirList, List[String]() )
  } // END getAllDirsList()

  // DO NOT CHANGE!!!
  def getAllDirsVector(dir: String): Vector[String] = {
    val dirList = getDirVector ( dir ).getOrElse(Vector[String]())

    def loop ( directories: Vector[ String ], accList: Vector[ String ] ): Vector[ String ] = {
      if ( directories.isEmpty ) accList
      else loop ( directories.tail, accList ++: getDirVector ( directories.head ).getOrElse( Vector[String]() ))
    }
    loop ( dirList, Vector[String]() )
  }
  // DO NOT CHANGE!!!
  def getAllFiles(directories: Seq[String]): Array[String] = {
    def loop(dir: Seq[String], accArray: Array[String]): Array[String] = {
      if (dir.isEmpty) accArray
      else loop(dir.tail, accArray ++: getFileArray(directories.head).getOrElse( Array[String]() ))
    }
    loop(directories, Array[String]())
  } // END getFullFileList

  def getAllFiles(directories: Option[Seq[String]]) = directories.flatMap(x => getFileList(x.head))

  // DO NOT CHANGE!!!
  def getAllFilesList(directories: Option[Seq[String]]): List[String] = {
    def loop(dir: Seq[String], accArray: List[String]): List[String] = {
      if (dir.isEmpty) accArray
      else loop(dir.tail, accArray ++: getFileList(dir.head).getOrElse( List[String]() ))
    }
    loop(directories.getOrElse( List[String]() ), List[String]())
  } // END getFullFileList

  // DO NOT CHANGE!!!
  def getAllFilesVector(directories: Seq[String]): Vector[String] = {
    def loop(dir: Seq[String], accArray: Vector[String]): Vector[String] = {
      if (dir.isEmpty) accArray
      else loop(dir.tail, accArray ++: getFileVector(dir.head).getOrElse( Vector[String]() ))
    }
    loop(directories, Vector[String]())
  } // END getFullFileList


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
  def fileToByteArray(file: String): Option[Array[Byte]] = {
    try {
      Some( Files.toByteArray (new File (file)) )
    } 	catch{
      case ioe: IOException =>
        println(ioe + s"There was a problem importing the file $file")
        None
      case fnf: FileNotFoundException =>
        println(fnf + s"The file you tried to $file serialize could not be found")
        None
    } // END try/catch
  } // END fileToByteArray()

} // END FileFun.scala
