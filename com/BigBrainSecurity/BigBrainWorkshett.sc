
import java.nio.file.{Files, Paths}
import java.security.MessageDigest
import java.io.File

import com.twitter.hashing.KeyHasher

import scala.annotation.tailrec
import scala.collection.parallel.mutable.ParArray
import scala.collection.immutable.TreeMap
import scala.math.Ordering
import scala.io.Source
/*
val prefetchDirectory = "/Users/username/Documents/prefetchdir"   // stores prefetch directory location

val prefFileName = {
	Source.fromFile("/Users/username/Documents/security/prefetch_hashes_lookup.txt").getLines.toArray.par }
val reg = """[A-Z0-9]+.\w[-A-Z0-9]+.pf""".r
val safePrefetchArray = prefFileName.map(reg.findFirstIn(_).mkString).par

/* Create an Array of made up of common system filenames. */
val otherReg = """[A-Z0-9.]+""".r
val commonFiles = safePrefetchArray.map(otherReg.findFirstIn(_).mkString).toSet.toArray.par

/*  import all of the prefetch files from a directory. */
val dirArray = Array(prefetchDirectory)
val systemPrefetchFiles = getAllFiles(dirArray).par

/* filter out the prefetch files that we have hash values for. */
val matchArray = systemPrefetchFiles.filter(x => commonFiles.exists(y => x.contains(y)))

/* filter out the prefetch files that are not in the safePrefetchList */
val scaryFiles = matchArray.filter(x => safePrefetchArray.exists(y => x.contains(y)))
*/


/********************CONVERT DIRECTORY TO LIST OF SUB-ITEMS****************************
	*       Methods accept a String directory name & converts to List or Seq of Strings.      *                                                       *
	**************************************************************************************/
// Why can't I make this code return a ListBuffer? Is it because listFiles() is an Array method?

// DO NOT CHANGE!!!!
def getDirArray(directoryName: String): List[String] = {
	( new File(directoryName) ).listFiles.filter(_.isDirectory).map(_.getAbsolutePath).toList
}

// DO NOT CHANGE!!!!
def getFileList(directoryName: String): List[String] = {
	( new File(directoryName) ).listFiles.filter(_.isFile).map(_.getAbsolutePath).toList
}
val test2 = getFileArray("/Users/xan0/Documents")

/*
def getFiles(dir: Array[String]): Array[String] = {
	var accArray = Array.empty[String]
	for( x <- dir)
		accArray ++: getFileArray(x)
	accArray
}*/
/*
def files(dir: List[String]): List[String] = dir.flatMap(x => getFileArray(x))

// getFiles(fullDirArray).length
val test = files(fullDirArray)
test.take(10).foreach(println)
*/

// DO NOT CHANGE!!!
def getAllDirs(dir: String): List[String] = {
	val dirList = getDirArray( dir )
	@tailrec
	def loop( directories: List[ String ], accList: List[ String ] ): List[ String ] = {
		if ( directories.isEmpty ) accList
		else loop( directories.tail, accList ++: getDirArray( directories.head ) )
	}
	loop( dirList, List[ String ]() )
}

// DO NOT CHANGE!!!!
def getAllFiles(directories: List[String]): List[String] = {
	def loop(dir: List[String], accArray: List[String]): List[String] = {
		if (dir.isEmpty) accArray
		else loop(dir.tail, getFileList(dir.head)) ++: accArray
	}
	loop( directories, List[String]() )
} // END getFullFileList



val systemListFlat = getAllDirs("/System")
systemListFlat.length
val allFilesList = getFiles(systemListFlat)
allFilesList.length

/* These values should be set by the configuration file. */
val userList = getAllDirs("/Users")
// fullList.foreach(println)
userList.length
val systemList = getAllDirs("/System")
systemList.length
val appList = getAllDirs("/Applications")
appList.length
val libList = getAllDirs("/Library")
libList.length

val fullDirArray: List[String] = (userList ++ systemList) ++ (appList ++ libList)
fullDirArray.length


def getFiles(dir: List[String]): List[String] = {
	if(dir.nonEmpty) getFiles(dir.tail) ++: getFileList(dir.head)
	else Nil
}
getFiles(fullDirArray).length

val allFiles = getAllFiles(fullDirArray)
allFiles.length

/**************************************HASHING FUNCTIONS***********************************************************/
/*
object HashGenerator {
	def generate(path: String): String = {
		val arr = Files.readAllBytes(Paths.get(path))
		val checksum = MessageDigest.getInstance("SHA-512") digest arr
		checksum.map("%02X" format _).mkString
	}
}

val firstHash = HashGenerator.generate(allFiles.head)
val secondHash = makeTwitterHash(allFiles.head)

val hashedTree = genTreeMap(allFiles)
hashedTree.foreach(println)

def makeTwitterHash( fileName: String ): Long = {
	// in order to do this method, the genMap method must change back
	// to (new File(*))
	val byteArray = Files.readAllBytes(Paths get fileName)
	KeyHasher.FNV1A_64.hashKey(byteArray)
}

def genTreeMap(fileSet: Seq[String])(implicit ord: Ordering[String]): TreeMap[String, String] = {
	def loop(fileSet: Seq[String], accTreeMap: TreeMap[String, String]): TreeMap[String, String] = {
		if (fileSet.isEmpty) accTreeMap
		else loop(fileSet.tail, accTreeMap + (fileSet.head -> HashGenerator.generate(fileSet.head)))
	} // END loop()
	loop( fileSet, new TreeMap[String, String]() )
} // END genMap()
*/