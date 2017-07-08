package com.BigBrainSecurity

/* Spark Imports */
import org.apache.hadoop.yarn.webapp.hamlet.HamletSpec.SELECT
import org.apache.spark.sql.functions._
import org.apache.spark.storage.StorageLevel
import org.apache.spark.sql.SparkSession
import org.apache.spark._

/* Scala & BBS imports */
import scala.io.Source
import scala.collection.parallel.mutable.ParArray
import com.BigBrainSecurity.{ AnalyzePrefetch, CleanMFT, IntegrityCheck }

import play.api.libs.json._
/**
  * (@)Author: J. Alexander
  * (#)Version: 1.0
  * (#)Date: 7/3/2017
  *
  * FILE CONTENTS:
  *
  * MAIN CLASS: BigBrainSecurity
  *
  * CASE CLASSES:
  * Brain
  * Findings
  * Registration
  * User
  * Technical
  *
  * PROGRAM PURPOSE: This is the driver program for Big Brain Security
  * forensics and IDS software. The Spark Session originates here.
  */

/**
  * case class Brain
  * Purpose: Contains the raw data from a single time the program runs.
  * This is the data that is sent over from the client.
  * Eventually the brain will communicate w/ a program that analyzes
  * raw memory dumps also.
  * @param id primary key
  * @param dateTime primary key Stores current date.
  * @param name contains user's name
  * @param mftCSV contains the mft in csv format
  * @param regCSV contains registry in csv format.
  * @param prefResults Contains a newline separated list of scary files
  * @param hashes List[String] Might not need to be included in Brain.
  */
case class Brain( id: Int,                                   // primary key
                  dateTime: java.util.Date = java.util.Date, // primary key
                  name: String,                              // contains user's name
                  mftCSV: Option[String],                    // contains the mft in csv format
                  regCSV: Option[String],                    // contains registry in csv format.
                  prefResults: Option[String],               // contains any extra information
                  hashes: Option[List[String]]               // HASH VALUE FOR EACH CSV.
                ){} // END Brain case class
object Brain {
  implicit val format: Format[Brain] = Json.format[Brain]
}
/**
  * case class Findings
  * Purpose: Contains information discovered from the assessment
  * of the raw data.
  * @param id primary key
  * @param dateTime primary key Stores current date.
  * @param mft MFTAssessment Data resulting from assessment.
  * @param registry RegAssessment Data from registry assesment
  * @param prefetch PrefAssessment Data from prefetch assessment
  */

case class Findings( id: Int,                                   // primary key
                     dateTime: java.util.Date = java.util.Date, // primary key
                     mft: Option[MFTAssessment],                // contains result of MFTAssessment
                     registry: Option[RegAssessment],           // contains result of Registry Assessment
                     prefetch: Option[PrefAssessment]           // contains result of Prefetch Assessment
                   ){} // END Findings case class
object Findings {
  implicit val format: Format[Findings] = Json.format[Findings]
}
/**
  * case class Registration
  * Purpose: Contains information about the client
  * @param id primary key
  * @param dateTime primary key Stores current date.
  * @param user User A String name of the user/organization.
  * @param tech Int The IP address & tech info about client
  * @param dir String Stores location of BigBrainSecurity on client.
  */
case class Registration( id: Int,                               // primary key
                         dateTime: java.util.Date = java.util.Date, // primary key
                         user: User,                            // name of user/organization
                         tech: Technical,                       // client's technical details
                         dir: String                            // location where user runs program from.
                       ){} // END Registration case class
object Registration {
  implicit val format: Format[Registration] = Json.format[Registration]
}

/**
  * case class User
  * Purpose: Contains information about the client
  * @param id Primary key Integer ID
  * @param name String name of user/organization
  * @param email String e-mail address of user
  * @param address Array[String] user/organization address
  * @param phone Int Client's
  */
case class User( id: Int,                       // primary key
                 name: String,                  // name of user/organization
                 email: String,                 // User's e-mail address
                 address: Array[String],        // name of user/organization
                 phone: Int,                    // client's technical details
                 badStatus: Boolean = false     // location where user runs program from.
               ){} // END User case class

object User {
  implicit val format: Format[User] = Json.format[User]
} // END User
/**
  * case class Technical
  * Purpose: Contains technical information about the client
  * @param id Primary key Integer ID
  * @param ip Int The IP address of the client
  * @param port Int The port the client receives at.
  */
case class Technical( val id: Int,
                      val ip: Int,
                      val port: Int,
                      val whateverelse: String
                    ){} // END Technical case class
object Technical {
  implicit val format: Format[Technical] = Json.format[Technical]
}

class BigBrainSecurity extends Setup {

  val spark = SparkSession.builder()
    .master("local")
    .appName("Big Brain Security")
    .enableHiveSupport()
    .getOrCreate()

  /******************* Actual main() calls run() ***************************/
  /**
    *  Everything is run from run() because eventually the main()
    *  will run out of a different class and will receive JSON objects from
    *  clients.
    *
    *  Nevertheless, this program should use Actors to support concurrency.
    */
  def main(args: Array[String]): Unit = run() // END main()

  /*************************FUNCTIONAL MAIN METHOD**************************/
  private def run(): Unit = {

    /***********************VARIABLE DECLARATIONS***************************/
    /* Create map of values from config file. */
    val configMap = super.getConfig("Users/glassCodeBender/Applications/BBS/config.txt")

    /* Will need classes for each operating system */
    val operatingSystem = configMap("operating_system").get

    /* Run BBS based on the user's operating system */
    val results = operatingSystem match {
      case "Windows10" => new BBSWindows10(configMap)
      case "Windows" => new BBSWindows7(configMap)
      case "Mac" => new BBSMac(configMap)
      case _ => new BBSWindows7(configMap)
    }

    /* This value should be determined by the state of the program. */
    val id: Int = 312234

    /* IntegrityCheck.scala depends on the user's OS */

    /**
      * Analyze MFT - NEEDS IT'S OWN CLASS
      */

    /*
     * AnalyzeIntegrity - NEEDS IT'S OWN CLASS
     */

    /**
      * Analyze Prefetch CSVs Directly  - NEEDS IT'S OWN CLASS
      */

    /**
      * Update JSON and dependent files Checksum.
      */

    /**
      * JSON Functionality should be added to FileFun.scala
      */

  } // END run()

} // END BigBrainSecurity class
