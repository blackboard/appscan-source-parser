package main

import controllers.Execute
import models.AppScanSourceXmlParser

import scala.collection.mutable.ListBuffer
import scala.collection.mutable

/**
 * Created with IntelliJ IDEA.
 * @author msaltzman
 * @since 8/13/13
 *
 * Class containing the various bits of data parsed out from the XML file
 */
class ParsedAppScanSourceXmlData
{
  /** The location of the project being scanned */
  private var codeLocation = new String
  /** The operating system of the application */
  private var operatingSystem = new String

  /** The set of applications being scanned (should only be 1, however) */
  private var assessmentName = new String
  /** The set of files that threw errors during parsing */
  private var fileErrors = new mutable.ListMap[ String, String ]
  /** The set of projects in the application */
  private var projects = new ListBuffer[ Map[ String, String ] ]
  /** The set of sites, which contain data about a specific vulnerability finding */
  private var sites = new ListBuffer[ Map[ String, String ] ]
  /** The set of sites with strings already mapped */
  private var siteStrings = new mutable.ListMap[ String, Map[ String, String ] ]
  /** The set of strings, which contain all of the text that's been removed from the rest of this xml file */
  private var strings = new mutable.ListMap[ String, String ]
  /** The set of files that were scanned */
  private var files = new mutable.ListMap[ String, String ]
  /** The set of files again, but listed by which project each belongs to */
  private var filesByProject = new ListBuffer[ Map[ String, String ] ]
  /** The set of vulnerability findings */
  private var findings = new ListBuffer[ Map[ String, String ] ]
  /** The set of findings containing finding records and taint records */
  private var taintFindings = new ListBuffer[ Map[ String, String ] ]
  /** The set of taints mapped by finding_id */
  private var taintsByFinding = new mutable.ListMap[ String, String ]
  /** The set of taint records */
  private var taints = new ListBuffer[ Map[ String, String ] ]

  /**
   * Append a new file to the list of files
   *
   * @param key The id of the file
   * @param value The path to the file
   */
  def addFile( key : String, value : String )
  {
    this.files += ( key -> value )
  }

  /**
   * Appends a new file and the project it belongs to the list
   *
   * @param newElement The record containing the filename and the project name
   */
  def addFileByProject( newElement : Map[ String, String ] )
  {
    this.filesByProject += newElement
  }

  /**
   * Appends a new error record to the list of errors
   *
   * @param key The filename with the error
   * @param value 1 (might change) indicating that an error was received during parse
   */
  def addFileError( key : String, value : String )
  {
    this.fileErrors += ( key -> value )
  }

  /**
   * Appends a new finding record to the list of findings
   *
   * @param newElement The record of the finding
   */
  def addFinding( newElement : Map[ String, String ] )
  {
    this.findings += newElement
  }

  /**
   * Appends a new project to the list of projects, also contains the Application name that this project belongs to
   *
   * @param newElement The project record to add
   */
  def addProject( newElement : Map[ String, String ] )
  {
    this.projects += newElement
  }

  /**
   * Appends a new site to the list of sites
   *
   * @param newElement The site record to add
   */
  def addSite( newElement : Map[ String, String ] )
  {
    this.sites += newElement
  }


  /**
   * Appends a new site with mapped strings value to the list of siteStrings
   *
   * @param key the site_id for looking up the record
   * @param value the site record to add
   */
  def addSiteStrings( key : String, value : Map[ String, String ] )
  {
    this.siteStrings += ( key -> value )
  }

  /**
   * Appends a new string to the list of strings
   *
   * @param key Identifier for the string
   * @param value The string text
   */
  def addString( key : String, value : String )
  {
    this.strings += ( key -> value )
  }

  /**
   * Appends a new taint record to the list of taints
   *
   * @param newElement The taint record to add
   */
  def addTaint( newElement : Map[ String, String ] )
  {
    this.taints += newElement
  }

  /**
   * Appends a new taint trace record mapped by finding id
   *
   * @param key The finding id
   * @param value The taint trace
   */
  def addTaintByFinding( key : String, value : String )
  {
    this.taintsByFinding += ( key -> value )
  }

  /**
   * Appends a new finding record containing taint information to the list of findings with taint
   *
   * @param newElement The finding with taint record to add
   */
  def addTaintFinding( newElement : Map[ String, String ] )
  {
    this.taintFindings += newElement
  }

  /**
   * Returns the set of application names for this scan file
   *
   * @return The set of application names
   */
  def getAssessmentName : String =
  {
    return this.assessmentName
  }

  /**
   * Returns the location of the code that has been scanned
   *
   * @return The code location
   */
  def getCodeLocation : String =
  {
    return this.codeLocation
  }

  /**
   * Returns the set of files that were scanned
   *
   * @return The set of files
   */
  def getFiles : mutable.ListMap[ String, String ] =
  {
    return this.files
  }

  /**
   * Returns the set of files organized by project
   *
   * @return the set of files by project
   */
  def getFilesByProject : ListBuffer[ Map[ String, String ] ] =
  {
    return this.filesByProject
  }

  /**
   * Returns the set of files that AppScan threw errors during parse for
   *
   * @return The set of files that caused errors
   */
  def getFileErrors : mutable.ListMap[ String, String ] =
  {
    return this.fileErrors
  }

  /**
   * Returns the set of findings from the scan
   *
   * @return The set of findings
   */
  def getFindings : ListBuffer[ Map[ String, String ] ] =
  {
    return this.findings
  }

  /**
   * Returns the set of projects that were scanned
   *
   * @return The set of projects
   */
  def getProjects : ListBuffer[ Map[ String, String ] ] =
  {
    return this.projects
  }

  /**
   * Returns the operating system of this application
   *
   * @return The operating system
   */
  def getOs : String =
  {
    return this.operatingSystem
  }

  /**
   * Returns the set of sites that provide context to the finding records
   *
   * @return the set of sites
   */
  def getSites : ListBuffer[ Map[ String, String ] ] =
  {
    return this.sites
  }

  /**
   * Returns the list of sites with mapped strings
   *
   * @return the list of sites with mapped strings
   */
  def getSiteStrings : mutable.ListMap[ String, Map[ String, String ] ] =
  {
    return this.siteStrings
  }

  /**
   * Returns the set of strings
   *
   * @return the set of strings
   */
  def getStrings : mutable.ListMap[ String, String ] =
  {
    return this.strings
  }

  /**
   * Returns the set of taint records
   *
   * @return the set of taint records
   */
  def getTaints : ListBuffer[ Map[ String, String ] ] =
  {
    return this.taints
  }

  /**
   * Returns the set of findings containing taint records
   *
   * @return the set of findings with taint records
   */
  def getTaintFindings : ListBuffer[ Map[ String, String ] ] =
  {
    return this.taintFindings
  }

  /**
   * Returns the set of taint trace records organized by finding_id
   *
   * @return the set of taint trace records
   */
  def getTaintsByFinding : mutable.ListMap[ String, String ] =
  {
    return this.taintsByFinding
  }

  /**
   * Function to properly set the location of the code that's being scanned. Appends a / or \, depending on operating
   * system, and then confirms that you've put in the proper location. If not, it appends mainline to it, along with
   * the appropriate slash for the OS
   *
   * @param codeLocation The location of the code being scanned
   */
  def setCodeLocation( codeLocation : String )
  {
    //regular expression checking the correctness of the directory being scanned
    val windowsCorrectPath = """.*(?i)[ (mainline\\|(?i)releases\\\d\.\d\\) ]""".r
    val linuxCorrectPath = """.*(?i)[ (mainline/|(?i)releases/\d\.\d/) ]""".r
    val windows = """(?i)windows""".r
    val linux = """(?i)linux""".r


    //Variable to house the passed in code location, to be updated and modified so as to set the value appropriately
    var newLoc = codeLocation

    //Setting the code location to be used later based on the output of processing
    this.codeLocation = operatingSystem match
    {
      //if the OS is windows
      case windows() =>
        //Append a \ character to the path if missing
        if( !codeLocation( codeLocation.length - 1 ).equals( '\\' )  )
        {
          newLoc = newLoc + "\\"
        }
        //verify that the path matches the windowsCorrectPath Regex, otherwise appends mainline
        newLoc match
        {
          case windowsCorrectPath() =>
            newLoc
          case _ =>
            newLoc + "mainline\\"
        }
      //if the OS is linux
      case linux() =>
        if( !codeLocation( codeLocation.length - 1 ).equals( '/' )  )
        {
          newLoc = newLoc + "/"
        }
        newLoc match
        {
          case linuxCorrectPath() =>
            newLoc
          case _ =>
            newLoc + "mainline/"
        }
      case _ =>
        ""
    }
  }

  /**
   * Set the operating system of the machine running this application
   *
   * @param os The operating system of the machine running this application
   */
  def setOs( os : String )
  {
    this.operatingSystem = os
  }

  /**
   * Change the name of the application
   *
   * @param assessment The new application name
   */
  def setAssessmentName( assessment : String )
  {
    this.assessmentName = assessment
  }
}