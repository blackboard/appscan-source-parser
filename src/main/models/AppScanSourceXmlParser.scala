package models

import controllers._
import main.ParsedAppScanSourceXmlData
import models.wrappers.EventReader
import models.wrappers.SystemEvents

import com.mongodb.casbah.commons.MongoDBObjectBuilder
import com.mongodb.casbah.commons.MongoDBListBuilder
import com.mongodb.casbah.commons.MongoDBList
import com.mongodb.casbah.commons.conversions.scala._

import scala.xml.pull.{ EvElemEnd, EvElemStart }
import scala.xml.MetaData
import scala.collection.mutable

/**
 * Created with IntelliJ IDEA.
 *
 * @author msaltzman
 * @since 8/13/13
 *
 * Object which contains iterative functions to parse the data contained in the XML file. Also contains helper
 * methods used to make sense of the data being collected.
 */
class AppScanSourceXmlParser( system : SystemEvents, operatingSystem : String )
{
  //matchers for windows and linux, case insensitive
  val windows = """(?i)windows""".r
  val linux = """(?i)linux""".r

  /**
   * The container for the various parsing loops, contains methods that implement various pull-style parsers which
   * allow us to iterate through large XML files relatively quickly, and grab only the data we need.
   *
   * @param xml The an XML Reader for the .ozasmt file, functions as an iterator
   * @param parsedData An empty container object for the various pieces of the .ozasmt file to be populated by the
   *                   various parsing loops
   */
  def parse( xml: EventReader, parsedData : ParsedAppScanSourceXmlData )
  {
    //Implemented as a while loop instead of recursion (every other loop) to break up large stacks
    while( xml.hasNext )
    {
      //Matcher for the current element in the XML file
      xml.next() match
      {
        //Start of a new element, we are interested in the label and attributes fields of the XML document. Unused
        //components are prefix and scope information
        case EvElemStart( _, label, attribs, _ ) =>
          //Matcher for each container element
          label match
         {
          //If we've reached the Assessment section of the .ozasmt file, parses out the findings with trace information
          case "Assessment" =>
            parsedData.setAssessmentName( getAttribute( attribs, "assessee_name" ) )
            assessmentLoopOuter( "Application", null, xml, parsedData )
            //If we've reached the strings pool, populates the list of strings, which we need to make sense of the data provided
            case "StringPool" =>
              stringsAndFilesLoop( xml, parsedData )
            //Populates the list of files, which we need to join a specific finding to a file within the application
            case "FilePool" =>
              stringsAndFilesLoop( xml, parsedData )
            //Populates the list of sites, which contain additional information about findings and taint records
            case "SitePool" =>
              siteAndFindingLoop( "sites", xml, parsedData )
            //Populates the finding data pool, which contains information about each vulnerability
            case "FindingDataPool" =>
              siteAndFindingLoop( "findings", xml, parsedData )
            //Populates the list of taint records, which contains information about the context around some of the
            //Vulnerabilities listed in the application
            case "TaintPool" =>
              siteAndFindingLoop( "taints", xml, parsedData )
            //Case to handle any item not covered by the previous records, do nothing and proceed with the loop
            case _ =>
          }
        //Case to handle any other element types, do nothing and proceed with the loop, since all important data
        //in the .ozasmt files are contained as element attributes or subelements
        case _ =>
      }
    }
  }

  /**
   * Method used to add a new string record to the set of strings housed in the container object. Lookup is done by
   * string_id
   *
   * @param attribs The set of attributes within the string element (should be id and value only)
   * @param parsedData The container object that the new string element will be added to
   */
  protected def setStrings( attribs : MetaData, parsedData : ParsedAppScanSourceXmlData )
  {
    //Get the id value, and store it as the lookup key
    val key = getAttribute( attribs, "id" )

    //Grab the value of the string, if one exists
    val value = getAttribute( attribs, "value" )

    //If there was a key (and there should be), store the key and value in the container object
    if( key != null )
    {
      parsedData.addString( key, value )
    }
  }

  /**
   * Private method to add a new file to the files list within the container object
   *
   * @param attribs The set of attributes for the file object, should only be key and value
   * @param parsedData The container object to add the new file to
   */
  protected def setFiles( attribs : MetaData, parsedData : ParsedAppScanSourceXmlData )
  {
    //Grab the id value of the file and store it as a lookup key
    val key = getAttribute( attribs, "id" )

    //Store the full path to the file from the file element
    val valueP = getAttribute( attribs, "value" )
    var value = ""

    //If there is a valid file path
    if( valueP != null )
    {
      //get the starting index of the code location within the file being stored
      val pathChecker = valueP indexOf parsedData.getCodeLocation

      if( pathChecker > -1 )
      {
        //Parse the path to store only the relevant data (from mainline onward)
        value = valueP.toString.substring( parsedData.getCodeLocation.length );

        //check if the index of the code location within the file path exists
        pathChecker match
        {
          //the path exists
          case x if x >= 0 =>
            //always use the / character instead of the \ character as a path separator, for comparison purposes
            value = operatingSystem match
            {
              case windows() => value.replaceAllLiterally( "\\", "/" )
              case _ => value
            }
        }
      }
    }

    //If we have a valid file object, add it to the container class
    if( key != null && ( value != "" || valueP == null ) )
    {
      parsedData.addFile( key, value )
    }
    else
    {
      System.out.println( "Code location parameter is incorrect: " + parsedData.getCodeLocation )
      system.exit( 1 )
    }
  }

  /**
   * Private method to add a list of maps to the correct list in the container object. There are many different
   * possibilities for which list to append to, but the implementation is basically identical, thus combining them all
   * in this single method
   *
   * @param attribs The list of key and value pairs that will be converted to our map
   * @param inprogressList The list type to append to, can be "sites", "findings", "taints", or "taintFindings"
   * @param parsedData The container object to append the data to
   *
   * @throws Error if the inprogressList parameter is not a valid string, as defined above
   */
  protected def parseListOfMaps( attribs : MetaData, inprogressList : String, parsedData : ParsedAppScanSourceXmlData )
  {
    var site = new mutable.ListMap[ String, String ]
    //Set an iterator through the attributes to the head of the attributes list
    var attribsIter = attribs.head

    //Iterate through the list of attributes, and append the key -> value pair to the new listMap
    while( attribsIter.key != null )
    {
      site += ( attribsIter.key.toString() -> attribsIter.value.toString() )
      //increment the iterator
      attribsIter = attribsIter.next
    }
    //Append the new data to the correct list
    inprogressList match
    {
      case "sites" =>
        parsedData.addSite( site.toMap )
      case "findings" =>
        parsedData.addFinding( site.toMap )
      case "taints" =>
        parsedData.addTaint( site.toMap )
      case "taintFinding" =>
        parsedData.addTaintFinding( site.toMap )
      case _ =>
        throw new Throwable( "List type not supported" )
    }
  }

  /**
   * Helper method to get a specific attributes' value
   *
   * @param attribs The set of attributes
   * @param attribute The key for the attribute we're looking for
   * @return The value of that attribute
   */
  protected def getAttribute( attribs : MetaData, attribute : String ) : String =
  {
    // Set attrib to the string value of the attributes' value, or null if it does not have that key
    val attrib = attribs.get( attribute ).getOrElse( null ) match
    {
      case x if x != null => x.head.text
      case x => null
    }

    //Return the value found
    return attrib
  }

  /**
   * Recursive loop iterating through the list of strings that the .ozasmt file provides. Stores each new string
   * as an element within the strings object of the parsedData container
   *
   * @param xml The object containing the set of parsed XML from the .ozasmt file
   * @param parsedData The object containing the data obtained from the .ozasmt file
   */
  def stringsAndFilesLoop( xml: EventReader, parsedData : ParsedAppScanSourceXmlData )
  {
    def loop()
    {
      //This function is recursive rather than iterative, so implemented check as an if statement rather than a while
      if( xml.hasNext )
      {
        //Matcher for the next element in the XML document
        xml.next() match
        {
          //Case where a new element is found
          case EvElemStart( _, label, attribs, _ ) =>
            label match
            {
              //Finding a new String element, and adding that string by lookup ID to parsedData
              case "String" =>
                setStrings( attribs, parsedData )
              case "File" =>
                setFiles( attribs, parsedData )
              //Case where another element is found, added as a precaution in case of problem, but the XSD check
              //at the beginning should catch a problem of that nature before reaching here
              case _ =>
            }
            //Continue iterating through the list of strings
            loop()
          //Match on any element's ending
          case EvElemEnd( _, label ) =>
            label match
            {
              //If the StringPool element closes, we're no longer inside of the list of strings, so allow the primary loop
              //to pick back up
              case "StringPool" | "FilePool" =>
              //If any other element ends, continue looking for more strings
              case _ =>
                loop()
            }
          //Case where another XML type is found, besides start or end of an element, ignore and proceed with the strings loop
          case _ =>
            loop()
        }
      }
    }
    //Call the loop
    loop()
  }

  /**
   * Recursive function to iterate through the list of sites, findings, and taints. Since all three elements share
   * a common syntax, the same loop can handle all three types
   *
   * @param inprogressList The type of list that is currently in progress. Can be either "sites", "findings", or "taints"
   * @param xml The XmlEvent object containing the data from the parsed XML file
   * @param parsedData The data from the XML file
   *
   * @throws Exception if inprogressList is not one of the accepted strings
   */
  def siteAndFindingLoop( inprogressList : String, xml : EventReader, parsedData : ParsedAppScanSourceXmlData )
  {
    def loop()
    {
      //Confirms that inprogressList is one of the accepted strings before proceeding
      if( !( inprogressList.equals( "sites" ) || inprogressList.equals( "findings" ) || inprogressList.equals( "taints" ) ) )
      {
        throw new Throwable( "List type not supported" )
      }

      //Since this function is recursive, implement this check as an if statement
      if( xml.hasNext )
      {
        //Matcher for the current xml object found
        xml.next() match
        {
          //Matches on the start of a new element
          case EvElemStart( _, label, attribs, _ ) =>
            label match
            {
              //Matches on any Site, FindingData, or Taint element, passing the list type to the parsing method for
              //the set of attributes, so it knows which list to update
              case "Site" | "FindingData" | "Taint" =>
                parseListOfMaps( attribs, inprogressList, parsedData )
              //On any other case, do nothing
              case _ =>
            }
            //recurse back to the site, finding, and taint loop to proceed with finding new data to add to the in progress list
            loop()
          //Matches on the end of an element
          case EvElemEnd( _, label ) =>
            label match
            {
              //Complete the loop if we find the end of the current list, and allow the primary loop to pick back up
              case "SitePool" | "FindingDataPool" | "TaintPool" =>
              //Any other case, proceed with this loop
              case _ =>
                loop()
            }
          //Any other case, proceed with this loop
          case _ =>
            loop()
        }
      }
    }

    loop()
  }

  /**
   * Recursive method to deal with the Assessment elements, and their children. Primary function is to join all taint
   * traces to findings, findings to files, files to projects, and projects to applications.
   *
   * @param ownerType The parent information type, none, applicatoin, project, or file for now
   * @param ownerName The name of the parent data type
   * @param xml The event object containing the XML input data to be parsed
   * @param parsedData The data object storing the information obtained via the xml
   */
  def assessmentLoopOuter( ownerType : String, ownerName : String, xml: EventReader,
                           parsedData : ParsedAppScanSourceXmlData )
  {
    def assessmentLoop( ownerType : String, ownerName : String )
    {
      //Instantiating objects to populate ownerName and ownerType
      var owner = ""
      var ownName = ""

      //Because this is a recursive function, implement this as an if statement
      if( xml.hasNext )
      {
        //Match the element type of the next XML object
        xml.next() match
        {
          //matches on the start of a new element
          case EvElemStart( _, label, attribs, _ ) =>
            label match
            {
              //Matches On a new Assessment element
              case "Assessment" =>
                //Sets the assessment type of of this assessment element,
                val assessType: String = getAttribute( attribs, "assessee_type" ) match
                {
                  //if the value of the get statement above is not null, set assessType to the result
                  case x if x != null => x.toString
                  //if the value is null, set assessType to null
                  case x => null
                }

                //Now, match the value of assessType
                assessType match
                {
                  case "Project" =>
                    //Create a new project map
                    var proj = new mutable.ListMap[ String, String ]

                    //Populate the project map with a name and an owner object, to join the project to an application
                    proj += ( "name" -> getAttribute( attribs, "assessee_name" ) )
                    proj += ( "owner" -> ownerName )
                    //Add the new project to the container object
                    parsedData.addProject( proj.toMap )

                    //Set the owner type to application
                    owner = "Application"
                  //Match everything else
                  case _ =>
                    //Set the owner type to the current owner type
                    owner = ownerType
                }
                //Call the assessment loop to continue to populate the assessment informatoin
                assessmentLoop( owner, ownerName )
              //This element starts the next section of the report, so break back to the main loop
              case "Messages" =>
              //Matches on a file record (Assessment File)
              case "AsmntFile" =>
                //Each file is owned by a project, so specify that here
                owner = "Project"
                //The owner name, however, is now the current file_id
                ownName = getAttribute( attribs, "file_id" )

                //Create and store a fileWithOwner element containing a filename and an owner mapping
                var fileWithOwner = new mutable.ListMap[ String, String ]
                fileWithOwner += ( "owner" -> parsedData.getProjects.last( "name" ) )
                fileWithOwner += ( "filename" -> parsedData.getFiles.get( ownName ).getOrElse( null ) )
                parsedData.addFileByProject( fileWithOwner.toMap )

                //If there's an error in compiling and parsing the file, store a record of it
                val error = getAttribute( attribs, "error_status" )
                if( error != null )
                {
                  parsedData.addFileError( parsedData.getFiles.get( ownName ).getOrElse( null ).asInstanceOf[ String ], error )
                }
                //Continue searching for more information on the assessment
                assessmentLoop( owner, ownName )
              //Matches on the assessmentStats project
              case "AssessmentStats" =>
                ownerType match
                {
                  //If this is an application, there is no owner, but set the name of the application to ownName
                  case "none" =>
                    owner = ownerType
                    ownName = getAttribute( attribs, "owner_name" )
                  //If this is a project, set the owner name to the project name and the owner_type to project
                  case "Application" =>
                    ownName = getAttribute( attribs, "owner_name" )
                    owner = "Project"
                  //If this is a file, set the owner name to the file name, and the owner type to file
                  case "Project" =>
                    ownName = ownerName
                    owner = "file"
                  //If it's anything else, keep the ownerName the same
                  case _ =>
                    ownName = ownerName
                }
                //Run the assessmentLoop again, using the new owner and owner name parameters
                assessmentLoop( owner, ownName )
              //Add a taintFinding record if we reach a finding element, and recall the current loop
              case "Finding" =>
                parseListOfMaps( attribs, "taintFinding", parsedData )
                assessmentLoop( owner, ownName )
              //In any other case, just continue with the
              case _ =>
                assessmentLoop( ownerType, "" )
            }
          //Matches an element's closing tag
          case EvElemEnd( _, label ) =>
            label match
            {
              //If the element being closed is an Assessment or AsmtFile, recall the assessment loop with the appropriate parameters
              case "Assessment" | "AsmtFile" =>
                owner match
                {
                  case "Application" => assessmentLoop( "none", ownerName )
                  case "Project" => assessmentLoop( "Application", ownerName )
                  case _ => assessmentLoop( ownerType, ownerName )
                }
              //If the element being closed is an AssessmentStats element, call the assessment loop with current parameters
              //unless the current element is a file
              case "AssessmentStats" =>
                if( ownerType.equalsIgnoreCase( "File" ) )
                {
                  assessmentLoop( "Project", ownerName )
                }
                else
                {
                  assessmentLoop( ownerType, ownerName )
                }
              //In any other case, keep the assessment loop going with the same data
              case _ =>
                assessmentLoop( ownerType, ownerName )
            }
          //In any other case, keep the assessment loop going with the same data
          case _ =>
            assessmentLoop( ownerType, ownerName )
        }
      }
    }
    assessmentLoop( ownerType, ownerName )
  }
}
