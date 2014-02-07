package models.data

import main.ParsedAppScanSourceXmlData

import com.mongodb.casbah.commons.{MongoDBObjectBuilder, MongoDBListBuilder, MongoDBList, MongoDBObject}
import scala.collection.mutable
import com.mongodb.casbah.Imports._

class DataCompilation( operatingSystem : String )
{
 /**
   * Creates the finding record to be uploaded to the mongodb system
   *
   * @param siteStrings The set of site identifiers mapped to strings
   * @param finding The finding records, not containing string data yet
   * @param files The list of files in this application
   * @param strings The list of strings for this assessment
   * @param parsedData The object storing all of the data parsed fromt he assessment file
   * @return MongoDBObject
   */
  def createFindingRecord( siteStrings : mutable.ListMap[ String, Map[ String, String ] ], finding : Map[ String, String ],
                                   files :  mutable.ListMap[ String, String ], strings : mutable.ListMap[ String, String ],
                                   parsedData : ParsedAppScanSourceXmlData ) : MongoDBObject =
  {
    var findingRecord = new MongoDBObjectBuilder
    //matchers for windows and linux, case insensitive
    val windows = """(?i)windows""".r
    val linux = """(?i)linux""".r

    //Lookup table for the confidence parameter
    val conf = finding.get( "conf" ).getOrElse( null ) match
    {
      case "1" => "Vulnerability"
      case "2" => "Type 1"
      case "3" => "Type 2"
      case _ => null
    }

    //Lookup table for the severity parameter
    val sev = finding.get( "sev" ).getOrElse( null ) match
    {
      case "0" => "High"
      case "1" => "Medium"
      case "2" => "Low"
      case "3" => "Informational"
      case _ => null
    }

    //Get the site record for this finding
    val site = parsedData.getSiteStrings.get( finding.get( "site_id" ).getOrElse( null ) ).getOrElse( null )
    //Get the findingId
    val findingId = finding.get( "id" ).getOrElse( null )

    //Adding the action object record, not sure what it maps to at this point
    findingRecord += ( "ao_id" -> finding.get( "ao_id" ).getOrElse( null ) )
    //Appending the confidence rating for the vulnerability
    findingRecord += ( "conf" -> conf )
    //Appending the finding identifier
    findingRecord += ( "finding_id" -> findingId )
    //Appending the project name to the finding record
    findingRecord += ( "project_name" -> strings.get( finding.get( "project_name" ).getOrElse( null ) ).getOrElse( null ) )
    //Appending the set of property identifiers, currently unused
    //TODO: Create a lookup table for property identifiers if they are useful
    findingRecord += ( "prop_ids" -> finding.get( "prop_ids" ).getOrElse( null ) )
    //Append the record identifier for the finding, currently unused
    findingRecord += ( "rec_id" -> finding.get( "rec_id" ).getOrElse( null ) )
    //Append the severity of the vulnerability
    findingRecord += ( "sev" -> sev )
    //Append the site id value, used as a manual check of the success of the conversion and upload
    findingRecord += ( "site_id" -> finding.get( "site_id" ).getOrElse( null ) )
    //Append the vulnerability type string
    findingRecord += ( "vtype" -> strings.get( finding.get( "vtype" ).getOrElse( null ) ).getOrElse( null ) )
    //Append the vulnerability type API call
    findingRecord += ( "method" -> site.get( "method" ).getOrElse( null ).toString )
    //Append the context data from the site
    findingRecord += ( "ctx" -> site.get( "ctx" ).getOrElse( null ) )
    //Append the column number
    findingRecord += ( "cn" -> site.get( "cn" ).getOrElse( null ) )
    //append the signature of the vulnerability, appears to be deprecated, currently unused
    findingRecord += ( "sig" -> site.get( "sig" ).getOrElse( null ) )
    //append the ordinal value of the vulnerability, currently unused
    findingRecord += ( "ord" -> site.get( "ord" ).getOrElse( null ) )
    //append the caller name
    findingRecord += ( "caller" -> site.get( "caller" ).getOrElse( null ) )
    //append the line number
    findingRecord += ( "ln" -> site.get( "ln" ).getOrElse( null ) )

    //Get the file record for this finding
    val file = site.get( "file" ).getOrElse( null )
    //normalize the file path to use / rather than \
    val fullPath = operatingSystem match
    {
      case windows() => parsedData.getCodeLocation + file.replaceAllLiterally( "/", "\\" )
      case linux() => parsedData.getCodeLocation + file
    }

    //add the file path to the record
    findingRecord += ( "file_path" -> file )
    //Get the line number of this finding
    val ln = site.get( "ln" ).getOrElse( null )

    val codeInFile = new GetCodeFromFile( fullPath )
    //grab the code for this finding record, assuming code exists
    val code = codeInFile.getCode( ln )

    codeInFile.closeFile

    //append the code to the finding record
    findingRecord += ( "code" -> code )

    //Get the list of taint traces organized by finding ID
    val taintsByFinding = parsedData.getTaintsByFinding
    //get the list of taints for this finding record
    val taints = taintsByFinding.get( findingId ).getOrElse( null )
    val appscanMatcher = new AppScanStringMatcher
    val taintStrings = appscanMatcher.createTaintStrings( parsedData )
    //create the taint trace itself, if one should exist
    var taintTrace = MongoDBList()
    if( taints != null )
    {
      taintTrace = createTaintTrace( taints, taintStrings, parsedData )
    }
    //Append the taint trace record to this finding
    findingRecord += ( "taint_trace" -> taintTrace )
    //Append the assessment name
    findingRecord += ( "application_name" -> parsedData.getAssessmentName )

    return findingRecord.result
  }

  /**
   * Function used to create a list from the taint trace records from the findingData records parsed out earlier. Due
   * to the complexities in storing this data (site information), saving this mapping for creating the MongoDBList and
   * MongoDBObject values, which are much more forgiving of type than standard Scala objects
   *
   * @param taintList The taint trace record stored in the assessment's Finding element
   * @param taintStrings The full list of taints with strings, organized as a lookup table by taint id
   * @param parsedData The container object containing the parsed data from throughout this process
   * @return The trace list, ready for export into the MongoDB
   */
  protected def createTaintTrace( taintList : String, taintStrings : mutable.ListMap[ String, Map[ String, String ] ],
                                  parsedData : ParsedAppScanSourceXmlData ) : MongoDBList =
  {
    //Create an array out of the taintList, since each taint record is separated by commas
    val taintTrace = taintList.split( "," )

    //set of sites with String data included from the container object
    val siteStrings = parsedData.getSiteStrings

    //Various bits of data we need in order to create the taint trace records
    var taints = new MongoDBListBuilder
    val parentStack = new mutable.Stack[ String ]
    var taintPosition = 0

    //Iterate through each taint record from the taint trace array
    for( taint <- taintTrace )
    {
      //Push the new taint record into the parent stack, which we will use to create a full trace diagram.
      //The trace record is a depth-first search, so once popped off the stack, the previous record will no longer
      //be a parent record, thus we use a stack object to keep track
      parentStack.push( taint )

      //Each . in a taint record tells you how far up in the parent stack to return to, so count them
      val parentFinder = taint.count( _ == '.' )
      if( parentFinder > 0 )
      {
        //If we need to return to a previous parent, pop the stack until that parent is reached
        for( iter <- 1 to parentFinder  )
        {
          parentStack.pop()
        }
      }

      //Create a new record to populate a single taint record
      var newTaint = new MongoDBObjectBuilder
      //Store the taint's original position, for clarity
      newTaint += ( "position" -> taintPosition )
      //increment the position record for the next item
      taintPosition = taintPosition + 1
      //Grab just the taint_id from the record, the .'s have already been accounted for above
      val taintId = taint.split( """\.""" )( 0 )

      //Iterate through each key in the taint record
      for( taintKey <- taintStrings( taintId ).keys )
      {
        //This is the reason we don't convert directly: We need to create a MongoDBObject out of the site record, since
        //we do not care about the site_id itself
        if( taintKey.equals( "site_id" ) )
        {
          var site = new MongoDBObjectBuilder
          val siteString = siteStrings( taintStrings( taintId )( taintKey ) )
          for( siteKey <- siteString.keys )
          {
            site += ( siteKey -> siteString( siteKey ) )
          }
          //add a record to our new taint object, site : { site object }
          newTaint += ( "site" -> site.result )
        }
        else
        {
          //if it isn't site_id, add it directly to the taint record object
          newTaint += ( taintKey -> taintStrings( taintId )( taintKey ) )
        }
      }
      //If we need to return to a previous parent record, after this taint object, add it here
      if( parentStack.top != taintId )
      {
        newTaint += ( "parent_id" -> parentStack.top )
      }
      taints += newTaint.result
    }

    return taints.result
  }
}