package models

import main.ParsedAppScanSourceXmlData
import models.data.{DataCompilation, AppScanStringMatcher}

import com.mongodb.casbah.Imports._

/**
 * Created with IntelliJ IDEA.
 *
 * @author msaltzman
 * @since 8/13/13
 *
 * Object containing the various methods used to upload the list of findings from a specific application from appscan
 * source to the database
 */
class UploadAppScanSourceXml( operatingSystem : String, dataCompiler : DataCompilation,
                              stringMatcher : AppScanStringMatcher )
{
  /**
   * Maps all of the data parsed from the XML (aside from the taint trace due to complexities), and puts that data in a
   * form that can be easily parsed through to create the final output to the Mongo Database, also lays out the format:
   * project <- files <- findings
   *
   * @param parsedData The container object containing all of the data we want to organize and upload
   * @param issuesConn An open connection to the mongoDB server
   */
  def createOutput( parsedData : ParsedAppScanSourceXmlData, issuesConn : MongoConnection )
  {
    //for readability and performance, map the strings from parsedData for ease of use
    val strings = parsedData.getStrings
    //get the list of files from the parsedData object
    val files = parsedData.getFiles

    //map site data to strings
    stringMatcher.mapStringToSites( parsedData.getSites, strings, files, parsedData )

    //next, iterate through the set of findings from the application portion to search for taint traces
    for( taintFinding <- parsedData.getTaintFindings )
    {
      //If there's a taint trace for this vulnerability, append it to the container object
      if( taintFinding.get( "trace" ).getOrElse( null ) != null )
      {
        parsedData.addTaintByFinding( taintFinding( "data_id" ), taintFinding( "trace" ) )
      }
    }

    //get the list of findings
    val findings = parsedData.getFindings
    //iterate through the list of findings, and upload results to the database one at a time
    for( finding <- findings )
    {
      val findingRecord = dataCompiler.createFindingRecord( parsedData.getSiteStrings, finding, files, strings, parsedData )
      uploadResults( findingRecord, issuesConn )
    }

    //close the connection to the database
    issuesConn.close()
  }

  /**
   * Function to add the newly updated record to the
   *
   * @param finding The MongoDBList object containing the project, files, and findings data
   * @param issuesConn The mongodb server to update this record in
   */
  protected def uploadResults( finding : MongoDBObject, issuesConn : MongoConnection  )
  {
    //Open the collection of issues found during static analysis
    val issuesColl = issuesConn( "ISSUES" )( "STATIC_ISSUES_LIST" )

    //create a matching object to find a previous incarnation of this record, if one exists
    val findingMap = finding.toMap
    val matcher = MongoDBObject( "application_name" -> findingMap.get( "application_name" ),
                                     "project_name" -> findingMap.get( "project_name" ),
                                     "file_path" -> findingMap.get( "file_path" ),
                                     "ln" -> findingMap.get( "ln" ).toString,
                                     "vtype" -> findingMap.get( "vtype" ),
                                     "method" -> findingMap.get( "method" ) )

    //Append the application with our project record
    issuesColl.update( matcher, finding, true, false )
  }
}
