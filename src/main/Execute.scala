package controllers

import models.AppScanSourceXmlParser
import models.UploadAppScanSourceXml
import models.Validator
import models.wrappers.EventReader
import models.wrappers.SystemEvents
import models.data.{DataCompilation, AppScanStringMatcher}

import main.ParsedAppScanSourceXmlData

import com.mongodb.casbah.commons.conversions.scala._
import scala.io.Source
import com.mongodb.casbah.MongoConnection

/**
 * Created with IntelliJ IDEA.
 * @author msaltzman
 * @since 8/7/13
 *
 * Execution object which houses the main class of the application used to parse the AppScan Source .ozasmt xml files
 * passed in. Also validates the .ozasmt files
 */
object Execute
{
  /** Defines the operating system in use (for the purposes of deciding which slash character to use: \ or / */
  private var operatingSystem = "Linux"

  //matchers for windows and linux, case insensitive
  private val windows = """(?i)windows""".r
  private val linux = """(?i)linux""".r
  private val system = new SystemEvents

  //The .ozasmt file to be parsed
  private var fileToParse = new String
  //The mongodb server to store the results
  private var mongoDbServer = new String

  /**
   * The main execution method of this application.
   *
   * @param args The set of arguments from the command line
   */
  def main( args : Array[ String ] )
  {
    //Allows us to use Joda Time with MongoDB
    RegisterJodaTimeConversionHelpers()

    //Checks if the user is asking for the syntax list, if so, display it
    if( args.length < 1 || args( 0 ).equals( "-?" ) )
    {
      System.out.println( "Usage: " )
      System.out.println( "   -f (--file) <filename>               -- Provides the name of the appscan source assessment filename for parsing" )
      System.out.println( "   -o (--OS) <operating system>         -- Provides the type of OS in use (Windows, Linux). Defaults to Linux" )
      System.out.println( "   -m (--mongo-db-server) <server>      -- Provides the hostname of the MongoDB server" )
      System.out.println( "   -c (--code-location) <path-to-code>  -- Provides a file path to the code (ideally ending with release " )
      System.out.println( "                                           version, however, mainline is assumed)" )
      System.out.println( " " )
      System.out.println( "Example: ")
      System.out.println( "   run -f test.ozasmt -o Windows -m localhost -c /usr/local/p4/B2/projects/date-management/mainline/" )
    }
    else
    {
      //Make sure that we have the right number of arguments, otherwise exit
      if( args.length != 8 )
      {
        System.out.println( "Missing argument or flag" )
        system.exit( 2 )
      }

      //Instantiates the object which will house the data parsed from AppScan
      var parsedData = new ParsedAppScanSourceXmlData

      //go through all of the arguments and set the appropriate parameters
      for( iter <- 0 to args.length - 1 by 2 )
      {
        args( iter ) match
        {
          case "-f" | "--file" => this.fileToParse = args( iter + 1 )
          case "-o" | "--OS" =>
            //grab the OS value
            val os = args( iter + 1 )

            //make sure the OS passed in is appropriate
            os match
            {
              //if the OS is an appropriate OS, set the variable
              case windows() | linux() =>
                this.operatingSystem = os
                parsedData.setOs( os )
              case _ =>
                System.out.println( "Unknown OS: " + os )
                system.exit( 1 )
            }
          case "-m" | "--mongo-db-server" => this.mongoDbServer = args( iter + 1 )
          case "-c" | "--code-location" =>
            parsedData.setCodeLocation( args( iter + 1 ) )
          case _ =>
            //Exit if an unknown parameter is used
            System.out.println( "Unknown flag: " + args( iter ) )
            system.exit( 1 )
        }
      }

      val xmlParser = new AppScanSourceXmlParser( system, operatingSystem )

      //Validate the .ozasmt file
      val xsdPath = operatingSystem match
      {
        case xmlParser.windows() => "xsd_Ozasmt_OunceV7_0.xsd"
        case xmlParser.linux() => "xsd_Ozasmt_OunceV7_0.xsd"
      }

      //Tell the validator what version of XML to use
      val schemaLang = "http://www.w3.org/2001/XMLSchema"

      val validator = new Validator( schemaLang )

      if( validator.validate( fileToParse, xsdPath ) )
      {
        //Read in the .ozasmt file as XML
        val xml = new EventReader( fileToParse )

        //Catches any thrown exceptions during processing
        try
        {
          //Pass the XML to our XML reader
          xmlParser.parse( xml, parsedData )

          //connect to the MongoDb instance once only
          val mongoConnection = MongoConnection( mongoDbServer )
          //create a data compiler object
          val dataCompiler = new DataCompilation( operatingSystem )
          //create a string matcher object
          val stringMatcher = new AppScanStringMatcher()

          val upload = new UploadAppScanSourceXml( operatingSystem, dataCompiler, stringMatcher )

          upload.createOutput( parsedData, mongoConnection )

          //cut connection to the mongoDb instance as part of cleanup
          mongoConnection.close()
        }
        catch
        {
          //For all exceptions that are thrown, print the stack trace and exit
          case ex : Exception =>
            ex.printStackTrace()
            system.exit( 4 )
        }
      }
      else
      {
        //Exit with status 3 if the .ozasmt file was not valid
        system.exit( 3 )
      }
    }
  }
}