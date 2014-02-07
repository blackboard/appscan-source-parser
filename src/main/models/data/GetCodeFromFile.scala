package models.data

import scala.collection.mutable
import scala.io.Source

/**
 * Class used to obtain code from a specific file. Can be reused for each file, so that we do not have to open
 * the same file over and over again.
 *
 * @param filePath
 */
class GetCodeFromFile( filePath : String )
{
  //Open the file where the vulnerability was found
  val file = Source.fromFile( filePath )

  /**
   * Function to get the code surrounding the vulnerability finding out of the file.
   *
   * @param ln The line number of the vulnerability
   * @return A map of line numbers to lines of code
   */
  def getCode( ln : String ) : Map[ String, String ] =
  {
    //Iterator to go through each line of the file
    val fileIter = file.getLines()

    //Return value, a map of line numbers to lines of code
    var retMap = new mutable.ListMap[ String, String ]

    //So long as the vulnerability lists a valid line of code
    if( ln.toInt > 0 )
    {
      //iterate through the file until we reach the lines of code that are of interest
      for( line <- 0 to ln.toInt - 7 )
      {
        if( fileIter.hasNext )
        {
          fileIter.next()
        }
      }

      //The code of interest, 5 lines below and 5 above
      for( line <- ln.toInt - 5 to ln.toInt + 5 )
      {
        //So long as the next line exits, grab it
        if( fileIter.hasNext )
        {
          retMap += ( line.toString -> fileIter.next() )
        }
      }
    }
    //if the vulnerability lists line 0, no specific code is listed as vulnerable
    else
    {
      retMap += ( "0" -> "" )
    }

    //Return an immutable version of the map we just created
    return retMap.toMap
  }

  /**
   * Separate method for closing the file
   */
  def closeFile
  {
    //Close the file, prevent memory leaks
    file.close()
  }
}