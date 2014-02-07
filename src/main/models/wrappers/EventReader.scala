package models.wrappers

import scala.xml.pull.{ XMLEventReader, XMLEvent }
import scala.io.Source

/**
 * Wrapper class for the XMLEventReader object, handling dependency injection to the AppScanSourceXmlParser
 * class
 *
 * @param file The name of the file being read in by the XMLEventReader
 */
class EventReader( file : String )
{
  /** The XMLEventReader object that this class is wrapping */
  private val xml = new XMLEventReader( Source.fromFile( file ) )

  /**
   * Wrapper for the XMLEventReader's next method. Returns the next XMLEvent object
   *
   * @return The next XMLEvent
   */
  def next() : XMLEvent =
  {
    xml.next()
  }

  /**
   * Method to check if the XMLEventReader has more XMLEvent Objects
   *
   * @return True if another XMLEvent object exists
   * @return False if this is the last XMLEvent
   */
  def hasNext : Boolean =
  {
    xml.hasNext
  }
}
