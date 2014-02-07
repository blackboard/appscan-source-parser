package models

import javax.xml.validation.SchemaFactory
import javax.xml.transform.stream.StreamSource
import org.xml.sax.SAXException

class Validator( schemaLang : String )
{
  /**
   * Validation method for the .ozasmt file.
   *
   * @param xmlFile The file passed in
   * @param xsdFile The XSD file used to validate the xml file
   * @return True if the file is valid, false otherwise
   */
  def validate(xmlFile: String, xsdFile: String ): Boolean =
  {
    try
    {
      //setting up a classloader object to obtain the xsdFile from inside a Jar
      val loader = this.getClass.getClassLoader
      val source = loader.getResourceAsStream( xsdFile )

      val factory = this.getFactory
      //Instantiate a schema object from the factory
      var schema = factory.newSchema( new StreamSource( source ) )
      //Create a new schema validation object
      val validator = schema.newValidator()
      //Validate our XML file
      validator.validate(new StreamSource(xmlFile))

      //Return true if no errors are thrown
      return true
    }
    catch
    {
      //Display the schema failure message and return false
      case ex: SAXException =>
        println(ex.getMessage());
        return false
      case ex: Exception =>
        ex.printStackTrace()
        return false
    }
  }

  /**
   * Private method used to instantiate a new SchemaFactory based on the schemaLang passed into the
   * constructor.
   *
   * @return A SchemaFactory object
   */
  protected def getFactory : SchemaFactory =
  {
    return SchemaFactory.newInstance( this.schemaLang )
  }
}