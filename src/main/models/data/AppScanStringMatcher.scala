package models.data

import main.ParsedAppScanSourceXmlData
import scala.collection.mutable
import scala.collection.mutable.ListBuffer

class AppScanStringMatcher
{
  /**
   * Function for mapping values in taint records with strings where appropriate, which is just the arg_name. Also
   * makes the list searchable by the taint's id value, allowing for easier lookup later
   *
   * @param parsedData The container object containing all of the data parsed during various points in this application
   * @return The list of taints, with strings mapped, searchable by taint_id
   */
  def createTaintStrings( parsedData : ParsedAppScanSourceXmlData ) : mutable.ListMap[ String, Map[ String, String ] ] =
  {
    //Performance and clarity improvements, retrieving the data from the container first, rather than each lookup
    val taints = parsedData.getTaints
    val strings = parsedData.getStrings

    //The object to store the taint lookups, with strings included where appropriate
    var taintStrings = new mutable.ListMap[ String, Map[ String, String ] ]

    //Iterates through the list of taint records retrieved from the XML file
    for( taint <- taints )
    {
      //Builder for the taint list
      var taintString = new mutable.ListMap[ String, String ]

      //Stores the argument type record, currently unused
      taintString += ( "arg" -> taint.get( "arg" ).getOrElse( null ) )
      //Stores the name of the argument
      taintString += ( "arg_name" -> strings.get( taint.get( "arg_name" ).getOrElse( null ) ).getOrElse( null ) )
      //Stores the direction indicator, currently unused since we will be creating this diagram using a parent record
      taintString += ( "dir" -> taint.get( "dir" ).getOrElse( null ) )
      //Stores the taint identifier
      taintString += ( "taint_id" -> taint.get( "id" ).getOrElse( null ) )
      //Stores the site identifier
      taintString += ( "site_id" -> taint.get( "id" ).getOrElse( null ) )
      //Stores the trace type record
      //TODO: Create lookup table for the trace type values
      taintString += ( "trace_type" -> taint.get( "trace_type" ).getOrElse( null ) )

      //Store the results of the mappings above
      val taintMap = taintString.toMap
      //add the above to the list of taintStrings, and make it part of a lookup table by mapping it by taint_id
      taintStrings += ( taint.get( "id" ).getOrElse( null ) -> taintMap )
    }

    return taintStrings
  }

  /**
   * Function to take the list of sites, and add to them the appropriate strings from the list. Adds this information to the
   * parsedData object
   *
   * @param siteList List of sites populated with string number mappings
   * @param strings List of strings that map to numbers
   * @param files List of files that map to file_ids
   * @param parsedData Object that will contain our parsed site data
   */
  def mapStringToSites( siteList : ListBuffer[ Map[ String, String ] ], strings : mutable.ListMap[ String, String ],
                                files: mutable.ListMap[ String, String ], parsedData : ParsedAppScanSourceXmlData )
  {
    //iterate through the set of sites and map string values and file values to them
    for( site <- siteList )
    {
      //Object to contain the new site with full mappings from files and strings
      var siteStrings = new mutable.ListMap[ String, String ]

      //append the file name
      siteStrings += ( "file" -> files.get( site.get( "file_id" ).getOrElse( null ) ).getOrElse( null ) )
      //append the caller name (usually a method name, but can also be a class name) mapped from a string
      siteStrings += ( "caller" -> strings.get( site.get( "caller" ).getOrElse( null ) ).getOrElse( null ) )
      //append the column number, currently unused
      siteStrings += ( "cn" -> site.get( "cn" ).getOrElse( null ) )
      //append the context data mapped from a string
      siteStrings += ( "ctx" -> strings.get( site.get( "ctx" ).getOrElse( null ) ).getOrElse( null ) )
      //append the line number of the vulnerability
      siteStrings += ( "ln" -> site.get( "ln" ).getOrElse( null ) )
      //append the vulnerability identifier to the object
      siteStrings += ( "method" -> strings.get( site.get( "method" ).getOrElse( null ) ).getOrElse( null ) )
      //append the ordinal value of the vulnerability, currently unused
      siteStrings += ( "ord" -> site.get( "ord" ).getOrElse( null ) )
      //append the signature of the vulnerability, appears to be deprecated, currently unused
      siteStrings += ( "sig" -> site.get( "sig" ).getOrElse( null ) )

      //append the entity name for the vulnerability, if one exists
      if( site.get( "entity_name" ).getOrElse( null ) != null )
      {
        siteStrings += ( "entity_name" -> strings.get( site( "entity_name" ) ).getOrElse( null ) )
      }

      //append the entity type for this vulnerability, if one exists
      if( site.get( "entity_type" ).getOrElse( null ) != null )
      {
        siteStrings += ( "entity_type" -> strings.get( site( "entity_type" ) ).getOrElse( null ) )
      }

      //add the site to the container object for use later
      parsedData.addSiteStrings( site.get( "id" ).getOrElse( null ), siteStrings.toMap )
    }
  }
}