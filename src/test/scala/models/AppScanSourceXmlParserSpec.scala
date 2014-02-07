package test.scala.models

import models.AppScanSourceXmlParser
import main.ParsedAppScanSourceXmlData
import models.wrappers.{ SystemEvents, EventReader }

import org.scalatest.FunSpec
import org.mockito.Mockito._
import org.mockito.{Mockito, Matchers}
import org.scalatest.junit.JUnitRunner
import org.junit.runner.RunWith
import org.scalatest.PrivateMethodTester._
import scala.xml.{MetaData, Unparsed, UnprefixedAttribute, Null}
import scala.xml.pull.{EvElemEnd, EvElemStart}
import scala.collection.mutable

@RunWith( classOf[ JUnitRunner ] )
class AppScanSourceXmlParserSpec extends FunSpec
{
  describe( "Testing the AppScanSourceXmlParser class" )
  {
    describe( "Testing the protected methods" )
    {
      def fixture =
        new {
          val system = mock( classOf[ SystemEvents ] )
          doNothing().when( system ).exit( Matchers.anyInt() )

          val parser = new AppScanSourceXmlParser( system, "Linux" )
          val data = new ParsedAppScanSourceXmlData
          val meta = new UnprefixedAttribute( "Test", Option( Seq( new Unparsed( "Test" ) ) ), Null )
        }

      describe( "Testing the getAttribute method" )
      {
        val getAttribute = PrivateMethod[ String ]( 'getAttribute )

        it( "should return a string so long as the attribute is present in the MetaData object" )
        {
          val fix = fixture

          val test = fix.parser invokePrivate getAttribute( fix.meta, "Test" )

          assert( test == "Test" )
        }

        it( "should return null if the attribute does not exist in the MetaData object" )
        {
          val fix = fixture

          val test = fix.parser invokePrivate getAttribute( fix.meta, "none" )

          assert( test == null )
        }
      }

      describe( "Testing the parseListOfMaps method" )
      {
        val parseListOfMaps = PrivateMethod( 'parseListOfMaps )

        it( "throws an error if the wrong list type is provided" )
        {
          val fix = fixture

          intercept[ Throwable ]
          {
            fix.parser invokePrivate parseListOfMaps( fix.meta, "incorrect", fix.data )
          }
        }

        it( "adds finding data to the data object when the list type findings is provided" )
        {
          val fix = fixture

          fix.parser invokePrivate parseListOfMaps( fix.meta, "findings", fix.data )

          assert( !fix.data.getFindings.isEmpty )
          assert( fix.data.getSites.isEmpty )
          assert( fix.data.getTaints.isEmpty )
          assert( fix.data.getTaintFindings.isEmpty )
        }

        it( "adds site data to the data object when the list type sites is provided" )
        {
          val fix = fixture

          fix.parser invokePrivate parseListOfMaps( fix.meta, "sites", fix.data )

          assert( fix.data.getFindings.isEmpty )
          assert( !fix.data.getSites.isEmpty )
          assert( fix.data.getTaints.isEmpty )
          assert( fix.data.getTaintFindings.isEmpty )
        }

        it( "adds taint data to the data object when the list type taints is provided" )
        {
          val fix = fixture

          fix.parser invokePrivate parseListOfMaps( fix.meta, "taints", fix.data )

          assert( fix.data.getFindings.isEmpty )
          assert( fix.data.getSites.isEmpty )
          assert( !fix.data.getTaints.isEmpty )
          assert( fix.data.getTaintFindings.isEmpty )
        }

        it( "adds taint finding data to the data object when the list type taintFinding is provided" )
        {
          val fix = fixture

          fix.parser invokePrivate parseListOfMaps( fix.meta, "taintFinding", fix.data )

          assert( fix.data.getFindings.isEmpty )
          assert( fix.data.getSites.isEmpty )
          assert( fix.data.getTaints.isEmpty )
          assert( !fix.data.getTaintFindings.isEmpty )
        }
      }

      describe( "Testing the setFiles method" )
      {
        val setFiles = PrivateMethod( 'setFiles )

        it( "adds a file to the list if the path is valid, converts \\ characters to / characters on windows" )
        {
          val fix = fixture
          val file = new UnprefixedAttribute( "value", Option( Seq( new Unparsed( "C:\\test\\path\\file.java" ) ) ), Null )
          val id = new UnprefixedAttribute( "id", Option( Seq( new Unparsed( "2" ) ) ), file )
          val parser = new AppScanSourceXmlParser( fix.system, "Windows" )
          val data = new ParsedAppScanSourceXmlData

          data.setOs( "Windows" )

          data.setCodeLocation( "C:\\test\\" )
          parser invokePrivate setFiles( id, data )

          assert( data.getFiles.keys.head == "2")
          assert( data.getFiles.get( data.getFiles.keys.head ).getOrElse( null ) == "path/file.java" )
        }

        it( "adds a file to the list if the path is valid, does not convert / characters on linux" )
        {
          val fix = fixture
          val file = new UnprefixedAttribute( "value", Option( Seq( new Unparsed( "/test/path/file.java" ) ) ), Null )
          val id = new UnprefixedAttribute( "id", Option( Seq( new Unparsed( "2" ) ) ), file )


          fix.data.setOs( "Linux" )
          fix.data.setCodeLocation( "/test/" )

          fix.parser invokePrivate setFiles( id, fix.data )

          assert( fix.data.getFiles.keys.head == "2" )
          assert( fix.data.getFiles.get( fix.data.getFiles.keys.head ).getOrElse( null ) == "path/file.java" )
        }

        it( "does not add a file to the list if the path is invalid, and exits the application" )
        {
          val fix = fixture
          val file = new UnprefixedAttribute( "value", Option( Seq( new Unparsed( "/test/path/file.java" ) ) ), Null )
          val id = new UnprefixedAttribute( "id", Option( Seq( new Unparsed( "2" ) ) ), file )

          fix.data.setOs( "Linux" )
          fix.data.setCodeLocation( "/wrong/" )
          fix.parser invokePrivate setFiles( id, fix.data )

          assert( fix.data.getFiles.keys.isEmpty )
          verify( fix.system, times( 1 ) ).exit( 1 )
        }
      }

      describe( "Testing the setStrings method" )
      {
        val setStrings = PrivateMethod( 'setStrings )

        it( "adds a new string to the list, so long as the key exists" )
        {
          val fix = fixture
          val string = new UnprefixedAttribute( "id", Option( Seq( new Unparsed( "2" ) ) ), Null )
          val id = new UnprefixedAttribute( "value", Option( Seq( new Unparsed( "test" ) ) ), string )

          fix.parser invokePrivate setStrings( id, fix.data )

          assert( fix.data.getStrings.keys.head == "2" )
          assert( fix.data.getStrings.get( fix.data.getStrings.keys.head ).getOrElse( null ) == "test" )
        }
      }
    }

    describe( "Testing the main parsing loop" )
    {
      val fixture =
        new {
          val event = mock( classOf[ EventReader ] )

          val system = mock( classOf[ SystemEvents ] )
          doNothing().when( system ).exit( Matchers.anyInt() )

          val parser = new AppScanSourceXmlParser( system, "Linux" )

          val data = new ParsedAppScanSourceXmlData
        }

      it( "will store the assessment name and if the label of the element is Assessment" )
      {
        val fix = fixture

        val spyOnParser = Mockito.spy( fix.parser )
        val assessmentName = new UnprefixedAttribute( "assessee_name", Option( Seq( new Unparsed( "Test" ) ) ), Null )

        when( fix.event.next ).thenReturn( new EvElemStart( null, "Assessment" , assessmentName, null ) )
        when( fix.event.hasNext ).thenReturn( true ).thenReturn( false )

        spyOnParser.parse( fix.event, fix.data )
        assert( fix.data.getAssessmentName == "Test" )

        verify( spyOnParser, times( 0 ) ).siteAndFindingLoop( "sites", fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).siteAndFindingLoop( "findings", fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).siteAndFindingLoop( "taints", fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).stringsAndFilesLoop( fix.event, fix.data )
        verify( spyOnParser, times( 1 ) ).assessmentLoopOuter( "Application", null, fix.event, fix.data )
      }

      it( "will hit the strings and files loop if the element label is StringPool" )
      {
        val fix = fixture
        val spyOnParser = Mockito.spy( fix.parser )

        when( fix.event.next ).thenReturn( new EvElemStart( null, "StringPool", Null, null ) )
        when( fix.event.hasNext ).thenReturn( true ).thenReturn( false )

        spyOnParser.parse( fix.event, fix.data )

        verify( spyOnParser, times( 0 ) ).siteAndFindingLoop( "sites", fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).siteAndFindingLoop( "findings", fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).siteAndFindingLoop( "taints", fix.event, fix.data )
        verify( spyOnParser, times( 1 ) ).stringsAndFilesLoop( fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).assessmentLoopOuter( "Application", null, fix.event, fix.data )
      }

      it( "will hit the strings and files loop if the element label is FilePool" )
      {
        val fix = fixture
        val spyOnParser = Mockito.spy( fix.parser )

        when( fix.event.next ).thenReturn( new EvElemStart( null, "FilePool", Null, null ) )
        when( fix.event.hasNext ).thenReturn( true ).thenReturn( false )

        spyOnParser.parse( fix.event, fix.data )


        verify( spyOnParser, times( 0 ) ).siteAndFindingLoop( "sites", fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).siteAndFindingLoop( "findings", fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).siteAndFindingLoop( "taints", fix.event, fix.data )
        verify( spyOnParser, times( 1 ) ).stringsAndFilesLoop( fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).assessmentLoopOuter( "Application", null, fix.event, fix.data )
      }

      it( "will call the final recursive loop for the element labeled SitePool" )
      {
        val fix = fixture
        val spyOnParser = Mockito.spy( fix.parser )

        when( fix.event.next ).thenReturn( new EvElemStart( null, "SitePool", Null, null ) )
        when( fix.event.hasNext ).thenReturn( true ).thenReturn( false )

        spyOnParser.parse( fix.event, fix.data )

        verify( spyOnParser, times( 1 ) ).siteAndFindingLoop( "sites", fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).siteAndFindingLoop( "findings", fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).siteAndFindingLoop( "taints", fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).stringsAndFilesLoop( fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).assessmentLoopOuter( "Application", null, fix.event, fix.data )
      }

      it( "will call the final recursive loop for the element labeled FindingDataPool" )
      {
        val fix = fixture
        val spyOnParser = Mockito.spy( fix.parser )

        when( fix.event.next ).thenReturn( new EvElemStart( null, "FindingDataPool", Null, null ) )
        when( fix.event.hasNext ).thenReturn( true ).thenReturn( false )

        spyOnParser.parse( fix.event, fix.data )

        verify( spyOnParser, times( 0 ) ).siteAndFindingLoop( "sites", fix.event, fix.data )
        verify( spyOnParser, times( 1 ) ).siteAndFindingLoop( "findings", fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).siteAndFindingLoop( "taints", fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).stringsAndFilesLoop( fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).assessmentLoopOuter( "Application", null, fix.event, fix.data )
      }

      it( "will call the final recursive loop for the element labeled TaintPool" )
      {
        val fix = fixture
        val spyOnParser = Mockito.spy( fix.parser )

        when( fix.event.next ).thenReturn( new EvElemStart( null, "TaintPool", Null, null ) )
        when( fix.event.hasNext ).thenReturn( true ).thenReturn( false )

        spyOnParser.parse( fix.event, fix.data )

        verify( spyOnParser, times( 0 ) ).siteAndFindingLoop( "sites", fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).siteAndFindingLoop( "findings", fix.event, fix.data )
        verify( spyOnParser, times( 1 ) ).siteAndFindingLoop( "taints", fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).stringsAndFilesLoop( fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).assessmentLoopOuter( "Application", null, fix.event, fix.data )
      }

      it( "will not call any recursive loop if the element has a different label" )
      {
        val fix = fixture
        val spyOnParser = Mockito.spy( fix.parser )

        when( fix.event.next ).thenReturn( new EvElemStart( null, "WrongLabel", Null, null ) )
        when( fix.event.hasNext ).thenReturn( true ).thenReturn( false )

        spyOnParser.parse( fix.event, fix.data )

        verify( spyOnParser, times( 0 ) ).siteAndFindingLoop( "sites", fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).siteAndFindingLoop( "findings", fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).siteAndFindingLoop( "taints", fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).stringsAndFilesLoop( fix.event, fix.data )
        verify( spyOnParser, times( 0 ) ).assessmentLoopOuter( "Application", null, fix.event, fix.data )
      }
    }

    describe( "Testing the recursive looping functions" )
    {
      class ParserStub( system : SystemEvents, operatingSystem : String ) extends AppScanSourceXmlParser( system : SystemEvents, operatingSystem : String )
      {
        override protected def setStrings( attribs : MetaData, parsedData : ParsedAppScanSourceXmlData )
        {
          parsedData.addString( "test", "test" )
        }

        override protected def setFiles( attribs : MetaData, parsedData : ParsedAppScanSourceXmlData )
        {
          parsedData.addFile( "test", "test" )
        }

        override protected def parseListOfMaps( attribs : MetaData, inprogressList : String,
                                                parsedData : ParsedAppScanSourceXmlData )
        {
          var toAdd = new mutable.ListMap[ String, String ]
          toAdd += ( "test" -> "test" )

          inprogressList match
          {
            case "sites" =>
              parsedData.addSite( toAdd.toMap )
            case "findings" =>
              parsedData.addFinding( toAdd.toMap )
            case "taints" =>
              parsedData.addTaint( toAdd.toMap )
            case "taintFindings" =>
              parsedData.addTaintFinding( toAdd.toMap )
          }
        }
      }

      val fixture =
        new {
          val event = mock( classOf[ EventReader ] )

          val parser = new ParserStub( new SystemEvents(), "Linux" )
        }

      describe( "Testing the strings and files loop" )
      {
        it( "will add a string to the list if the element found has the label String" )
        {
          val fix = fixture
          val data = new ParsedAppScanSourceXmlData

          val attribs = new UnprefixedAttribute( "bar", Option( Seq( new Unparsed( "foo" ) ) ), Null )

          when( fix.event.next ).thenReturn( new EvElemStart( null, "String", attribs, null ) )
          when( fix.event.hasNext ).thenReturn( true ).thenReturn( false )

          fix.parser.stringsAndFilesLoop( fix.event, data )

          assert( data.getStrings.get( "test" ).getOrElse( null ) == "test" )
          assert( data.getFiles.get( "test" ).getOrElse( null ) == null )
        }

        it( "will add a file to the list if the element found has the label File" )
        {
          val fix = fixture
          val data = new ParsedAppScanSourceXmlData

          val attribs = new UnprefixedAttribute( "bar", Option( Seq( new Unparsed( "foo" ) ) ), Null )

          when( fix.event.next ).thenReturn( new EvElemStart( null, "File", attribs, null ) )
          when( fix.event.hasNext ).thenReturn( true ).thenReturn( false )

          fix.parser.stringsAndFilesLoop( fix.event, data )

          assert( data.getStrings.get( "test" ).getOrElse( null ) == null )
          assert( data.getFiles.get( "test" ).getOrElse( null ) == "test" )
        }

        it( "will not add a new string or file to the list if the element has a different label" )
        {
          val fix = fixture
          val data = new ParsedAppScanSourceXmlData

          val attribs = new UnprefixedAttribute( "bar", Option( Seq( new Unparsed( "foo" ) ) ), Null )

          when( fix.event.next ).thenReturn( new EvElemStart( null, "Nope", attribs, null ) )
          when( fix.event.hasNext ).thenReturn( true ).thenReturn( false )

          fix.parser.stringsAndFilesLoop( fix.event, data )

          assert( data.getStrings.get( "test" ).getOrElse( null ) == null )
          assert( data.getFiles.get( "test" ).getOrElse( null ) == null )
        }

        it( "Does not recurse if the ending StringPool element is found" )
        {
          val fix = fixture
          val data = new ParsedAppScanSourceXmlData

          val attribs = new UnprefixedAttribute( "bar", Option( Seq( new Unparsed( "foo" ) ) ), Null )

          when( fix.event.next ).thenReturn( new EvElemEnd( null, "StringPool" ) ).thenReturn(
            new EvElemStart( null, "String", attribs, null ) )
          when( fix.event.hasNext ).thenReturn( true ).thenReturn( true ).thenReturn( false )

          fix.parser.stringsAndFilesLoop( fix.event, data )

          assert( data.getStrings.get( "test" ).getOrElse( null ) == null )
        }

        it( "does not recurse if the ending FilePool element is found" )
        {
          val fix = fixture
          val data = new ParsedAppScanSourceXmlData

          val attribs = new UnprefixedAttribute( "bar", Option( Seq( new Unparsed( "foo" ) ) ), Null )

          when( fix.event.next ).thenReturn( new EvElemEnd( null, "FilePool" ) ).thenReturn(
            new EvElemStart( null, "String", attribs, null ) )
          when( fix.event.hasNext ).thenReturn( true ).thenReturn( true ).thenReturn( false )

          fix.parser.stringsAndFilesLoop( fix.event, data )

          assert( data.getStrings.get( "test" ).getOrElse( null ) == null )
        }
      }

      describe( "Testing the site, finding, and taint loop" )
      {
        it( "throws an error if the list type is not supported" )
        {
          val fix = fixture
          val data = new ParsedAppScanSourceXmlData

          val attribs = new UnprefixedAttribute( "bar", Option( Seq( new Unparsed( "foo" ) ) ), Null )
          when( fix.event.next ).thenReturn( new EvElemStart(  null, "Site", attribs, null ) )
          when( fix.event.hasNext ).thenReturn( true )

          intercept[ Throwable ]
          {
            fix.parser.siteAndFindingLoop( "Wrong", fix.event, data )
          }
        }

        it( "records the site data if the element found is Site" )
        {
          val fix = fixture
          val data = new ParsedAppScanSourceXmlData

          val attribs = new UnprefixedAttribute( "bar", Option( Seq( new Unparsed( "foo" ) ) ), Null )
          when( fix.event.next ).thenReturn( new EvElemStart(  null, "Site", attribs, null ) )
          when( fix.event.hasNext ).thenReturn( true ).thenReturn( false )

          fix.parser.siteAndFindingLoop( "sites", fix.event, data )

          assert( data.getSites.result().head.get( "test" ).getOrElse( null ) == "test" )
          assert( data.getFindings.result().length == 0 )
          assert( data.getTaints.result().length == 0 )
        }

        it( "records the finding data if the element found is Site" )
        {
          val fix = fixture
          val data = new ParsedAppScanSourceXmlData

          val attribs = new UnprefixedAttribute( "bar", Option( Seq( new Unparsed( "foo" ) ) ), Null )
          when( fix.event.next ).thenReturn( new EvElemStart(  null, "FindingData", attribs, null ) )
          when( fix.event.hasNext ).thenReturn( true ).thenReturn( false )

          fix.parser.siteAndFindingLoop( "findings", fix.event, data )

          assert( data.getFindings.result().head.get( "test" ).getOrElse( null ) == "test" )
          assert( data.getSites.result().length == 0 )
          assert( data.getTaints.result().length == 0 )
        }

        it( "records the taint data if the element found is Taint" )
        {
          val fix = fixture
          val data = new ParsedAppScanSourceXmlData

          val attribs = new UnprefixedAttribute( "bar", Option( Seq( new Unparsed( "foo" ) ) ), Null )
          when( fix.event.next ).thenReturn( new EvElemStart(  null, "Taint", attribs, null ) )
          when( fix.event.hasNext ).thenReturn( true ).thenReturn( false )

          fix.parser.siteAndFindingLoop( "taints", fix.event, data )

          assert( data.getTaints.result().head.get( "test" ).getOrElse( null ) == "test" )
          assert( data.getFindings.result().length == 0 )
          assert( data.getSites.result().length == 0 )
        }

        it( "does not recurse if the ending element is found for the SitePool" )
        {
          val fix = fixture
          val event = mock( classOf[ EventReader ] )

          val data = new ParsedAppScanSourceXmlData

          val attribs = new UnprefixedAttribute( "bar", Option( Seq( new Unparsed( "foo" ) ) ), Null )

          when( event.next ).thenReturn( new EvElemEnd( null, "SitePool" ) ).thenReturn(
            new EvElemStart( null, "Site", attribs, null ) )
          when( event.hasNext ).thenReturn( true ).thenReturn( true ).thenReturn( false )

          fix.parser.siteAndFindingLoop( "sites", event, data )

          verify( event, times( 1 ) ).hasNext
          assert( data.getSites.result().length == 0 )
          assert( data.getFindings.result().length == 0 )
          assert( data.getTaints.result().length == 0 )
        }

        it( "does not recurse if the ending element is found for the FindingDataPool" )
        {
          val fix = fixture
          val event = mock( classOf[ EventReader ] )
          val data = new ParsedAppScanSourceXmlData

          val attribs = new UnprefixedAttribute( "bar", Option( Seq( new Unparsed( "foo" ) ) ), Null )

          when( event.next ).thenReturn( new EvElemEnd( null, "FindingDataPool" ) ).thenReturn(
            new EvElemStart( null, "FindingData", attribs, null ) )
          when( event.hasNext ).thenReturn( true ).thenReturn( true ).thenReturn( false )

          fix.parser.siteAndFindingLoop( "findings", event, data )

          verify( event, times( 1 ) ).hasNext
          assert( data.getSites.result().length == 0 )
          assert( data.getFindings.result().length == 0 )
          assert( data.getTaints.result().length == 0 )
        }

        it( "does not recurse if the ending element is found for the TaintPool" )
        {
          val fix = fixture
          val event = mock( classOf[ EventReader ] )
          val data = new ParsedAppScanSourceXmlData

          val attribs = new UnprefixedAttribute( "bar", Option( Seq( new Unparsed( "foo" ) ) ), Null )

          when( event.next ).thenReturn( new EvElemEnd( null, "TaintPool" ) ).thenReturn(
            new EvElemStart( null, "Taint", attribs, null ) )
          when( event.hasNext ).thenReturn( true ).thenReturn( true ).thenReturn( false )

          fix.parser.siteAndFindingLoop( "taints", event, data )

          verify( event, times( 1 ) ).hasNext
          assert( data.getSites.result().length == 0 )
          assert( data.getFindings.result().length == 0 )
          assert( data.getTaints.result().length == 0 )
        }
      }

      describe( "Testing the assessment loop" )
      {
        it( "will re-call the loop and add no data for an Assessment element of assessee_type of Application" )
        {
          val fix = fixture
          val event = mock( classOf[ EventReader ] )
          val data = new ParsedAppScanSourceXmlData

          val attribs = new UnprefixedAttribute( "assessee_type", Option( Seq( new Unparsed( "Application" ) ) ), Null )


          when( event.next ).thenReturn( new EvElemStart( null, "Assessment", attribs, null ) )
          when( event.hasNext ).thenReturn( true ).thenReturn( false )

          fix.parser.assessmentLoopOuter( "Application", null, event, data )

          verify( event, times( 2 ) ).hasNext
          assert( data.getProjects.length == 0 )
          assert( data.getFilesByProject.length == 0 )
          assert( data.getFileErrors.size == 0 )
          assert( data.getTaintFindings.size == 0 )
        }

        it( "will re-call the loop and add project data for an Assessment element of assessee_type of Project" )
        {
          val fix = fixture
          val event = mock( classOf[ EventReader ] )
          val data = new ParsedAppScanSourceXmlData

          val name = new UnprefixedAttribute( "assessee_name", Option( Seq( new Unparsed( "test" ) ) ), Null )
          val attribs = new UnprefixedAttribute( "assessee_type", Option( Seq( new Unparsed( "Project" ) ) ), name )


          when( event.next ).thenReturn( new EvElemStart( null, "Assessment", attribs, null ) )
          when( event.hasNext ).thenReturn( true ).thenReturn( false )

          fix.parser.assessmentLoopOuter( "Application", null, event, data )

          verify( event, times( 2 ) ).hasNext
          assert( data.getProjects.length == 1 )
          assert( data.getFilesByProject.length == 0 )
          assert( data.getFileErrors.size == 0 )
          assert( data.getTaintFindings.size == 0 )
        }

        it( "will end the assessments loop if an element of type Messages is reached" )
        {
          val fix = fixture
          val event = mock( classOf[ EventReader ] )
          val data = new ParsedAppScanSourceXmlData

          when( event.next ).thenReturn( new EvElemStart( null, "Messages", Null, null ) )
          when( event.hasNext ).thenReturn( true ).thenReturn( false )

          fix.parser.assessmentLoopOuter( "Application", null, event, data )

          verify( event, times( 1 ) ).hasNext
          assert( data.getProjects.length == 0 )
          assert( data.getFilesByProject.length == 0 )
          assert( data.getFileErrors.size == 0 )
          assert( data.getTaintFindings.size == 0 )
        }

        it( "will map a file to a project if an element of type AsmntFile is reached" )
        {
          val fix = fixture
          val event = mock( classOf[ EventReader ] )
          val data = new ParsedAppScanSourceXmlData

          val map = new mutable.ListMap[ String, String ]
          map += ( "owner" -> "test" )
          map += ( "name" -> "test" )
          data.addProject( map.toMap )

          val attribs = new UnprefixedAttribute( "file_id", Option( Seq( new Unparsed( "test" ) ) ), Null )


          when( event.next ).thenReturn( new EvElemStart( null, "AsmntFile", attribs, null ) )
          when( event.hasNext ).thenReturn( true ).thenReturn( false )

          fix.parser.assessmentLoopOuter( "Project", null, event, data )

          verify( event, times( 2 ) ).hasNext
          assert( data.getProjects.length == 1 )
          assert( data.getFilesByProject.length == 1 )
          assert( data.getFileErrors.size == 0 )
          assert( data.getTaintFindings.size == 0 )
        }

        it( "will re-call the loop and add no data for an AssessmentStats element" )
        {
          val fix = fixture
          val event = mock( classOf[ EventReader ] )
          val data = new ParsedAppScanSourceXmlData

          when( event.next ).thenReturn( new EvElemStart( null, "AssessmentStats", Null, null ) )
          when( event.hasNext ).thenReturn( true ).thenReturn( false )

          fix.parser.assessmentLoopOuter( "Application", null, event, data )

          verify( event, times( 2 ) ).hasNext
          assert( data.getProjects.length == 0 )
          assert( data.getFilesByProject.length == 0 )
          assert( data.getFileErrors.size == 0 )
          assert( data.getTaintFindings.size == 0 )
        }
      }
    }
  }
}