package test.scala.models

import models.data.{AppScanStringMatcher, DataCompilation}
import models.UploadAppScanSourceXml
import main.ParsedAppScanSourceXmlData

import org.scalatest.FunSpec
import org.mockito.Mockito._
import org.mockito.{Mockito, Matchers}
import org.scalatest.junit.JUnitRunner
import org.junit.runner.RunWith
import javax.xml.validation.{Schema, SchemaFactory}
import javax.xml.transform.stream.StreamSource
import org.xml.sax.SAXException
import com.mongodb.casbah.Imports._
import scala.collection.mutable.ListBuffer
import scala.collection.mutable

@RunWith( classOf[ JUnitRunner ] )
class UploadAppScanSourceXmlSpec extends FunSpec
{
  describe( "Testing the UploadAppScanSourceXml class" )
  {

    describe( "which has a method called createOuptut" )
    {
      class UploadStub( operatingSystem : String, dataCompiler : DataCompilation, stringMatcher : AppScanStringMatcher )
        extends UploadAppScanSourceXml( operatingSystem : String, dataCompiler : DataCompilation,
          stringMatcher : AppScanStringMatcher )
      {
        var numCalls = 0

        override protected def uploadResults( finding : MongoDBObject, issuesConn : MongoConnection  )
        {
          numCalls = numCalls + 1
        }
      }

      it( "uploads each finding record individually" )
      {
        val mockData = mock( classOf[ DataCompilation] )
        val mockMatcher = mock( classOf[ AppScanStringMatcher ] )
        val mockParsedData = mock( classOf[ ParsedAppScanSourceXmlData ] )
        val mockIssues = mock( classOf[ MongoConnection ] )

        val upload = new UploadStub( "Linux", mockData, mockMatcher )

        val map = new mutable.ListMap[ String, String ]
        val list = new ListBuffer[ Map[ String, String ] ]

        map += ( "test" -> "test" )
        list += map.toMap
        list += map.toMap


        doNothing().when( mockMatcher ).mapStringToSites( null, null, null, mockParsedData )
        doNothing().when( mockIssues ).close()
        when( mockParsedData.getFindings ).thenReturn( list )
        when( mockParsedData.getTaintFindings ).thenReturn( new ListBuffer[ Map[ String, String ] ] )

        upload.createOutput( mockParsedData, mockIssues )

        assert( upload.numCalls == 2 )
      }
    }
  }
}