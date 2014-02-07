package test.scala.models

import models.Validator

import org.scalatest.FunSpec
import org.mockito.Mockito._
import org.mockito.Matchers
import org.scalatest.junit.JUnitRunner
import org.junit.runner.RunWith
import javax.xml.validation.{Schema, SchemaFactory}
import javax.xml.transform.stream.StreamSource
import org.xml.sax.SAXException

@RunWith( classOf[ JUnitRunner ] )
class ValidatorSpec extends FunSpec
{
  describe( "Testing the Validator class" )
  {
    describe( "Testing the validate function" )
    {
      def fixture =
        new {
          val mockFactory = mock( classOf[ SchemaFactory ] )
          val mockValidator = mock( classOf[ javax.xml.validation.Validator ] )
          val mockSchema = mock( classOf[ Schema ] )

          when( mockFactory.newSchema( Matchers.any( classOf[ StreamSource ] ) ) ).thenReturn( mockSchema )
          when( mockSchema.newValidator ).thenReturn( mockValidator )
        }

      class ValidatorStub( schemaLang : String, mockFactory : SchemaFactory ) extends Validator( schemaLang : String )
      {
        override protected def getFactory : SchemaFactory =
        {
          return mockFactory
        }
      }

      it( "should validate a properly formatted .ozasmt file" )
      {
        val fix = fixture
        doNothing().when( fix.mockValidator ).validate( new StreamSource( Matchers.anyString() ) )
        val stub = new ValidatorStub( "test", fix.mockFactory )

        assert( stub.validate( "One", "Two" ) == true )
      }

      it( "should fail if the .ozasmt file is improperly formatted" )
      {
        val fix = fixture
        val stub = new ValidatorStub( "test", fix.mockFactory )
        doThrow( classOf[ SAXException ] ).when( fix.mockValidator ).validate( new StreamSource( Matchers.anyString() ) )

        assert( stub.validate( "One", "Two" ) == false )
      }

      it( "should fail if the .ozasmt file does not exist" )
      {
        val fix = fixture
        val stub = new ValidatorStub( "test", fix.mockFactory )
        doThrow( classOf[ Exception ] ).when( fix.mockSchema ).newValidator()

        assert( stub.validate( "One", "Two" ) == false )
      }
    }
  }
}
