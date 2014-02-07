package models.wrappers

/**
 * Wrapper for various System events called throughout the application, such as the exit event. This is
 * so that we can deal with these types of events when testing by mocking away said disruptive event
 */
class SystemEvents
{
  /**
   * Wrapping the System.exit function, so that during testing the application does not exit prematurely
   *
   * @param statusCode The exit status to pass to the System.exit call
   */
  def exit( statusCode : Int )
  {
    System.exit( statusCode )
  }
}
