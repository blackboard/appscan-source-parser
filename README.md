The AppScan Source Parser Scala application takes a .ozasmt file from AppScan Source, as well as the source directory
for the code that was scanned, as input, and inserts them into a MongoDB database. The purpose of doing this is to remove duplication
from multiple scans against the same application, and provide the data to another application to display.

To use this application, you can execute it using a gradle command:

    gdl run -Ppropname="<argument_list>"

The argument list contains 4 required parameters:

    Usage:
       -f (--file) <filename>               -- Provides the name of the appscan source assessment filename for parsing
       -o (--OS) <operating system>         -- Provides the type of OS in use (Windows, Linux). Defaults to Linux
       -m (--mongo-db-server) <server>      -- Provides the hostname of the MongoDB server
       -c (--code-location) <path-to-code>  -- Provides a file path to the code (ideally ending with release
                                               version, however, mainline is assumed)

    Example:
       run -f test.ozasmt -o Windows -m localhost -c /usr/local/p4/B2/projects/date-management/mainline/

