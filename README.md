This project is a library that implements RFC 7030 (Enrollment over Secure Transport).  EST is used to provision certificates from a CA or RA.  EST is a replacement for SCEP, providing several security enhancements and support for ECC certificates.  Libest is written in C and uses OpenSSL 1.0.1.  The following flows defined in RFC 7030 for both server and client operation have been implemented:

/getcacerts
/csrattrs
/simpleenroll
/simplereenroll

Also of interest, an EST test server running this library has been setup at
http://testrfc7030.com/ and can be used for interop testing the EST 
protocol.

Please direct questions/comments to est-interest@external.cisco.com
