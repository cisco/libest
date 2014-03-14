The project is a placeholder for libest, which is a library that implements RFC 7030 (Enrollment over Secure Transport).  EST is used to provision certificates from a CA or RA.  EST is a replacement for SCEP, providing several security enhancements and support for ECC certificates.  Libest is written in C and uses OpenSSL.  The following flows defined in RFC 7030 for both server and client operation have been implemented:

/getcacerts
/csrattrs
/simpleenroll
/simplereenroll

Cisco plans to release libest under the same license as libsrtp.  We are currently going through the final internal legal approvals and plan to release the code in the near future.  
