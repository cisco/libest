package com.cisco.c3m.est.test.DT;

import static org.junit.Assert.*;

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.junit.*;
import org.junit.rules.ExpectedException;
import static org.junit.Assert.*;

import java.io.*;
import java.util.*;

import java.math.BigInteger;

import java.util.Date;
import java.util.Enumeration;
import java.util.logging.*;

import java.security.*;
import java.security.spec.ECGenParameterSpec;


import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import com.cisco.c3m.est.BufferSizeException;
import com.cisco.c3m.est.ESTClient;
import com.cisco.c3m.est.EncodingException;
import com.cisco.c3m.est.EnrollException;
import com.cisco.c3m.est.EnrollRetryAfterException;
import com.cisco.c3m.est.PKCS10CertificateRequest;
import com.cisco.c3m.est.ESTClient.NativeLogLevel;
import com.cisco.c3m.est.PKCS10CreationException;

/*
 * In order to run most of these tests we need an estserver running.
 * To take care of that we use a shell script "dt_start_estserver1.sh"
 * and call it in the setUpBeforeClass method which runs before
 * the other test methods are started.  Currently (Nov 2014) there
 * are multiple instances of estserver started by this script.
 * 
 * There have been some timing issues we have tried to adjust to in
 * starting the estservers.  The junit tests run quickly and it seems
 * that sometimes the estservers are not "ready" by the time the first
 * connections are attempted.  Also we rely on a timer to kill the 
 * estserver instances - so there can be overlap (one still running when
 * another is started) if you run the junit suite quickly in succession.
 * 
 * This test class assumes the following environment variables are set:
 * 
 * EST_TRUST     - Location of JKS file that contains trusted certs
 *
 *     NOTE: The estservers should be started by the script called in setUpBeforeClass
 *           below.  The script name is set in that method.  But the script is checked in to svn.
 *           This way the script can be adjusted (if needed) without changing the method.
 *                    
 * EST_ADDR   - IP address of EST server
 */
public class ESTClientTest {
	private static X509Certificate[] certs;
	private static String mTrustDB;
	private static String mTestServer = new String("127.0.0.1");
	
	/*
	 *  The following ports are used by the client to connect to estserver
	 *  instances.  The actual port numbers will be set later by getting
	 *  environment variables that need to be set before starting the tests.
	 */
	// port that estserver should be running on
	private static int mTestPort = 0;
	// another estserver instance set up for retry
	private static int mTestPortRetry = 0;
	// another estserver instance set up for http digest authentication
	private static int mTestPortDigest = 0;
	// port2 that estserver should be running on
	private static int mTestPort2 = 0;
	
	private static KeyPair mKey;
	private static PKCS10CertificateRequest mCSR;

        // The logger and stream handler are needed
        private static final Logger logger = Logger.getLogger(ESTClientTest.class.getName());
        private static StreamHandler shOut = new StreamHandler(System.out, new SimpleFormatter());
        private static StreamHandler shErr = new StreamHandler(System.err, new SimpleFormatter());
        
	private static X509Certificate selfSignedCert;
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
        logger.setLevel(Level.INFO);
	    System.out.println("*******************************************************");
	    System.out.println("Running setUpBeforeClass ...");
	    System.out.println("Testing CiscoJEST Version " + ESTClient.getVersion() + " !!!");

	    // Build up a list of strings called "command" to use with the ProcessBuilder class
	    List<String> command = new ArrayList<String>();

	    // use workspace as dir so that the path to the script is not hard coded
	    String dir1 = System.getenv("WORKSPACE");
	    
	    // Add the name of our script
            String script1 = "/java/src/com/cisco/c3m/est/test/DT/dt_start_estserver1.sh";

	    // add what we have so far to the command
	    command.add(dir1 + script1);

	    // get a free tcp port to use for the estserver
	    mTestPort       = PortFinder.findUniqueFreePort();
	    mTestPortRetry  = PortFinder.findUniqueFreePort();
	    mTestPortDigest = PortFinder.findUniqueFreePort();
	    mTestPort2      = PortFinder.findUniqueFreePort();

	    // now add the ports as strings to the command list as arg1, arg2, etc
	    command.add(Integer.toString(mTestPort));
	    command.add(Integer.toString(mTestPortRetry));
	    command.add(Integer.toString(mTestPortDigest));
	    command.add(Integer.toString(mTestPort2));

	    // we want the estserver start script to run in the background
	    command.add("&");

	    // create an instance and pass it our command list
	    ProcessBuilder builder2 = new ProcessBuilder(command);
	    Process proc2 = builder2.start();
	    // give some time for estservers to get going by sleeping a bit
	    Thread.sleep(4100);
	    
	    /************ Begin From setUp *************************/	    

            /*
	     * Get location of WORKSPACE on local file system
	     */
	    mTrustDB = System.getenv("EST_TRUST");
	    mTestServer = System.getenv("EST_ADDR");

	    try {
	        /*
	         * Create a new keypair to use with the various tests
	         */
	        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	        SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
		keyGen.initialize(1024, rnd);
		System.out.println("Creating new RSA key pair...");
		mKey = keyGen.generateKeyPair();
		assertNotNull(mKey);
		} catch (Exception e) {
		     fail(e.getMessage());
		     e.printStackTrace();
		     return;
		}
	    /************ End From setUp *************************/
		
	    /************ Begin From UT *************************/	    
	    /*
	     * Create a self-signed cert that's used for several of the test cases
	     */
	    java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	    try {
		selfSignedCert = genSelfSignedCert(mKey);
		}
		catch (Exception e) {
		    System.out.println(e.getMessage());
		    fail(e.getMessage());
		    e.printStackTrace();
		    System.out.println("WARNING:  Unable to create self-signed cert, suite will fail!!!!");
		}				
		
	    /************ End   From UT *************************/		    
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	    System.out.println("ESTClientTest has completed ...");
	    /* 
	     *  sleep a few seconds so that junit summary output
	     *  is printed after testcase output
	     */
	    Thread.sleep(3500);
	}

	@Before
	public void setUp() throws Exception {
        logger.info("****************************************************************");
        logger.addHandler(shOut);
        logger.addHandler(shErr);

		try {
			/*
			 * Create a PKCS10 CSR that will be used for the various test cases
			 */
			mCSR = new PKCS10CertificateRequest();
			System.out.println("Creating CSR...");
			mCSR.generateNewCSR ("Java EST Client Dev Test", "US", "Raleigh", "NC", "SandTO", "FOR TEST PURPOSES ONLY", mKey);
			assertNotNull(mCSR);
		} catch (InvalidKeyException | PKCS10CreationException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		
	}

	@After
	public void tearDown() throws Exception {
    	shOut.flush();
        logger.removeHandler(shOut);
    	shErr.flush();
        logger.removeHandler(shErr);
        logger.info("****************************************************************");
	}

	@Test
	public void testSetNativeLogLevel() {
		System.out.println("Beginning TC3532");
		ESTClient ec = new ESTClient();
		assertNotNull(ec);
		ec.setNativeLogLevel(NativeLogLevel.logWarnings);
		ec.setNativeLogLevel(NativeLogLevel.logErrors);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		System.out.println("Ending TC3532");
	}

	@Test
	public void testGetNativeMaxCertLength() {
		System.out.println("Beginning TC3533");
		int m = ESTClient.getNativeMaxCertLength();
		assertTrue(m > 0);
		System.out.println("Ending TC3533");
	}

	@Test
	public void testSetNativeMaxCertLength() {
		System.out.println("Beginning TC3534");
		ESTClient.setNativeMaxCertLength(2023);
		int m = ESTClient.getNativeMaxCertLength();
		assertTrue(m == 2023);
		System.out.println("Ending TC3534");
	}

	@Test
	public void testSetTrustAnchor() {
		System.out.println("Beginning TC3535");
		ESTClient ec = new ESTClient();
		assertNotNull(ec);
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		System.out.println("Ending TC3535");
	}

	/*
	 *  Send SimpleEnrollRequest with everything correct
	 *	This is the best case scenario and should pass.
	 */
	@Test
	public void testSendSimpleEnrollRequest() {
		System.out.println("Beginning TC3467");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
		System.out.println("Ending TC3467");
	}

	@Test
	public void testSendSimpleEnrollRequestNoPoP() {
		System.out.println("Beginning TC3536");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);

		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
		System.out.println("Ending TC3536");
	}
	
	@Test
	public void testSimpleEnrollCorruptCSR() {
		System.out.println("Beginning TC3539");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		PKCS10CertificateRequest csr = null;
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPortRetry);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Convert CSR to byte array, corrupt it, and instantiate a new CSR from the corrupted bytes
		 */
		byte csr_bytes[];
		try {
			csr_bytes = mCSR.getBytes(PKCS10CertificateRequest.Encoding.DER);
			csr_bytes[15] = (byte) (csr_bytes[15] + 1);
			csr = new PKCS10CertificateRequest(csr_bytes);
		} catch (EncodingException | IOException e1) {
			fail(e1.getMessage());
			e1.printStackTrace();
		}
		assertNotNull(csr);
		if (csr == null) return;
		
		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(csr, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException | EnrollRetryAfterException | BufferSizeException
				| CertificateException | IOException | EncodingException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("Caught EnrollException as expected: " + ee.getMessage());
		}
		assertNull(newCert);
		System.out.println("Ending TC3539");
	}
	
	@Test
	public void testSimpleEnrollMismatchedtKey() {
		System.out.println("Beginning TC3540");
		KeyPair tKey;
		
		try {
			/*
			 * Create a new keypair
			 */
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
			keyGen.initialize(1024, rnd);
			System.out.println("Creating new RSA key pair...");
			tKey = keyGen.generateKeyPair();
			assertNotNull(tKey);
		} catch (Exception e) {
			fail(e.getMessage());
			e.printStackTrace();
			return;
		}
		
		/*
		 * Create a mismatched key by using the public key from mKey and
		 * private key from tKey
		 */
		KeyPair badKey = new KeyPair(mKey.getPublic(), tKey.getPrivate());
		
		
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, badKey, Boolean.FALSE);
		} catch (InvalidKeyException | BufferSizeException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("Enroll failed as expected");
		}
		assertNull(newCert);		
		System.out.println("Ending TC3540");
	}
	
	/*
	 *  Simple enroll retry that should fail
	 */
	@Test
	public void testSimpleEnrollRetryAfter() {
		System.out.println("Beginning TC3541");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPortRetry);
		ec.setHTTPCredentials("estuser", "estpwd");		
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException | BufferSizeException
				| CertificateException | IOException | EncodingException
				| EnrollException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollRetryAfterException era) {
			System.out.println("Retry-after exception caught as expected");
		}
		assertNull(newCert);
		System.out.println("Ending TC3541");
	}
	
	
	/*
	 *  Send SimpleEnrollRequest - basic http auth - multiple enrolls - 
	 *  should succeed.
	 */
	@Test
	public void testSimpleEnrollRequestMultiple() throws InterruptedException {
		System.out.println("Beginning TC3548");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		int try_attempts = 0;
		/*
		 * Attempt to provision a new certificates
		 */
		while (try_attempts  < 10) {
			try_attempts++;
			System.out.println("Enroll with basic http auth - attempt number " + try_attempts);
			//Thread.sleep(1000);
			try {
				newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
			} catch (InvalidKeyException
					| CertificateException | IOException | EncodingException
					| EnrollRetryAfterException e) {
				fail(e.getMessage());
				e.printStackTrace();
			}catch (Exception e) {
				fail("\nEnroll with http digest auth failed unexpectedly...\n");
				e.printStackTrace();
			}
			assertNotNull(newCert);
		}
		System.out.println("Ending TC3548");
	}
	
	/*
	 *  Send a Simple Enroll request with http auth and incorrect password
	 *  and make sure enroll fails as expected.
	 */
	@Test
	public void testSendSimpleEnrollRequestBadPassword() {
		System.out.println("Beginning TC3549");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "wrongpw");		
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException | BufferSizeException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad password\n");
		}
		assertNull(newCert);
		System.out.println("Ending TC3549");
	}

	/*
	 *  Send a Simple Enroll request with http auth and incorrect username
	 *  and make sure enroll fails as expected.
	 */
	@Test
	public void testSendSimpleEnrollRequestBadUserName() {
		System.out.println("Beginning TC3550");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("badusername", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException | BufferSizeException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from incorrect user name\n");
		}
		assertNull(newCert);
		System.out.println("Ending TC3550");
	}


	/*
	 *  Send SimpleEnrollRequest with estserver -h started
	 *	on digest port (defined above as EST_DT_PORT + 17)
	 *  but use bad passwd and verify failure to enroll
	 */
	@Test
	public void testSimpleEnrollRequestDigestBadPwd() {
		System.out.println("Beginning TC3553");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPortDigest);
		ec.setHTTPCredentials("estuser", "boguspassword");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException | BufferSizeException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected with http digest and bad http pw used\n");
		}
		assertNull(newCert);
		System.out.println("Ending TC3553");
	}
	
    /*******************************************************************/
    /****************** IRON SPRINT 3 TESTCASES ************************/
	
	/*
	 *  Send SimpleEnrollRequest with everything correct
	 *	This is the best case scenario and should pass.
	 */
	@Test
	public void testSendSimpleEnrollRequestV6() {
		System.out.println("Beginning TCXXXX");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException | BufferSizeException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
		System.out.println("Ending TCXXXX");
	}
		
	@Test
	public void testSimpleEnrollTLSAuth () {
		/*
		 * US1121 - good path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv4, TLS Auth, no PoP, http user good, http pw good, good TA
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC1001");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// IPv4
		ec.setServerName(mTestServer);
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC1001");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthv6 () {
		/*
		 * US1121 - good path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv6, TLS Auth, no PoP, http user good, http pw good, good TA
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC1002");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC1002");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthPoP () {
		/*
		 * US1121 - good path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv4, TLS Auth, PoP on, http user good, http pw good, good TA
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC1003");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// IPv4
		ec.setServerName(mTestServer);
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC1003");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthPoPv6 () {
		/*
		 * US1121 - good path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv6, TLS Auth, PoP on, http user good, http pw good, good TA
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC1004");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC1004");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthbPW () {
		/*
		 * US1121 - good path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv4, TLS Auth, no PoP, http user good, http pw BAD, good TA
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC1005");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// IPv4
		ec.setServerName(mTestServer);
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estbadpw");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC1005");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthbUv6 () {
		/*
		 * US1121 - good path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv6, TLS Auth, no PoP, http user BAD, http pw good, good TA
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC1006");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estbadu", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC1006");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthPoPbU () {
		/*
		 * US1121 - good path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv4, TLS Auth, PoP on, http user BAD, http pw good, good TA
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC1007");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// IPv4
		ec.setServerName(mTestServer);
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estbadu", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC1007");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthPoPbPWv6 () {
		/*
		 * US1121 - good path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv6, TLS Auth, PoP on, http user good, http pw bad, good TA
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC1008");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estbadpw");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC1008");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthnoHTTP () {
		/*
		 * US1121 - good path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv4, TLS Auth, no PoP, no http cred, good TA
		 * 
		 * Note: good http credentials are used for obtaining first cert
		 *       by the provisionTrustedCert method
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC1009");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// IPv4
		ec.setServerName(mTestServer);
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC1009");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthNoHTTPv6 () {
		/*
		 * US1121 - good path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv6, TLS Auth, no PoP, no http cred, good TA
		 * 
		 * Note: good http credentials are used for obtaining first cert
		 *       by the provisionTrustedCert method
		 * Expect success
		 */			
		System.out.println("Beginning TC1010");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC1010");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthPoPnoHTTP () {
		/*
		 * US1121 - good path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv4, TLS Auth, PoP on, no http cred, good TA
		 * 
		 * Note: good http credentials are used for obtaining first cert
		 *       by the provisionTrustedCert method
		 * Expect success
		 */			
		System.out.println("Beginning TC1011");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// IPv4
		ec.setServerName(mTestServer);
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC1011");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthPoPnoHTTPv6 () {
		/*
		 * US1121 - good path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv6, TLS Auth, PoP on, no http cred, good TA
		 * 
		 * Note: good http credentials are used for obtaining first cert
		 *       by the provisionTrustedCert method
		 * Expect success
		 */			
		System.out.println("Beginning TC1012");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC1012");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthbHTTPnoTA () {
		/*
		 * US1121 - good path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv4, TLS Auth, no PoP, bad http credentials for cert2, no TA
		 * 
		 * Expect failure to obtain cert2
		 */			
		System.out.println("Beginning TC1013");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// IPv4
		ec.setServerName(mTestServer);
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estbadu", "estbadpw");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll with Cert failed as expected without Trust Anchor\n");
		}
		assertNull(newCert2);		
		System.out.println("Ending TC1013");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthbHTTPnoTAv6 () {
		/*
		 * US1121 - good path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv6, TLS Auth, no PoP, bad http credentials for cert2, no TA
		 * 
		 * Expect failure to obtain cert2
		 */			
		System.out.println("Beginning TC1014");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estbadu", "estbadpw");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll with Cert failed as expected without Trust Anchor\n");
		}
		assertNull(newCert2);		
		System.out.println("Ending TC1014");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthPoPbHTTPnoTA () {
		/*
		 * US1121 - good path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv4, TLS Auth, PoP on, bad http credentials for cert2, no TA
		 * 
		 * Expect failure to obtain cert2
		 */			
		System.out.println("Beginning TC1015");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// IPv4
		ec.setServerName(mTestServer);
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estbadu", "estbadpw");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll with Cert failed as expected without Trust Anchor\n");
		}
		assertNull(newCert2);		
		System.out.println("Ending TC1015");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthPoPbHTTPnoTAv6 () {
		/*
		 * US1121 - good path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv6, TLS Auth, PoP on, bad http credentials for cert2, no TA
		 * 
		 * Expect failure to obtain cert2
		 */			
		System.out.println("Beginning TC1016");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estbadu", "estbadpw");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll with Cert failed as expected without Trust Anchor\n");
		}
		assertNull(newCert2);		
		System.out.println("Ending TC1016");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthNoHTTPnoTA () {
		/*
		 * US1121 - good path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv4, TLS Auth, no PoP, no http cred, no TA
		 * 
		 * Note: good http credentials are used for obtaining first cert
		 *       by the provisionTrustedCert method
		 * 
		 * Expect failure to obtain cert2
		 */			
		System.out.println("Beginning TC1017");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// IPv4
		ec.setServerName(mTestServer);
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll with Cert failed as expected without Trust Anchor\n");
		}
		assertNull(newCert2);		
		System.out.println("Ending TC1017");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthNoHTTPnoTAv6 () {
		/*
		 * US1121 - good path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv6, TLS Auth, no PoP, no http cred, no TA
		 * 
		 * Note: good http credentials are used for obtaining first cert
		 *       by the provisionTrustedCert method
		 * Expect failure to obtain cert2
		 */			
		System.out.println("Beginning TC1018");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll with Cert failed as expected without Trust Anchor\n");
		}
		assertNull(newCert2);		
		System.out.println("Ending TC1018");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthPoPnoHTTPnoTA () {
		/*
		 * US1121 - good path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv4, TLS Auth, PoP on, no http cred, no TA
		 * 
		 * Note: good http credentials are used for obtaining first cert
		 *       by the provisionTrustedCert method
		 * Expect failure to obtain cert2
		 */			
		System.out.println("Beginning TC1019");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// IPv4
		ec.setServerName(mTestServer);
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll with Cert failed as expected without Trust Anchor\n");
		}
		assertNull(newCert2);		
		System.out.println("Ending TC1019");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthPoPnoHTTPnoTAv6 () {
		/*
		 * US1121 - bad path TLS auth test using a valid client cert.
		 * 
		 * Enroll, ipv6, TLS Auth, PoP on, no http cred, no TA
		 * 
		 * Note: good http credentials are used for obtaining first cert
		 *       by the provisionTrustedCert method
		 * Expect failure to obtain cert2
		 */			
		System.out.println("Beginning TC1020");
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll with Cert failed as expected without Trust Anchor\n");
		}
		assertNull(newCert2);		
		System.out.println("Ending TC1020");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthSSnoTA () {
		/*
		 * US1121 - bad path TLS auth test with Self-Signed Cert and no Trust Anchor set.
		 * 
		 * Enroll, ipv4, TLS Auth, no PoP, http user good, http pw good, no TA
		 * 
		 * Expect failure to obtain cert
		 */			
		System.out.println("Beginning TC1021");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);

		// IPv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert);	
		
		System.out.println("Ending TC1021");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthSSnoTAv6 () {
		/*
		 * US1121 - bad path TLS auth test using a Self-Signed client cert
		 *          and no Trust Anchor set.
		 * Enroll, ipv6, TLS Auth, no PoP, http user good, http pw good, no TA
		 * 
		 * Expect failure to obtain cert2
		 */			
		System.out.println("Beginning TC1022");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert);
		
		System.out.println("Ending TC1022");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthSSPoPnoTA () {
		/*
		 * US1121 - bad path TLS auth test using a Self-Signed client cert and no TA
		 * 
		 * Enroll, ipv4, TLS Auth, PoP on, http user good, http pw good, no TA
		 * 
		 * Expect failure to obtain cert
		 */			
		System.out.println("Beginning TC1023");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// IPv4
		ec.setServerName(mTestServer);
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert);
		System.out.println("Ending TC1023");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthSSPoPnoTAv6 () {
		/*
		 * US1121 - bad path TLS auth test using a Self-Signed cert and no TA
		 * 
		 * Enroll, ipv6, TLS Auth, PoP on, http user good, http pw good, no TA
		 * 
		 * Expect failure to obtain cert
		 */			
		System.out.println("Beginning TC1024");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert);
		System.out.println("Ending TC1024");
	}
	
	@Test
	public void testSimpEnrollTLSAuthSSnoTAnoHTTP () {
		/*
		 * US1121 - bad path TLS auth test with Self-Signed Cert and no Trust Anchor set.
		 * 
		 * Enroll, ipv4, TLS Auth, no PoP, no http cred, no TA
		 * 
		 * Expect failure to obtain cert
		 */			
		System.out.println("Beginning TC1025");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);

		// IPv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert);	
		
		System.out.println("Ending TC1025");
	}
	
	@Test
	public void testSimpEnrollTLSAuthSSnoTAnoHTTPv6 () {
		/*
		 * US1121 - bad path TLS auth test using a Self-Signed client cert
		 *          and no Trust Anchor set.
		 * Enroll, ipv6, TLS Auth, no PoP, no http cred, no TA
		 * 
		 * Expect failure to obtain cert2
		 */			
		System.out.println("Beginning TC1026");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert);
		
		System.out.println("Ending TC1026");
	}
	
	@Test
	public void testSimpEnrollTLSAuthSSPoPnoTAnoHTTP () {
		/*
		 * US1121 - bad path TLS auth test using a Self-Signed client cert and no TA
		 * 
		 * Enroll, ipv4, TLS Auth, PoP on, no http cred, no TA
		 * 
		 * Expect failure to obtain cert
		 */			
		System.out.println("Beginning TC1027");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// IPv4
		ec.setServerName(mTestServer);
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert);
		System.out.println("Ending TC1027");
	}
	
	@Test
	public void testSimpEnrollTLSAuthSSPoPnoTAnoHTTPv6 () {
		/*
		 * US1121 - bad path TLS auth test using a Self-Signed cert and no TA
		 * 
		 * Enroll, ipv6, TLS Auth, PoP on, no http cred, no TA
		 * 
		 * Expect failure to obtain cert
		 */			
		System.out.println("Beginning TC1028");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert);
		System.out.println("Ending TC1028");
	}
	
	@Test
	public void testSimpEnrollTLSAuthSSnoTA () {
		/*
		 * US1121 - bad path TLS auth test with Self-Signed Cert and no Trust Anchor set.
		 * 
		 * Enroll, ipv4, TLS Auth, no PoP, http user bad, http pw bad, no TA
		 * 
		 * Expect failure to obtain cert
		 */			
		System.out.println("Beginning TC1029");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);

		// IPv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estbadu", "estbadpw");
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert);	
		
		System.out.println("Ending TC1029");
	}
	
	@Test
	public void testSimpEnrollTLSAuthSSnoTAv6 () {
		/*
		 * US1121 - bad path TLS auth test using a Self-Signed client cert
		 *          and no Trust Anchor set.
		 * Enroll, ipv6, TLS Auth, no PoP, http user bad, http pw good, no TA
		 * 
		 * Expect failure to obtain cert2
		 */			
		System.out.println("Beginning TC1030");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estbadu", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert);
		
		System.out.println("Ending TC1030");
	}
	
	@Test
	public void testSimpEnrollTLSAuthSSPoPnoTA () {
		/*
		 * US1121 - bad path TLS auth test using a Self-Signed client cert and no TA
		 * 
		 * Enroll, ipv4, TLS Auth, PoP on, http user good, http pw bad, no TA
		 * 
		 * Expect failure to obtain cert
		 */			
		System.out.println("Beginning TC1031");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// IPv4
		ec.setServerName(mTestServer);
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estbadpw");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert);
		System.out.println("Ending TC1031");
	}
	
	@Test
	public void testSimpEnrollTLSAuthSSPoPnoTAv6 () {
		/*
		 * US1121 - bad path TLS auth test using a Self-Signed cert and no TA
		 * 
		 * Enroll, ipv6, TLS Auth, PoP on, http user bad, http pw bad, no TA
		 * 
		 * Expect failure to obtain cert
		 */			
		System.out.println("Beginning TC1032");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estbadu", "estbadpw");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert);
		System.out.println("Ending TC1032");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthSS () {
		/*
		 * US1121 - bad path TLS auth test due to using a Self-Signed client cert.
		 * 
		 * Enroll, ipv4, TLS Auth, no PoP, http user good, http pw good, good TA
		 * 
		 * Expect failure to obtain cert
		 */			
		System.out.println("Beginning TC1033");
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// IPv4
		ec.setServerName(mTestServer);
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert2);
		System.out.println("Ending TC1033");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthSSv6 () {
		/*
		 * US1121 - bad path TLS auth test due to using a Self-Signed client cert.
		 * 
		 * Enroll, ipv6, TLS Auth, no PoP, http user good, http pw good, good TA
		 * 
		 * Expect failure to obtain cert
		 */			
		System.out.println("Beginning TC1034");
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert2);
		System.out.println("Ending TC1034");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthSSPoP () {
		/*
		 * US1121 - bad path TLS auth test due to using a Self-Signed client cert.
		 * 
		 * Enroll, ipv4, TLS Auth, PoP on, http user good, http pw good, good TA
		 * 
		 * Expect failure to obtain cert
		 */			
		System.out.println("Beginning TC1035");
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// IPv4
		ec.setServerName(mTestServer);
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert2);
		System.out.println("Ending TC1035");
	}
	
	@Test
	public void testSimpleEnrollTLSAuthSSPoPv6 () {
		/*
		 * US1121 - bad path TLS auth test due to using a Self-Signed client cert.
		 * 
		 * Enroll, ipv6, TLS Auth, PoP on, http user good, http pw good, good TA
		 * 
		 * Expect failure to obtain cert
		 */			
		System.out.println("Beginning TC1036");
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert2);
		System.out.println("Ending TC1036");
	}
	
	@Test
	public void testSimpEnrllTLSAuthSSnoHTTP () {
		/*
		 * US1121 - bad path TLS auth test due to using a Self-Signed client cert.
		 * 
		 * Enroll, ipv4, TLS Auth, no PoP, no http cred, good TA
		 * 
		 * Expect failure to obtain cert
		 */			
		System.out.println("Beginning TC1037");
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// IPv4
		ec.setServerName(mTestServer);
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert2);
		System.out.println("Ending TC1037");
	}
	
	@Test
	public void testSimpEnrllTLSAuthSSnoHTTPv6 () {
		/*
		 * US1121 - bad path TLS auth test due to using a Self-Signed client cert.
		 * 
		 * Enroll, ipv6, TLS Auth, no PoP, no http cred, good TA
		 * 
		 * Expect failure to obtain cert
		 */			
		System.out.println("Beginning TC1038");
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert2);
		System.out.println("Ending TC1038");
	}
	
	@Test
	public void testSimpEnrllTLSAuthSSPoPnoHTTP () {
		/*
		 * US1121 - bad path TLS auth test due to using a Self-Signed client cert.
		 * 
		 * Enroll, ipv4, TLS Auth, PoP on, no http cred, good TA
		 * 
		 * Expect failure to obtain cert
		 */			
		System.out.println("Beginning TC1039");
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// IPv4
		ec.setServerName(mTestServer);
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert2);
		System.out.println("Ending TC1039");
	}
	
	@Test
	public void testSimpEnrllTLSAuthSSPoPnoHTTPv6 () {
		/*
		 * US1121 - bad path TLS auth test due to using a Self-Signed client cert.
		 * 
		 * Enroll, ipv6, TLS Auth, PoP on, no http credentials, good TA
		 * 
		 * Expect failure to obtain cert
		 */			
		System.out.println("Beginning TC1040");
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// Set Trust Anchor
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		// normal dt port
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that is within the trust chain of our CA, try to
		 * use that cert to enroll again using TLS authentication.
		 */
		ec.setTLSAuthenticationCredentials(selfSignedCert, mKey);
		try {
			newCert2 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (Exception e) {
			//e.printStackTrace();
			System.out.println("\nEnroll failed as expected due to self-signed cert\n");
		}
		assertNull(newCert2);
		System.out.println("Ending TC1040");
	}
	
    /*******************************************************************/
    /*******************************************************************/
    /*******************************************************************/
    /*******************************************************************/
	/*
	 * This function will generate a self-signed certificate
	 */
	@SuppressWarnings("deprecation")
	private static X509Certificate genSelfSignedCert(KeyPair pair) throws InvalidKeyException,
      	NoSuchProviderException, SignatureException {
		
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

		certGen.setSerialNumber(new BigInteger("1987"));
		certGen.setIssuerDN(new X509Principal("CN=Test Certificate"));
		certGen.setNotBefore(new Date(System.currentTimeMillis() - 10000));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 10000));
		certGen.setSubjectDN(new X509Principal("CN=Test Certificate"));
		certGen.setPublicKey(pair.getPublic());
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

		return certGen.generateX509Certificate(pair.getPrivate(), "BC");
	}

	/*
	 * This helper routine is used by some of the test cases that 
	 * need a cert trusted by the CA.
	 */
	private X509Certificate provisionTrustedCert() {
		ESTClient ec = new ESTClient();
		X509Certificate newCert = null;
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		return newCert;
	}

	
	/*
	 * This function will take the name of a file on the local system that is a Java keystore (JKS).
	 * It will load the file into a KeyStore object and pull out the trusted certificates.
	 * It returns an array of X509Certificate objects that contain these trusted certs.
	 */
	private static void loadTA (String jksFile) {
		int c_count = 0;
		KeyStore store;
		String pass = "changeit";

		try {
			InputStream rs = new FileInputStream(jksFile);
			store = KeyStore.getInstance("JKS");
			store.load(rs, pass.toCharArray());
			Enumeration e = store.aliases();
			//First, see how many certs we have
			while (e.hasMoreElements() && c_count < 10) {
				String alias = (String)e.nextElement();
				if (store.isCertificateEntry(alias)) {
					c_count++;
				}
			}
			//Allocate space for the certs
			certs = new X509Certificate[c_count];
			e = store.aliases();
			c_count = 0;
			while (e.hasMoreElements() && c_count < 10) {
				String alias = (String)e.nextElement();
				if (store.isCertificateEntry(alias)) {
					System.out.println("found " + alias + " is trust cert: " + store.isCertificateEntry(alias));
					certs[c_count] = (java.security.cert.X509Certificate)store.getCertificate(alias);
					c_count++;
				}
			}
			rs.close();
		} catch (Exception e) {
			System.out.println("Exception in JESTTest: " + e.getMessage());
			System.out.println(e.getStackTrace());			
		}
	}
	

} /* end of class ESTClientTest */


