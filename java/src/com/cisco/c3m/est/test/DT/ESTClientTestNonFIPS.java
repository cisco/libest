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
public class ESTClientTestNonFIPS {
	private static X509Certificate[] certs;
	private static String mTrustDB;
	private static String mTestServer = new String("127.0.0.1");
	
	/*
	 *  The following ports are used by the client to connect to estserver
	 *  instances.  The actual port numbers will be set later by getting
	 *  environment variables that need to be set before starting the tests.
	 */
	// port that estserver should be running on EST_DT_PORT
	private static int mTestPort = 0;
	// another estserver instance set up for retry should run on EST_DT_PORT + 1
	private static int mTestPortRetry = 0;
	// another estserver instance set up for http digest authentication on EST_DT_PORT + 17
	private static int mTestPortDigest = 0;
	// port that estserver should be running on EST_DT_PORT + 2
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

	    /************ End   From UT    *************************/
			    
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

	/*
	 *  Send SimpleEnrollRequest - first attempt will be with basic http auth that should receive retry
	 *	and then do retry with http digest that should succeed.
	 */
	@Test
	public void testSimpleEnrollRequestDigest() {
	        System.out.println("Beginning TC3546");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPortDigest);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
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
		System.out.println("Ending TC3546");
	}
	
	/*
	 *  Send SimpleEnrollRequest - http digest - multiple enrolls - 
	 *  should succeed.
	 */
	@Test
	public void testSimpleEnrollRequestDigestMultiple() throws InterruptedException {
	        System.out.println("Beginning TC3547");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPortDigest);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		int try_attempts = 0;
		/*
		 * Attempt to provision a new certificate
		 */
		while (try_attempts  < 10) {
			try_attempts++;
			System.out.println("Enroll with http digest auth - attempt number " + try_attempts);
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
		System.out.println("Ending TC3547");
	}

	/*
	 *  Send a Simple Enroll request with good http name and pw
	 *  but only enable SRP auth and make sure enroll fails as expected.
	 */
	@Test
	public void testSimpleEnrollRequestTryHTTPwithOnlySRP() {
		System.out.println("Beginning TC3551");
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
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException | BufferSizeException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected when only http auth defined and only srp enabled\n");
		}
		assertNull(newCert);
		System.out.println("Ending TC3551");
	}
	
	/*
	 *  Make sure that with the authentication mode set to HTTP and SRP
	 *  a simple enroll using http authentication still works 
	 */
	@Test
	public void testSendSimpleEnrollRequestHTTPandSRP() {
		System.out.println("Beginning TC3552");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);

		System.out.println("Completed setting up EST Context...");
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException | BufferSizeException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
		System.out.println("Ending TC3552");
	}

	@Test
	public void testSimpleEnrollSRPwoHTTP () {
		/*
		 * This is a happy path SRP test without HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, no PoP, srp user good, srp pw good, TA good, no http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0001");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0001");
	}
	
	@Test
	public void testSimpleEnrollSRPwoHTTPv6 () {
		/*
		 * This is a happy path SRP test without HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv6, SRP, no PoP, srp user good, srp pw good, TA good, no http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0002");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0002");
	}
	
	@Test
	public void testSimpleEnrollSRPwHTTP () {
		/*
		 * This is a happy path SRP test with HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, no PoP, srp user good, srp pw good, TA good, good http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0003");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0003");
	}
	
	@Test
	public void testSimpleEnrollSRPwHTTPv6 () {
		/*
		 * This is a happy path SRP test w SRP and HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv6, SRP, no PoP, srp user good, srp pw good, TA good, good http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0004");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		
		// ipv4
		//ec.setServerName(mTestServer);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0004");
	}
	
	@Test
	public void testSimpleEnrollSRPwoHTTPwPoP () {
		/*
		 * This is a happy path SRP test without HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, PoP on, srp user good, srp pw good, TA good, no http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0005");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0005");
	}
	
	@Test
	public void testSimpleEnrollSRPwoHTTPwPoPv6 () {
		/*
		 * This is a happy path SRP test without HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv6, SRP, PoP on, srp user good, srp pw good, TA good, no http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0006");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		//ec.setServerName(mTestServer);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0006");
	}
	
	@Test
	public void testSimpleEnrollSRPwHTTPwPoP () {
		/*
		 * This is a happy path SRP test with HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, PoP on, srp user good, srp pw good, TA good, good http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0007");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0007");
	}

	@Test
	public void testSimpleEnrollSRPwHTTPv6PoP () {
		/*
		 * This is a happy path SRP test w SRP and HTTP auth credentials
		 * provided and PoP on.
		 * 
		 * Enroll, ipv6, SRP, PoP on, srp user good, srp pw good, TA good, good http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0008");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		
		// ipv4
		//ec.setServerName(mTestServer);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0008");
	}
	
	@Test
	public void testSimpleEnrollSRPwoHTTPBadU () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided and with bad srp username.
		 * 
		 * Enroll, ipv4, SRP, no PoP, srp user BAD, srp pw good, TA good, no http
		 * 
		 * Expect failure to enroll
		 * 
		 */
		System.out.println("Beginning TC0009");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpbaduser", "srppwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP username\n");
		}
		assertNull(newCert);		
		System.out.println("Ending TC0009");
	}
	
	@Test
	public void testSimpleEnrollSRPwoHTTPBadUv6 () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided and with bad srp username.
		 * 
		 * Enroll, ipv6, SRP, no PoP, srp user BAD, srp pw good, TA good, no http
		 * 
		 * Expect failure to enroll
		 * 
		 */
		System.out.println("Beginning TC0010");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		//ec.setServerName(mTestServer);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpbaduser", "srppwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP username\n");
		}
		assertNull(newCert);		
		System.out.println("Ending TC0010");
	}
	
	@Test
	public void testSimpleEnrollSRPwHTTPBadSRPUser () {
		/*
		 * This is a bad path SRP test with HTTP auth credentials
		 * provided.  Bad SRP User but good http credentials
		 * 
		 * Enroll, ipv4, SRP, no PoP, srp user BAD, srp pw good, TA good, good http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0011");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort2);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBAD", "srppwd");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP username\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0011");
	}
	
	@Test
	public void testSimpleEnrollSRPwHTTPBadSRPUserv6 () {
		/*
		 * This is a happy path SRP test w SRP and HTTP auth credentials
		 * provided.  Bad SRP User fails even with good http credentials
		 * 
		 * Enroll, ipv6, SRP, no PoP, srp user BAD, srp pw good, TA good, good http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0012");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		
		// ipv4
		//ec.setServerName(mTestServer);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort2);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpbad", "srppwd");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP username\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0012");
	}
	
	@Test
	public void testSimpleEnrollSRPwoHTTPwPoPBadSRPU () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, PoP on, srp user BAD, srp pw good, TA good, no http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0013");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBAD", "srppwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP username\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0013");
	}
	
	@Test
	public void testSimpleEnrollSRPwoHTTPwPoPBadSRPUv6 () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv6, SRP, PoP on, srp user BAD, srp pw good, TA good, no http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0014");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		//ec.setServerName(mTestServer);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBAD", "srppwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP username\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0014");
	}
	
	@Test
	public void testSimpleEnrollSRPwHTTPwPoPBadSRPU () {
		/*
		 * This is a bad path SRP test with HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, PoP on, srp user BAD, srp pw good, TA good, good http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0015");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBAD", "srppwd");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP username\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0015");
	}

	@Test
	public void testSimpleEnrollSRPwHTTPv6PoPBadSRPU () {
		/*
		 * This is a bad path SRP test w SRP and HTTP auth credentials
		 * provided and PoP on.
		 * 
		 * Enroll, ipv6, SRP, PoP on, srp user BAD, srp pw good, TA good, good http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0016");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		
		// ipv4
		//ec.setServerName(mTestServer);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBAD", "srppwd");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP username\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0016");
	}
	
	@Test
	public void testSimpleEnrollSRPwoHTTPBadSRPPW () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided and with bad srp pw.
		 * 
		 * Enroll, ipv4, SRP, no PoP, srp user good, srp pw BAD, TA good, no http
		 * 
		 * Expect failure to enroll
		 * 
		 */
		System.out.println("Beginning TC0017");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP password\n");
		}
		assertNull(newCert);		
		System.out.println("Ending TC0017");
	}
	
	@Test
	public void testSimpleEnrollSRPwoHTTPBadSRPPWv6 () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided and with bad srp pw.
		 * 
		 * Enroll, ipv6, SRP, no PoP, srp user good, srp pw BAD, TA good, no http
		 * 
		 * Expect failure to enroll
		 * 
		 */
		System.out.println("Beginning TC0018");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		//ec.setServerName(mTestServer);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP password\n");
		}
		assertNull(newCert);		
		System.out.println("Ending TC0018");
	}
	
	@Test
	public void testSimpleEnrollSRPwHTTPBadSRPPW () {
		/*
		 * This is a bad path SRP test with HTTP auth credentials
		 * provided.  Bad SRP PW but good http credentials
		 * 
		 * Enroll, ipv4, SRP, no PoP, srp user good, srp pw BAD, TA good, good http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0019");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort2);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwdBAD");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP password\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0019");
	}
	
	@Test
	public void testSimpleEnrollSRPwHTTPBadSRPPWv6 () {
		/*
		 * This is a happy path SRP test w SRP and HTTP auth credentials
		 * provided.  Bad SRP PW fails even with good http credentials
		 * 
		 * Enroll, ipv6, SRP, no PoP, srp user good, srp pw BAD, TA good, good http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0020");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		
		// ipv4
		//ec.setServerName(mTestServer);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort2);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwdBAD");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP password\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0020");
	}
	
	@Test
	public void testSimpleEnrollSRPwoHTTPwPoPBadSRPPW () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, PoP on, srp user good, srp pw BAD, TA good, no http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0021");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwdBADBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP password\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0021");
	}
	
	@Test
	public void testSimpleEnrollSRPwoHTTPwPoPBadSRPPWv6 () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv6, SRP, PoP on, srp user good, srp pw BAD, TA good, no http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0022");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		//ec.setServerName(mTestServer);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwdBOGUS");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP password\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0022");
	}
	
	@Test
	public void testSimpleEnrollSRPwHTTPwPoPBadSRPPW () {
		/*
		 * This is a bad path SRP test with HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, PoP on, srp user good, srp pw BAD, TA good, good http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0023");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwdBLAH");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP password\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0023");
	}

	@Test
	public void testSimpleEnrollSRPwHTTPv6PoPBadSRPPW () {
		/*
		 * This is a bad path SRP test w SRP and HTTP auth credentials
		 * provided and PoP on.
		 * 
		 * Enroll, ipv6, SRP, PoP on, srp user good, srp pw BAD, TA good, good http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0024");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		
		// ipv4
		//ec.setServerName(mTestServer);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwdBLAH");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP password\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0024");
	}
	
	@Test
	public void testSimpleEnrollSRPwoHTTPBadSRP () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided and with bad srp credentials.
		 * 
		 * Enroll, ipv4, SRP, no PoP, srp user BAD, srp pw BAD, TA good, no http
		 * 
		 * Expect failure to enroll
		 * 
		 */
		System.out.println("Beginning TC0025");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBADU", "srppwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP credentials\n");
		}
		assertNull(newCert);		
		System.out.println("Ending TC0025");
	}
	
	@Test
	public void testSimpleEnrollSRPwoHTTPBadSRPv6 () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided and with bad srp credentials.
		 * 
		 * Enroll, ipv6, SRP, no PoP, srp user BAD, srp pw BAD, TA good, no http
		 * 
		 * Expect failure to enroll
		 * 
		 */
		System.out.println("Beginning TC0026");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		//ec.setServerName(mTestServer);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBADU", "srppwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP credentials\n");
		}
		assertNull(newCert);		
		System.out.println("Ending TC0026");
	}
	
	@Test
	public void testSimpleEnrollSRPwHTTPBadSRP () {
		/*
		 * This is a bad path SRP test with HTTP auth credentials
		 * provided.  Bad Srp Credentials but good http credentials
		 * 
		 * Enroll, ipv4, SRP, no PoP, srp user BAD, srp pw BAD, TA good, good http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0027");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort2);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBADU", "srppwdBAD");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP credentials\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0027");
	}
	
	@Test
	public void testSimpleEnrollSRPwHTTPBadSRPv6 () {
		/*
		 * This is a happy path SRP test w SRP and HTTP auth credentials
		 * provided.  Bad Srp Credentials fails even with good http credentials
		 * 
		 * Enroll, ipv6, SRP, no PoP, srp user BAD, srp pw BAD, TA good, good http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0028");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		
		// ipv4
		//ec.setServerName(mTestServer);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort2);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBADU", "srppwdBAD");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP credentials\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0028");
	}
	
	@Test
	public void testSimpleEnrollSRPwoHTTPwPoPBadSRP () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, PoP on, srp user BAD, srp pw BAD, TA good, no http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0029");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBADU", "srppwdBADBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP credentials\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0029");
	}
	
	@Test
	public void testSimpleEnrollSRPwoHTTPwPoPBadSRPv6 () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv6, SRP, PoP on, srp user BAD, srp pw BAD, TA good, no http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0030");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		//ec.setServerName(mTestServer);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBADU", "srppwdBOGUS");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP credentials\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0030");
	}
	
	@Test
	public void testSimpleEnrollSRPwHTTPwPoPBadSRP () {
		/*
		 * This is a bad path SRP test with HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, PoP on, srp user BAD, srp pw BAD, TA good, good http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0031");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBADU", "srppwdBLAH");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP credentials\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0031");
	}

	@Test
	public void testSimpleEnrollSRPwHTTPv6PoPBadSRP () {
		/*
		 * This is a bad path SRP test w SRP and HTTP auth credentials
		 * provided and PoP on.
		 * 
		 * Enroll, ipv6, SRP, PoP on, srp user BAD, srp pw BAD, TA good, good http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0032");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		
		// ipv4
		//ec.setServerName(mTestServer);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBADU", "srppwdBLAH");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP credentials\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0032");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwoHTTP () {
		/*
		 * This is a happy path SRP test without HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, no PoP, srp user good, srp pw good, no TA, no http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0033");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0033");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwoHTTPv6 () {
		/*
		 * This is a happy path SRP test without HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv6, SRP, no PoP, srp user good, srp pw good, no TA, no http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0034");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0034");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwHTTP () {
		/*
		 * This is a happy path SRP test with BAD HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, no PoP, srp user good, srp pw good, no TA, bad http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0035");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setHTTPCredentials("estuserBAD", "estpwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0035");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwHTTPv6 () {
		/*
		 * This is a happy path SRP test w SRP and bad HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv6, SRP, no PoP, srp user good, srp pw good, no TA, bad http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0036");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		
		// ipv4
		//ec.setServerName(mTestServer);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setHTTPCredentials("estuserBAD", "estpwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0036");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwoHTTPwPoP () {
		/*
		 * This is a happy path SRP test without HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, PoP on, srp user good, srp pw good, no TA, no http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0037");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0037");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwoHTTPwPoPv6 () {
		/*
		 * This is a happy path SRP test without HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv6, SRP, PoP on, srp user good, srp pw good, no TA, no http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0038");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		//ec.setServerName(mTestServer);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0038");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwHTTPwPoP () {
		/*
		 * This is a happy path SRP test with BAD HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, PoP on, srp user good, srp pw good, no TA, bad http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0039");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setHTTPCredentials("estuserBAD", "estpwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0039");
	}

	@Test
	public void testSimpleEnrollSRPnoTAwHTTPv6PoP () {
		/*
		 * This is a happy path SRP test w SRP and bad HTTP auth credentials
		 * provided and PoP on.
		 * 
		 * Enroll, ipv6, SRP, PoP on, srp user good, srp pw good, no TA, bad http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0040");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		
		// ipv4
		//ec.setServerName(mTestServer);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setHTTPCredentials("estuserBAD", "estpwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0040");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwoHTTPBadU () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided and with bad srp username.
		 * 
		 * Enroll, ipv4, SRP, no PoP, srp user BAD, srp pw good, no TA, no http
		 * 
		 * Expect failure to enroll
		 * 
		 */
		System.out.println("Beginning TC0041");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpbaduser", "srppwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP username\n");
		}
		assertNull(newCert);		
		System.out.println("Ending TC0041");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwoHTTPBadUv6 () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided and with bad srp username.
		 * 
		 * Enroll, ipv6, SRP, no PoP, srp user BAD, srp pw good, no TA, no http
		 * 
		 * Expect failure to enroll
		 * 
		 */
		System.out.println("Beginning TC0042");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		//ec.setServerName(mTestServer);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpbaduser", "srppwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP username\n");
		}
		assertNull(newCert);		
		System.out.println("Ending TC0042");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwHTTPBadSRPUser () {
		/*
		 * This is a bad path SRP test with BAD HTTP auth credentials
		 * provided.  Bad SRP User but good http credentials
		 * 
		 * Enroll, ipv4, SRP, no PoP, srp user BAD, srp pw good, no TA, bad http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0043");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort2);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBAD", "srppwd");
		ec.setHTTPCredentials("estuserBAD", "estpwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP username\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0043");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwHTTPBadSRPUserv6 () {
		/*
		 * This is a happy path SRP test w SRP and bad HTTP auth credentials
		 * provided.  
		 * 
		 * Enroll, ipv6, SRP, no PoP, srp user BAD, srp pw good, no TA, bad http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0044");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		
		// ipv4
		//ec.setServerName(mTestServer);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort2);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpbad", "srppwd");
		ec.setHTTPCredentials("estuserBAD", "estpwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP username\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0044");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwoHTTPwPoPBadSRPU () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, PoP on, srp user BAD, srp pw good, no TA, no http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0045");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBAD", "srppwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP username\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0045");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwoHTTPwPoPBadSRPUv6 () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv6, SRP, PoP on, srp user BAD, srp pw good, no TA, no http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0046");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		//ec.setServerName(mTestServer);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBAD", "srppwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP username\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0046");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwHTTPwPoPBadSRPU () {
		/*
		 * This is a bad path SRP test with BAD HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, PoP on, srp user BAD, srp pw good, no TA, bad http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0047");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBAD", "srppwd");
		ec.setHTTPCredentials("estuserBAD", "estpwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP username\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0047");
	}

	@Test
	public void testSimpleEnrollSRPnoTAwHTTPv6PoPBadSRPU () {
		/*
		 * This is a bad path SRP test w SRP and bad HTTP auth credentials
		 * provided and PoP on.
		 * 
		 * Enroll, ipv6, SRP, PoP on, srp user BAD, srp pw good, no TA, bad http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0048");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		
		// ipv4
		//ec.setServerName(mTestServer);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBAD", "srppwd");
		ec.setHTTPCredentials("estuserBAD", "estpwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP username\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0048");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwoHTTPBadSRPPW () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided and with bad srp pw.
		 * 
		 * Enroll, ipv4, SRP, no PoP, srp user good, srp pw BAD, no TA, no http
		 * 
		 * Expect failure to enroll
		 * 
		 */
		System.out.println("Beginning TC0049");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP password\n");
		}
		assertNull(newCert);		
		System.out.println("Ending TC0049");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwoHTTPBadSRPPWv6 () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided and with bad srp pw.
		 * 
		 * Enroll, ipv6, SRP, no PoP, srp user good, srp pw BAD, no TA, no http
		 * 
		 * Expect failure to enroll
		 * 
		 */
		System.out.println("Beginning TC0050");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		//ec.setServerName(mTestServer);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP password\n");
		}
		assertNull(newCert);		
		System.out.println("Ending TC0050");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwHTTPBadSRPPW () {
		/*
		 * This is a bad path SRP test with BAD HTTP auth credentials
		 * provided.  Bad SRP PW but good http credentials
		 * 
		 * Enroll, ipv4, SRP, no PoP, srp user good, srp pw BAD, no TA, bad http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0051");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort2);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwdBAD");
		ec.setHTTPCredentials("estuserBAD", "estpwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP password\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0051");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwHTTPBadSRPPWv6 () {
		/*
		 * This is a happy path SRP test w SRP and bad HTTP auth credentials
		 * provided. 
		 * 
		 * Enroll, ipv6, SRP, no PoP, srp user good, srp pw BAD, no TA, bad http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0052");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		
		// ipv4
		//ec.setServerName(mTestServer);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort2);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwdBAD");
		ec.setHTTPCredentials("estuserBAD", "estpwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP password\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0052");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwoHTTPwPoPBadSRPPW () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, PoP on, srp user good, srp pw BAD, no TA, no http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0053");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwdBADBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP password\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0053");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwoHTTPwPoPBadSRPPWv6 () {
		/*
		 * This is a bad path SRP test without HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv6, SRP, PoP on, srp user good, srp pw BAD, no TA, no http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0054");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		//ec.setServerName(mTestServer);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwdBOGUS");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP password\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0054");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwHTTPwPoPBadSRPPW () {
		/*
		 * This is a bad path SRP test with BAD HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, PoP on, srp user good, srp pw BAD, no TA, bad http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0055");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwdBLAH");
		ec.setHTTPCredentials("estuserBAD", "estpwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP password\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0055");
	}

	@Test
	public void testSimpleEnrollSRPnoTAwHTTPv6PoPBadSRPPW () {
		/*
		 * This is a bad path SRP test w SRP and bad HTTP auth credentials
		 * provided and PoP on.
		 * 
		 * Enroll, ipv6, SRP, PoP on, srp user good, srp pw BAD, no TA, bad http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0056");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		
		// ipv4
		//ec.setServerName(mTestServer);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwdBLAH");
		ec.setHTTPCredentials("estuserBAD", "estpwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP password\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0056");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwGHTTPBadSRP () {
		/*
		 * This is a bad path SRP test with good HTTP auth credentials
		 * provided and with bad srp credentials.
		 * 
		 * Enroll, ipv4, SRP, no PoP, srp user BAD, srp pw BAD, no TA, good http
		 * 
		 * Expect failure to enroll
		 * 
		 */
		System.out.println("Beginning TC0057");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBADU", "srppwdBAD");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP credentials\n");
		}
		assertNull(newCert);		
		System.out.println("Ending TC0057");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwGHTTPBadSRPv6 () {
		/*
		 * This is a bad path SRP test with good HTTP auth credentials
		 * provided but with bad srp credentials.
		 * 
		 * Enroll, ipv6, SRP, no PoP, srp user BAD, srp pw BAD, no TA, good http
		 * 
		 * Expect failure to enroll
		 * 
		 */
		System.out.println("Beginning TC0058");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		//ec.setServerName(mTestServer);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBADU", "srppwdBAD");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP credentials\n");
		}
		assertNull(newCert);		
		System.out.println("Ending TC0058");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwHTTPBadSRP () {
		/*
		 * This is a bad path SRP test with BAD HTTP auth credentials
		 * provided.  Bad Srp Credentials but good http credentials
		 * 
		 * Enroll, ipv4, SRP, no PoP, srp user BAD, srp pw BAD, no TA, bad http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0059");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort2);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBADU", "srppwdBAD");
		ec.setHTTPCredentials("estuserBAD", "estpwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP credentials\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0059");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwHTTPBadSRPv6 () {
		/*
		 * This is a happy path SRP test w SRP and bad HTTP auth credentials
		 * provided.  Bad Srp Credentials fails even with good http credentials
		 * 
		 * Enroll, ipv6, SRP, no PoP, srp user BAD, srp pw BAD, no TA, bad http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0060");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		
		// ipv4
		//ec.setServerName(mTestServer);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort2);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBADU", "srppwdBAD");
		ec.setHTTPCredentials("estuserBAD", "estpwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP credentials\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0060");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwGHTTPwPoPBadSRP () {
		/*
		 * This is a bad path SRP test with good HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, PoP on, srp user BAD, srp pw BAD, no TA, good http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0061");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBADU", "srppwdBADBAD");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP credentials\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0061");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwGHTTPwPoPBadSRPv6 () {
		/*
		 * This is a bad path SRP test with good HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv6, SRP, PoP on, srp user BAD, srp pw BAD, no TA, good http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0062");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		//ec.setServerName(mTestServer);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBADU", "srppwdBOGUS");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP credentials\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0062");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwHTTPwPoPBadSRP () {
		/*
		 * This is a bad path SRP test with BAD HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, PoP on, srp user BAD, srp pw BAD, no TA, bad http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0063");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBADU", "srppwdBLAH");
		ec.setHTTPCredentials("estuserBAD", "estpwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP credentials\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0063");
	}

	@Test
	public void testSimpleEnrollSRPnoTAwHTTPv6PoPBadSRP () {
		/*
		 * This is a bad path SRP test w SRP and bad HTTP auth credentials
		 * provided and PoP on.
		 * 
		 * Enroll, ipv6, SRP, PoP on, srp user BAD, srp pw BAD, no TA, bad http
		 * 
		 * Expect fail to enroll
		 * 
		 */
		System.out.println("Beginning TC0064");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(mTrustDB);
		//ec.setTrustAnchor(certs);
		
		// ipv4
		//ec.setServerName(mTestServer);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpBADU", "srppwdBLAH");
		ec.setHTTPCredentials("estuserBAD", "estpwdBAD");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("\nEnroll failed as expected from bad SRP credentials\n");
		}
		assertNull(newCert);		

		System.out.println("Ending TC0064");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAnoPoPwHTTP () {
		/*
		 * This is a good path SRP test with HTTP auth credentials
		 * provided.
		 * 
		 * Enroll, ipv4, SRP, no PoP, srp user good, srp pw good, no TA, good http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0065");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0065");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAnoPoPwHTTPv6 () {
		/*
		 * This is a good path SRP test w SRP and HTTP auth credentials
		 * provided but no Trust Anchor set.
		 * 
		 * Enroll, ipv6, SRP, no PoP, srp user good, srp pw good, no TA, good http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0066");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
				
		// ipv4
		//ec.setServerName(mTestServer);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0066");
	}

	@Test
	public void testSimpleEnrollSRPnoTAwPoPwHTTP () {
		/*
		 * This is a good path SRP test with HTTP auth credentials
		 * provided, with PoP on and with no Trust Anchor set.
		 * 
		 * Enroll, ipv4, SRP, PoP on, srp user good, srp pw good, no TA, good http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0067");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		// ipv4
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0067");
	}
	
	@Test
	public void testSimpleEnrollSRPnoTAwPoPwHTTPv6 () {
		/*
		 * This is a good path SRP test w SRP and HTTP auth credentials
		 * provided, with no Trust Anchor and with PoP on.
		 * 
		 * Enroll, ipv6, SRP, PoP on, srp user good, srp pw good, no TA, good http
		 * 
		 * Expect success
		 * 
		 */
		System.out.println("Beginning TC0068");
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
				
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);		
		System.out.println("Ending TC0068");
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
	

} /* end of class ESTClientTestNonFIPS */


