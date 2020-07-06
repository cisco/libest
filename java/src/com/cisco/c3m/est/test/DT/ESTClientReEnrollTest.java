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
 * To take care of that we use a shell script "dt_start_estserver2.sh"
 * and call it in the setUpBeforeClass method which runs before
 * the other test methods are started.  Currently (Nov 2014) there
 * are multiple instances of estserver started by these scripts.
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
public class ESTClientReEnrollTest {
	private static X509Certificate[] mCerts;
	private static X509Certificate[] certs;
	private static X509Certificate[] javaCAcerts;
	
	private static String mTrustDB;
	private static String mTestServer = new String("127.0.0.1");
	
	/*
	 *  The following ports are used by the client to connect to estserver
	 *  instances.  The actual port number(s) will be acquired later and
	 *  passed in to the shell script that starts the estserver
	 */

	// port that estserver should be running on
	private static int mTestPort = 0;
	
	private static KeyPair mKey;
	private static PKCS10CertificateRequest mCSR;

        // The logger and stream handler are needed
        private static final Logger logger = Logger.getLogger(ESTClientReEnrollTest.class.getName());
        private static StreamHandler shOut = new StreamHandler(System.out, new SimpleFormatter());
        private static StreamHandler shErr = new StreamHandler(System.err, new SimpleFormatter());
        
	private static X509Certificate selfSignedCert;
	// added for reenroll testing
	private static X509Certificate badCert1;
	private static X509Certificate expiredCert1;
	private static String estBadClientKeyStore;
	private static String cacertsFileName;
	
	
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
            String script2 = "/java/src/com/cisco/c3m/est/test/DT/dt_start_estserver2.sh";

	    // add what we have so far to the command
	    command.add(dir1 + script2);

	    // get a free tcp port to use for the estserver
	    mTestPort = PortFinder.findUniqueFreePort();

	    // now add the port as a string to the command list as arg1
	    command.add(Integer.toString(mTestPort));
	    // we want the estserver start script to run in the background
	    command.add("&");

	    // create an instance and pass it our command list
	    ProcessBuilder builder2 = new ProcessBuilder(command);

	    Process proc2 = builder2.start();
	    // give some time for estserver to get going by sleeping a bit
	    System.out.println("Wait a few seconds for estservers to get ready ...");
	    Thread.sleep(4100);
	    
	    /************ Begin From setUp *************************/	    
            /*
	     * Get location of WORKSPACE on local file system
	     */
	    mTrustDB = System.getenv("EST_TRUST");
	    loadTA(mTrustDB);
	    estBadClientKeyStore = System.getenv("EST_REENROLL_BAD_JKS");
	    badCert1 = Helpers.getCert(estBadClientKeyStore);
	    mTestServer = System.getenv("EST_ADDR");
	    cacertsFileName = System.getenv("JAVA_CACERTS");
	    
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
	    System.out.println("ESTClientReEnrollTest has completed ...");
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
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		System.out.println("Ending TC3532");
	}

	@Test
	public void testGetNativeMaxCertLength() {
		System.out.println("Beginning TC3533");
		int m = ESTClient.getNativeMaxCertLength();
		assertTrue(m > 0);
		System.out.println("Native Max Cert Length is " + m);
		System.out.println("Ending TC3533");
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

	
    /*******************************************************************/
    /*******************************************************************/
    /******************* Begin Iron Sprint 4 Tests *********************/
	

	
	@Test
	public void testReEnrollHTTP_TLSAuth () {
		/*
		 * TC3033 - good path ReEnroll test using a good TA, valid client cert and HTTP auth
		 * 
		 * ReEnroll, ipv4, PoP off, HTTP Auth 1st, TLS Auth 2nd, HTTP cred1 good, HTTP cred2 not set
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3033");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);

		// unset http cred1
		ec.setHTTPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		
		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3033");
	}
	
	@Test
	public void testReEnrollHTTP_TLSAuthPoP () {
		/*
		 * TC3034 - good path ReEnroll test using a good TA, valid client cert and HTTP auth
		 * 
		 * ReEnroll, ipv4, PoP ON, HTTP Auth 1st, TLS Auth 2nd, HTTP cred1 good, HTTP cred2 not set
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3034");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset http cred1
		ec.setHTTPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert1, mKey);

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3034");
	}
	
	@Test
	public void testReEnrollHTTP_TLSAuthV6 () {
		/*
		 * TC3035 - good path ReEnroll test using a good TA, valid client cert and HTTP auth
		 * 
		 * ReEnroll, ipv6, PoP off, HTTP Auth 1st, TLS Auth 2nd, HTTP cred1 good, HTTP cred2 not set
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3035");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset http cred
		ec.setHTTPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert1, mKey);

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3035");
	}
	
	@Test
	public void testReEnrollHTTP_TLSAuthPoPv6 () {
		/*
		 * TC3036 - good path ReEnroll test using a good TA, valid client cert and HTTP auth
		 * 
		 * ReEnroll, ipv6, PoP ON, HTTP Auth 1st, HTTP Auth 2nd, HTTP cred1 good, HTTP cred2 not set
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3036");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset http cred
		ec.setHTTPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert1, mKey);

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3036");
	}
	
	@Test
	public void testReEnrollHTTP_TLSAuthSelf () {
		/*
		 * TC3037 - good path ReEnroll test using a good TA, self-signed cert and HTTP auth
		 * 
		 * ReEnroll, ipv4, PoP off, HTTP Auth 1st, TLS Auth 2nd, HTTP cred1 good, HTTP cred2 not set
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3037");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset http cred
		ec.setHTTPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert1, mKey);

		/*
		 * Now let's try to re-enroll a self-signed certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(selfSignedCert, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3037");
	}
	
	@Test
	public void testReEnrollHTTP_TLSAuthPoPSelf () {
		/*
		 * TC3038 - good path ReEnroll test using a good TA, self-signed cert and HTTP auth
		 * 
		 * ReEnroll, ipv4, PoP ON, HTTP Auth 1st, TLS Auth 2nd, HTTP cred1 good, HTTP cred2 not set
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3038");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset http cred
		ec.setHTTPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert1, mKey);

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(selfSignedCert, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3038");
	}
	
	@Test
	public void testReEnrollHTTP_TLSAuthV6Self () {
		/*
		 * TC3039 - good path ReEnroll test using a good TA, self-signed cert and HTTP auth
		 * 
		 * ReEnroll, ipv6, PoP off, HTTP Auth 1st, TLS Auth 2nd, HTTP cred1 good, HTTP cred2 not set
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3039");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset http cred
		ec.setHTTPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert1, mKey);

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(selfSignedCert, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3039");
	}
	
	@Test
	public void testReEnrollHTTP_TLSAuthPoPv6Self () {
		/*
		 * TC3040 - good path ReEnroll test using a good TA, self-signed cert and HTTP auth
		 * 
		 * ReEnroll, ipv6, PoP ON, HTTP Auth 1st, TLS Auth 2nd, HTTP cred1 good, HTTP cred2 not set
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3040");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset http cred
		ec.setHTTPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert1, mKey);

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(selfSignedCert, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3040");
	}
	
	@Test
	public void testReEnrollHTTP_HTTPAuth () {
		/*
		 * TC3041 - good path ReEnroll test using a good TA, valid client cert and HTTP auth
		 * 
		 * ReEnroll, ipv4, PoP off, HTTP Auth 1st, HTTP Auth 2nd, HTTP cred1 good, HTTP cred2 good
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3041");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3041");
	}
	
	@Test
	public void testReEnrollHTTP_HTTPAuthPoP () {
		/*
		 * TC3042 - good path ReEnroll test using a good TA, valid client cert and HTTP auth
		 * 
		 * ReEnroll, ipv4, PoP ON, HTTP Auth 1st, HTTP Auth 2nd, HTTP cred1 good, HTTP cred2 good
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3042");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3042");
	}
	
	@Test
	public void testReEnrollHTTP_HTTPAuthV6 () {
		/*
		 * TC3043 - good path ReEnroll test using a good TA, valid client cert and HTTP auth
		 * 
		 * ReEnroll, ipv6, PoP off, HTTP Auth 1st, HTTP Auth 2nd, HTTP cred1 good, HTTP cred2 good
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3043");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3043");
	}
	
	@Test
	public void testReEnrollHTTP_HTTPAuthPoPv6 () {
		/*
		 * TC3044 - good path ReEnroll test using a good TA, valid client cert and HTTP auth
		 * 
		 * ReEnroll, ipv6, PoP ON, HTTP Auth 1st, HTTP Auth 2nd, HTTP cred1 good, HTTP cred2 good
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3044");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3044");
	}
	
	@Test
	public void testReEnrollHTTP_HTTPAuthSelf () {
		/*
		 * TC3045 - good path ReEnroll test using a good TA, self-signed cert and HTTP auth
		 * 
		 * ReEnroll, ipv4, PoP off, HTTP Auth 1st, HTTP Auth 2nd, HTTP cred1 good, HTTP cred2 good
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3045");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		/*
		 * Now let's try to re-enroll a self-signed certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(selfSignedCert, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3045");
	}
	
	@Test
	public void testReEnrollHTTP_HTTPAuthPoPSelf () {
		/*
		 * TC3046 - good path ReEnroll test using a good TA, self-signed cert and HTTP auth
		 * 
		 * ReEnroll, ipv4, PoP ON, HTTP Auth 1st, HTTP Auth 2nd, HTTP cred1 good, HTTP cred2 good
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3046");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(selfSignedCert, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3046");
	}
	
	@Test
	public void testReEnrollHTTP_HTTPAuthV6Self () {
		/*
		 * TC3047 - good path ReEnroll test using a good TA, self-signed cert and HTTP auth
		 * 
		 * ReEnroll, ipv6, PoP off, HTTP Auth 1st, HTTP Auth 2nd, HTTP cred1 good, HTTP cred2 good
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3047");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(selfSignedCert, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3047");
	}
	
	@Test
	public void testReEnrollHTTP_HTTPAuthPoPv6Self () {
		/*
		 * TC3048 - good path ReEnroll test using a good TA, self-signed cert and HTTP auth
		 * 
		 * ReEnroll, ipv6, PoP ON, HTTP Auth 1st, HTTP Auth 2nd, HTTP cred1 good, HTTP cred2 good
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3048");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(selfSignedCert, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3048");
	}

	
	@Test
	public void testReEnrollTLS_TLSAuth () {
		/*
		 * TC3057 - good path ReEnroll test using a good TA, valid client cert and TLS auth
		 * 
		 * ReEnroll, ipv4, PoP off, TLS Auth 1st, TLS Auth 2nd, SRP cred2 not set, HTTP cred2 not set
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3057");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		assertNotNull(newCert0);

		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);

		// unset srp cred
		ec.setSRPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		
		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3057");
	}
	
	@Test
	public void testReEnrollTLS_TLSAuthPoP () {
		/*
		 * TC3058 - good path ReEnroll test using a good TA, valid client cert and TLS auth
		 * 
		 * ReEnroll, ipv4, PoP ON, TLS Auth 1st, TLS Auth 2nd, SRP cred2 not set, HTTP cred2 not set
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3058");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset srp cred
		ec.setSRPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert1, mKey);

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3058");
	}
	
	@Test
	public void testReEnrollTLS_TLSAuthV6 () {
		/*
		 * TC3059 - good path ReEnroll test using a good TA, valid client cert and TLS auth
		 * 
		 * ReEnroll, ipv6, PoP off, TLS Auth 1st, TLS Auth 2nd, SRP cred2 not set, HTTP cred2 not set
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3059");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset srp cred
		ec.setSRPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert1, mKey);

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3059");
	}
	
	@Test
	public void testReEnrollTLS_TLSAuthPoPv6 () {
		/*
		 * TC3060 - good path ReEnroll test using a good TA, valid client cert and TLS auth
		 * 
		 * ReEnroll, ipv6, PoP ON, TLS Auth 1st, SRP Auth 2nd, SRP cred2 not set, HTTP cred2 not set
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3060");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset srp cred
		ec.setSRPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert1, mKey);

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3060");
	}
	
	@Test
	public void testReEnrollTLS_TLSAuthSelf () {
		/*
		 * TC3061 - good path ReEnroll test using a good TA, self-signed cert and TLS auth
		 * 
		 * ReEnroll, ipv4, PoP off, TLS Auth 1st, TLS Auth 2nd, SRP cred2 not set, HTTP cred2 not set
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3061");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset srp cred
		ec.setSRPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert1, mKey);

		/*
		 * Now let's try to re-enroll a self-signed certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(selfSignedCert, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3061");
	}
	
	@Test
	public void testReEnrollTLS_TLSAuthPoPSelf () {
		/*
		 * TC3062 - good path ReEnroll test using a good TA, self-signed cert and TLS auth
		 * 
		 * ReEnroll, ipv4, PoP ON, TLS Auth 1st, TLS Auth 2nd, SRP cred2 not set, HTTP cred2 not set
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3062");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset srp cred
		ec.setSRPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert1, mKey);

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(selfSignedCert, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3062");
	}
	
	@Test
	public void testReEnrollTLS_TLSAuthV6Self () {
		/*
		 * TC3063 - good path ReEnroll test using a good TA, self-signed cert and TLS auth
		 * 
		 * ReEnroll, ipv6, PoP off, TLS Auth 1st, TLS Auth 2nd, SRP cred2 not set, HTTP cred2 not set
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3063");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset srp cred
		ec.setSRPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert1, mKey);

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(selfSignedCert, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3063");
	}
	
	@Test
	public void testReEnrollTLS_TLSAuthPoPv6Self () {
		/*
		 * TC3064 - good path ReEnroll test using a good TA, self-signed cert and TLS auth
		 * 
		 * ReEnroll, ipv6, PoP ON, TLS Auth 1st, TLS Auth 2nd, SRP cred2 not set, HTTP cred2 not set
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3064");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset srp cred
		ec.setSRPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert1, mKey);

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(selfSignedCert, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3064");
	}
	
	@Test
	public void testReEnrollTLS_HTTPAuth () {
		/*
		 * TC3065 - good path ReEnroll test using a good TA, valid client cert and TLS auth
		 * 
		 * ReEnroll, ipv4, PoP off, TLS Auth 1st, HTTP Auth 2nd, SRP cred2 not set, HTTP cred2 good
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3065");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);

		// unset srp cred
		ec.setSRPCredentials("", "");
		ec.setHTTPCredentials("estuser", "estpwd");
		
		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3065");
	}
	
	@Test
	public void testReEnrollTLS_HTTPAuthPoP () {
		/*
		 * TC3066 - good path ReEnroll test using a good TA, valid client cert and TLS auth
		 * 
		 * ReEnroll, ipv4, PoP ON, TLS Auth 1st, HTTP Auth 2nd, SRP cred2 not set, HTTP cred2 good
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3066");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset srp cred
		ec.setSRPCredentials("", "");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3066");
	}
	
	@Test
	public void testReEnrollTLS_HTTPAuthV6 () {
		/*
		 * TC3067 - good path ReEnroll test using a good TA, valid client cert and TLS auth
		 * 
		 * ReEnroll, ipv6, PoP off, TLS Auth 1st, HTTP Auth 2nd, SRP cred2 not set, HTTP cred2 good
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3067");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset srp cred
		ec.setSRPCredentials("", "");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3067");
	}
	
	@Test
	public void testReEnrollTLS_HTTPAuthPoPv6 () {
		/*
		 * TC3068 - good path ReEnroll test using a good TA, valid client cert and TLS auth
		 * 
		 * ReEnroll, ipv6, PoP ON, TLS Auth 1st, HTTP Auth 2nd, SRP cred2 not set, HTTP cred2 good
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3068");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset srp cred
		ec.setSRPCredentials("", "");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3068");
	}
	
	@Test
	public void testReEnrollTLS_HTTPAuthSelf () {
		/*
		 * TC3069 - good path ReEnroll test using a good TA, self-signed cert and TLS auth
		 * 
		 * ReEnroll, ipv4, PoP off, TLS Auth 1st, HTTP Auth 2nd, SRP cred2 not set, HTTP cred2 good
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3069");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset srp cred
		ec.setSRPCredentials("", "");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Now let's try to re-enroll a self-signed certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(selfSignedCert, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3069");
	}
	
	@Test
	public void testReEnrollTLS_HTTPAuthPoPSelf () {
		/*
		 * TC3070 - good path ReEnroll test using a good TA, self-signed cert and TLS auth
		 * 
		 * ReEnroll, ipv4, PoP ON, TLS Auth 1st, HTTP Auth 2nd, SRP cred2 not set, HTTP cred2 good
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3070");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset srp cred
		ec.setSRPCredentials("", "");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(selfSignedCert, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3070");
	}
	
	@Test
	public void testReEnrollTLS_HTTPAuthV6Self () {
		/*
		 * TC3071 - good path ReEnroll test using a good TA, self-signed cert and TLS auth
		 * 
		 * ReEnroll, ipv6, PoP off, TLS Auth 1st, HTTP Auth 2nd, SRP cred2 not set, HTTP cred2 good
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3071");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset srp cred
		ec.setSRPCredentials("", "");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(selfSignedCert, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3071");
	}
	
	@Test
	public void testReEnrollTLS_HTTPAuthPoPv6Self () {
		/*
		 * TC3072 - good path ReEnroll test using a good TA, self-signed cert and TLS auth
		 * 
		 * ReEnroll, ipv6, PoP ON, TLS Auth 1st, HTTP Auth 2nd, SRP cred2 not set, HTTP cred2 good
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3072");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// unset srp cred
		ec.setSRPCredentials("", "");
		ec.setHTTPCredentials("estuser", "estpwd");

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(selfSignedCert, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3072");
	}
	
	@Test
	public void testReEnrollHTTP_TLSAuthNeg () throws Exception {
		/*
		 * TC3081 - bad path ReEnroll test using a good TA, valid client cert and HTTP auth
		 * 
		 * ReEnroll, ipv4, PoP off, HTTP Auth 1st, TLS Auth 2nd, HTTP cred2 not set, SRP cred2 not set
		 * 
		 * Expect Enroll Exception
		 */			
		System.out.println("Beginning TC3081");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);

		ec.setSRPCredentials("", "");
		// reset http credentials set in "provisionTrustedCert"
		ec.setHTTPCredentials("", "");
		// load a TA for the client that has no certs in common with the TA of our estserver so that
		// TLS authentication will fail
		ec.setTrustAnchor(javaCAcerts);

		/*
		 * Now let's try to re-enroll this new certificate with mismatched TAs (should fail TLS auth)
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (EnrollException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
			System.out.println("TC3081 - Enroll Exception thrown as expected due to failed TLS auth - pass");
		}
		assertNull(newCert2);
		System.out.println("Ending TC3081");
	}
	
	@Test
	public void testReEnrollHTTP_TLSAuthPoPNeg () throws Exception {
		/*
		 * TC3082 - bad path ReEnroll test using a good TA, valid client cert and HTTP auth
		 * 
		 * ReEnroll, ipv4, PoP ON, HTTP Auth 1st, TLS Auth 2nd, HTTP cred2 not set, SRP cred2 not set
		 * 
		 * Expect Enroll Exception
		 */			
		System.out.println("Beginning TC3082");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		ec.setSRPCredentials("", "");
		// reset http credentials set in "provisionTrustedCert"
		ec.setHTTPCredentials("", "");
		// load a TA for the client that has no certs in common with the TA of our estserver so that
		// TLS authentication will fail
		ec.setTrustAnchor(javaCAcerts);

		/*
		 * Now let's try to re-enroll this new certificate with mismatched TAs (should fail TLS auth)
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (EnrollException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
			System.out.println("TC3082 - Enroll Exception thrown as expected due to failed TLS auth - pass");
		}
		assertNull(newCert2);
		System.out.println("Ending TC3082");
	}
	
	@Test
	public void testReEnrollTLS_TLSAuthNeg () throws Exception {
		/*
		 * TC3083 - bad path ReEnroll test using a good TA, valid client cert and TLS auth
		 * 
		 * ReEnroll, ipv4, PoP off, TLS Auth 1st, TLS Auth 2nd, SRP cred2 not set, HTTP cred2 not set
		 * 
		 * Expect Enroll Exception
		 */			
		System.out.println("Beginning TC3083");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		// reset http credentials set in "provisionTrustedCert"
		ec.setSRPCredentials("", "");
		ec.setHTTPCredentials("", "");
		// load a TA for the client that has no certs in common with the TA of our estserver so that
		// TLS authentication will fail
		ec.setTrustAnchor(javaCAcerts);

		/*
		 * Now let's try to re-enroll this new certificate but with trust anchors mismatched
		 *   (Mismatched = TA for estserver has nothing in common with TA for java EST client).
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (EnrollException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
			System.out.println("TC3083 - Enroll Exception thrown as expected due to TLS authentication failure - pass");
		}
		assertNull(newCert2);
		System.out.println("Ending TC3083");
	}
	
	@Test
	public void testReEnrollTLS_TLSAuthPoPNeg () throws Exception {
		/*
		 * TC3084 - bad path ReEnroll test using a good TA, valid client cert and TLS auth
		 * 
		 * ReEnroll, ipv4, PoP ON, TLS Auth 1st, TLS Auth 2nd, SRP cred2 not set, HTTP cred2 not set
		 * 
		 * Expect Enroll Exception
		 */			
		System.out.println("Beginning TC3084");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		ec.setHTTPCredentials("", "");
		// reset credentials set in "provisionTrustedCert" or elsewhere
		ec.setSRPCredentials("", "");
		ec.setHTTPCredentials("", "");
		// load a TA for the client that has no certs in common with the TA of our estserver so that
		// TLS authentication will fail
		ec.setTrustAnchor(javaCAcerts);

		/*
		 * Now let's try to re-enroll this new certificate but with mismatched TAs
		 */
		ec.setTLSAuthenticationCredentials(newCert1, mKey);
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (EnrollException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
			System.out.println("TC3084 - Enroll Exception thrown as expected due to failed TLS auth - pass");
		}
		assertNull(newCert2);
		System.out.println("Ending TC3084");
	}
	
	@Test
	public void testReEnrollHTTP_HTTPAuthNeg () throws Exception {
		/*
		 * TC3087 - bad path ReEnroll test using a good TA, valid client cert and HTTP auth
		 * 
		 * ReEnroll, ipv4, PoP off, HTTP Auth 1st, HTTP Auth 2nd, HTTP cred2 bad, SRP cred2 bad
		 * 
		 * Expect Enroll Exception
		 */			
		System.out.println("Beginning TC3087");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);

		ec.setSRPCredentials("", "");

		/*
		 * Now let's try to re-enroll this new certificate but with bad HTTP credentials
		 */
		ec.setHTTPCredentials("estuserBOGUS", "estpwdBOGUS");
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (EnrollException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
			System.out.println("TC3087 - Enroll Exception thrown as expected due to bad http credentials - pass");
		}
		assertNull(newCert2);
		System.out.println("Ending TC3087");
	}
	
	@Test
	public void testReEnrollHTTP_HTTPAuthPoPNeg () throws Exception {
		/*
		 * TC3088 - bad path ReEnroll test using a good TA, valid client cert and HTTP auth
		 * 
		 * ReEnroll, ipv4, PoP ON, HTTP Auth 1st, HTTP Auth 2nd, HTTP cred2 bad, SRP cred2 not set
		 * 
		 * Expect Enroll Exception
		 */			
		System.out.println("Beginning TC3088");
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		ec.setSRPCredentials("", "");

		/*
		 * Now let's try to re-enroll this new certificate but with bad HTTP credentials
		 */
		ec.setHTTPCredentials("estuserBOGUS", "estpwdBOGUS");
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.TRUE);
		} catch (EnrollException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
			System.out.println("TC3088 - Enroll Exception thrown as expected due to bad http credentials - pass");
		}
		assertNull(newCert2);
		System.out.println("Ending TC3088");
	}
	
	@Test
	public void testReEnrollTLS_HTTPAuthNeg () throws Exception {
		/*
		 * TC3089 - bad path ReEnroll test using a good TA, valid client cert and TLS auth
		 * 
		 * ReEnroll, ipv4, PoP off, TLS Auth 1st, HTTP Auth 2nd, SRP cred2 bad, HTTP cred2 bad
		 * 
		 * Expect Enroll Exception
		 */			
		System.out.println("Beginning TC3089");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		ec.setHTTPCredentials("", "");
		ec.setSRPCredentials("", "");

		/*
		 * Now let's try to re-enroll this new certificate but with bad HTTP credentials
		 */
		ec.setHTTPCredentials("estuserBOGUS", "estpwdBOGUS");
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (EnrollException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
			System.out.println("TC3089 - Enroll Exception thrown as expected due to bad http credentials - pass");
		}
		assertNull(newCert2);
		System.out.println("Ending TC3089");
	}
	
	@Test
	public void testReEnrollTLS_HTTPAuthPoPNeg () throws Exception {
		/*
		 * TC3090 - bad path ReEnroll test using a good TA, valid client cert and TLS auth
		 * 
		 * ReEnroll, ipv4, PoP ON, TLS Auth 1st, HTTP Auth 2nd, SRP cred2 not set, HTTP cred2 bad
		 * 
		 * Expect Enroll Exception
		 */			
		System.out.println("Beginning TC3090");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert1 = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert1 = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert1);
		
		ec.setSRPCredentials("", "");

		/*
		 * Now let's try to re-enroll this new certificate but with bad HTTP credentials
		 */
		ec.setHTTPCredentials("estuserBOGUS", "estpwdBOGUS");
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert1, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.TRUE);
		} catch (EnrollException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
			System.out.println("TC3090 - Enroll Exception thrown as expected due to bad http credentials - pass");
		}
		assertNull(newCert2);
		System.out.println("Ending TC3090");
	}



    /*******************************************************************/	
	
	@Test
	public void testSimpleReEnrollHTTPAuth () {
		/*
		 * TC3101 - good path ReEnroll test using a valid client cert and http auth
		 * 
		 * ReEnroll, ipv4, HTTP Auth, PoP off, good http cred, good TA
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3101");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		// should be set in first simple enroll testcase
		assertNotNull(newCert0);
		
		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert0, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3101");
	}
	
	@Test
	public void testSimpleReEnrollTLSAuth () {
		/*
		 * TC3103 - good path ReEnroll test using a valid client cert and TLS auth
		 * 
		 * ReEnroll, ipv4, TLS Auth, PoP off, goot http cred, good TA
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3103");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now let's try to re-enroll this new certificate
		 */
		ec.setHTTPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert0, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3103");
	}
	
	@Test
	public void testSimpleReEnrollTLSAuth2 () {
		/*
		 * TC3104 - good path ReEnroll test using a valid client cert and TLS auth
		 * 
		 * ReEnroll, ipv4, TLS Auth, PoP off, goot http cred, good TA
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3104");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now let's try to re-enroll with a self-signed certificate
		 * using a good cert for TLS authentication
		 */
		ec.setHTTPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		try {
			newCert2 = ec.sendSimpleReenrollRequest(selfSignedCert, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3104");
	}

	@Test
	public void testSimpleReEnrollTLSAuth3 () {
		/*
		 * TC3105 - good path ReEnroll test using a valid client cert and TLS auth
		 * 
		 * ReEnroll, ipv4, TLS Auth, PoP off, goot http cred, good TA
		 * 
		 * Expect success
		 */			
		System.out.println("Beginning TC3105");
		X509Certificate newCert0 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		//loadTA(cacertsFileName);
		loadTA(mTrustDB);
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now let's try to re-enroll with a self-signed certificate
		 * using a good cert for TLS authentication
		 */
		ec.setHTTPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert0, mKey);
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert0, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
		System.out.println("Ending TC3105");
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
	private static X509Certificate provisionTrustedCert() {
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
		System.out.println("Beginning loadTA for " + jksFile);

		try {
			InputStream rs = new FileInputStream(jksFile);
			store = KeyStore.getInstance("JKS");
			store.load(rs, pass.toCharArray());
			Enumeration e = store.aliases();
			//First, see how many certs we have
			while (e.hasMoreElements() && c_count < 1000) {
				String alias = (String)e.nextElement();
				if (store.isCertificateEntry(alias)) {
					c_count++;
				}
			}
			//Allocate space for the certs
			certs = new X509Certificate[c_count];
			e = store.aliases();
			c_count = 0;
			while (e.hasMoreElements() && c_count < 1000) {
				String alias = (String)e.nextElement();
				if (store.isCertificateEntry(alias)) {
					System.out.println("found " + alias + " is trust cert: " + store.isCertificateEntry(alias));
					certs[c_count] = (java.security.cert.X509Certificate)store.getCertificate(alias);
					c_count++;
					System.out.println("Cert count is " + c_count);
				}
			}
			rs.close();
		} catch (Exception e) {
			System.out.println("Exception in JESTTest: " + e.getMessage());
			System.out.println(e.getStackTrace());			
		}
	}
	

} /* end of class ESTClientReEnrollTest */


