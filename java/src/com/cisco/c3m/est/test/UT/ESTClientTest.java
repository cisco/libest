package com.cisco.c3m.est.test.UT;

import static org.junit.Assert.*;


import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Enumeration;
import java.util.Date;

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.cisco.c3m.est.BufferSizeException;
import com.cisco.c3m.est.ESTClient;
import com.cisco.c3m.est.EncodingException;
import com.cisco.c3m.est.EnrollException;
import com.cisco.c3m.est.EnrollRetryAfterException;
import com.cisco.c3m.est.PKCS10CertificateRequest;
import com.cisco.c3m.est.ESTClient.NativeLogLevel;
import com.cisco.c3m.est.PKCS10CreationException;


/*
 * This class assumes the following environment variables are set:
 * 
 * EST_TRUST  - Location JKS file that contains trusted certs
 * EST_PORT   - Port number of EST server to use for testing simple enroll
 * EST_PORT_R - Port number of EST server to use that has retry-after enabled
 * EST_ADDR   - IP address of EST server
 */
public class ESTClientTest {
	private static X509Certificate[] certs;
	private static String mTrustDB;
	private static String mTestServer = new String("127.0.0.1");
	private static int mTestPort = 0;
	private static int mTestPortRetry = 0;
	private static KeyPair mKey;
	private PKCS10CertificateRequest mCSR;
	private static X509Certificate selfSignedCert;
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		System.out.println("Initializing ESTClientTest for " + ESTClient.getVersion() + "...");
		
		/*
		 * Get location of WORKSPACE on local file system
		 */
		mTrustDB = System.getenv("EST_TRUST");
		mTestServer = System.getenv("EST_ADDR");
		mTestPort = Integer.parseInt(System.getenv("EST_PORT"));
		mTestPortRetry = mTestPort + 1;
		certs = Helpers.loadTA(mTrustDB);
		
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
			System.out.println("WARNING:  Unable to create RSA key pair, suite will fail!!!!");
		}
		
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
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		System.out.println("Test completed.");
	}

	@Before
	public void setUp() throws Exception {
		try {
			/*
			 * Create a PKCS10 CSR that will be used for the various test cases
			 */
			mCSR = new PKCS10CertificateRequest();
			System.out.println("Creating CSR...");
			mCSR.generateNewCSR ("unit-testing", "US", "Raleigh", "NC", "TRIAD", "FOR TEST PURPOSES ONLY", mKey);
			assertNotNull(mCSR);
		} catch (InvalidKeyException | PKCS10CreationException e) {
			fail(e.getMessage());
			e.printStackTrace();
			System.out.println("WARNING:  Unable to initialize CSR for all the tests, suite will fail!!!!");
		}
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testSetNativeLogLevel() {
		ESTClient ec = new ESTClient();
		assertNotNull(ec);
		ec.setNativeLogLevel(NativeLogLevel.logWarnings);
		ec.setNativeLogLevel(NativeLogLevel.logErrors);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
	}

	@Test
	public void testGetNativeMaxCertLength() {
		int m = ESTClient.getNativeMaxCertLength();
		assertTrue(m > 0);
	}

	@Test
	public void testSetNativeMaxCertLength() {
		ESTClient.setNativeMaxCertLength(2023);
		int m = ESTClient.getNativeMaxCertLength();
		assertTrue(m == 2023);
	}

	@Test
	public void testSetTrustAnchor() {
		ESTClient ec = new ESTClient();
		assertNotNull(ec);
		ec.setTrustAnchor(certs);
	}

	@Test
	public void testSendSimpleEnrollRequest() {
		X509Certificate newCert = null;
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
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
	}

	@Test
	public void testSendSimpleEnrollRequestNoPoP() {
		X509Certificate newCert = null;
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
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.TRUE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
	}
	
	@Test
	public void testSimpleEnrollCorruptCSR() {
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		PKCS10CertificateRequest csr = null;
		
		assertNotNull(ec);
		
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
		} catch (InvalidKeyException | EnrollRetryAfterException
				| CertificateException | IOException | EncodingException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("Caught EnrollException as expected: " + ee.getMessage());
		}
		assertNull(newCert);
	}
	
	@Test
	public void testSimpleEnrollMismatchedtKey() {
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
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("Enroll failed as expected");
		}
		assertNull(newCert);		
	}
	
	@Test
	public void testSimpleEnrollRetryAfter() {
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
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
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollRetryAfterException era) {
			System.out.println("Retry-after exception caught as expected");
		}
		assertNull(newCert);
	}
	
	@Test
	public void testSimpleEnrollSRPwithHTTP () {
		/*
		 * This is a happy path SRP test with HTTP auth credentials
		 * provided.
		 */
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");		
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
	}

	@Test
	public void testSimpleEnrollSRPwoHTTP () {
		/*
		 * This is a happy path SRP test without HTTP auth credentials
		 * provided.
		 */
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
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
	}

	@Test
	public void testSimpleEnrollSRPnoTA () {
		/*
		 * This is a happy path SRP test without a trust anchor configured.
		 */
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
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
	}

	@Test
	public void testSimpleEnrollSRPNullCredentials () {
		/*
		 * Test SRP interface using a null user name
		 */
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		try {
			ec.setSRPCredentials(null, "password");
		} catch (IllegalArgumentException ie) {
			System.out.println("Caught IllegalArgumentException as expected: " + ie.getMessage());				
		}

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
			System.out.println("Caught EnrollException as expected: " + ee.getMessage());				
		}
		
		/*
		 * Test SRP interface using a null password
		 */
		try {
			ec.setSRPCredentials("user", null);
		} catch (IllegalArgumentException ie) {
			System.out.println("Caught IllegalArgumentException as expected: " + ie.getMessage());
		}

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
			System.out.println("Caught EnrollException as expected: " + ee.getMessage());				
		}
	}
	
	@Test
	public void testSimpleEnrollSRPInvalidCredentials () {
		/*
		 * Test SRP interface using an invalid password
		 */
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "chump");

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
			System.out.println("Caught EnrollException as expected: " + ee.getMessage());
		}
	}
	
	
	@Test
	public void testSimpleEnrollTLSAuth () {
		/*
		 * This is a happy path TLS auth test using a valid client cert.
		 */			
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Now that we have a cert that's within the trust chain of our CA, let's
		 * use that cert to enroll again using TLS auth.
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
	}
	
	@Test
	public void testSimpleEnrollTLSAuthBadCert () {
		
		X509Certificate newCert;
		
		/*
		 * This is a negative test of TLS auth using an invalid client cert.
		 * The cert is not trusted by the EST server.
		 */		
		ESTClient ec = new ESTClient();
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
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
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("Caught EnrollException as expected: " + ee.getMessage());	
		}
	}

	@Test
	public void testSimpleEnrollTLSAuthNullCert () {
		X509Certificate newCert;
		ESTClient ec = new ESTClient();
		assertNotNull(ec);

		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");		
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		
		/*
		 * Test the TLS auth interface using a null client cert.
		 */
		try {
			ec.setTLSAuthenticationCredentials(null, mKey);
		} catch (IllegalArgumentException ie) {
			System.out.println("Caught IllegalArgumentException as expected: " + ie.getMessage());
		}
		
		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("Caught EnrollException as expected: " + ee.getMessage());	
		}		

		/*
		 * Test the TLS auth interface using a null key.
		 */
		try {
			ec.setTLSAuthenticationCredentials(selfSignedCert, null);
		} catch (IllegalArgumentException ie) {
			System.out.println("Caught IllegalArgumentException as expected: " + ie.getMessage());
		}
	}

	@Test
	public void testSimpleEnrollTLSAuthCorruptCert () {
		byte encoded[];
		X509Certificate newCert1 = provisionTrustedCert();
		X509Certificate tCert = null;
		X509Certificate newCert;
		ByteArrayInputStream bi = null;
		
		/*
		 * Test the TLS auth interface using a corrupted client cert.
		 */
		try {
			encoded = newCert1.getEncoded();
			if (encoded.length < 16) {
				fail("Seed cert was not provisioned properly");
				return;
			}
			encoded[15] += 1;
			bi = new ByteArrayInputStream(encoded);
		    CertificateFactory cf = CertificateFactory.getInstance("X.509");
		    tCert = (X509Certificate)cf.generateCertificate(bi);
		} catch (CertificateEncodingException cee) {
			fail(cee.getMessage());
			cee.printStackTrace();
		} catch (CertificateException ce) {
			System.out.println("Unable to corrupt cert");
			fail(ce.getMessage());
			ce.printStackTrace();
		} finally {
			if (bi != null) {
				try {
					bi.close();
				} catch (IOException ioe) {
					
				}
		    }
		}
		
		ESTClient ec = new ESTClient();
		assertNotNull(ec);

		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");		
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		
		/*
		 * Now that we have a corrupted cert, try to use it
		 */
		try {
			ec.setTLSAuthenticationCredentials(tCert, mKey);
		} catch (IllegalArgumentException ie) {
			fail(ie.getMessage());
			ie.printStackTrace();
		}
		
		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (EnrollException ee) {
			System.out.println("Caught EnrollException as expected: " + ee.getMessage());	
		}				
	}

	@Test
	public void testSimpleReEnrollHTTPAuth () {
		X509Certificate newCert = null;
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
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
		
		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
	}
	
	@Test
	public void testSimpleReEnrollSRPAuth () {
		X509Certificate newCert = null;
		X509Certificate newCert2 = null;
		ESTClient ec = new ESTClient();
		
		assertNotNull(ec);
		
		ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

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
		
		/*
		 * Now let's try to re-enroll this new certificate
		 */
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
	}
	
	@Test
	public void testSimpleReEnrollTLSAuth () {
		X509Certificate newCert = null;
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
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
		
		/*
		 * Now let's try to re-enroll this new certificate
		 */
		ec.setHTTPCredentials("", "");
		ec.setTLSAuthenticationCredentials(newCert, mKey);
		try {
			newCert2 = ec.sendSimpleReenrollRequest(newCert, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert2);
	}
	
	/*
	 * This function will generate a self-signed certificate
	 */
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
}



/**
 * This code serializes a KeyPair and corrupts one of the bytes
 * when de-serializing.  This results in a null privateKey() 
 * on the KeyPair.  This may be useful for testing outlier
 * scenarios.
try {
	ByteArrayOutputStream b = new ByteArrayOutputStream();
	ObjectOutputStream o =  new ObjectOutputStream(b);
	o.writeObject(mKey);
	byte[] res = b.toByteArray();
	o.close();
	b.close();
	
	res[45] = (byte)(res[15] + 1);

	ByteArrayInputStream bi = new ByteArrayInputStream(res);
	ObjectInputStream oi = new ObjectInputStream(bi);
	tKey = (KeyPair)oi.readObject();
	assertNotNull(tKey);
	oi.close();
	bi.close(); 
} catch (IOException ioe) {
	fail(ioe.getMessage());
	return;
} catch (ClassNotFoundException cnfe) {
	fail(cnfe.getMessage());
	return;
}
*/
