package com.cisco.c3m.est.test.DT;

/*
 * CACertsTest.java
 *
 *  Created on: Sept 25, 2014
 *      Author: sbf
 *
 * Copyright (c) 2014 by cisco Systems, Inc.
 * All rights reserved.
 *
 */

import static org.junit.Assert.*;

import java.io.*;
import java.util.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.logging.StreamHandler;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.cisco.c3m.est.BufferSizeException;
import com.cisco.c3m.est.CACertsException;
import com.cisco.c3m.est.ESTClient;
import com.cisco.c3m.est.EncodingException;
import com.cisco.c3m.est.EnrollException;
import com.cisco.c3m.est.EnrollRetryAfterException;
import com.cisco.c3m.est.PKCS10CertificateRequest;
import com.cisco.c3m.est.PKCS10CreationException;
import com.cisco.c3m.est.ESTClient.NativeLogLevel;

public class CACertsTest {
	private static X509Certificate[] mCerts;
	private static X509Certificate[] mUntrustedCerts;
	private static X509Certificate mUntrustedCert1;
	private static String mTrustDB;
	private static String mUntrustedDB;
	private static String mTestServer = new String("127.0.0.1");
	private static int mTestPort = 0;
	private static KeyPair mKey;
	private PKCS10CertificateRequest mCSR;
	
	private int temp_int1 = 0;

        // The logger and stream handler are needed
        private static final Logger logger = Logger.getLogger(ESTClientTest.class.getName());
        private static StreamHandler shOut = new StreamHandler(System.out, new SimpleFormatter());
        private static StreamHandler shErr = new StreamHandler(System.err, new SimpleFormatter());

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	    System.out.println("Initializing CACertsTest for "+ ESTClient.getVersion() + "...");
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
	    // give some time for estservers to get going by sleeping a bit
	    Thread.sleep(4100);
	    
     	    /************ Begin From setUp *************************/	    
            /*
	     * Get location of WORKSPACE on local file system
	     */
	    mTrustDB = System.getenv("EST_TRUST");
	    mUntrustedDB = System.getenv("EST_UNTRUSTED");
	    mTestServer = System.getenv("EST_ADDR");
	    mCerts = Helpers.loadTA(mTrustDB);
	    mUntrustedCerts = Helpers.loadTA(mUntrustedDB);
	    mUntrustedCert1 = Helpers.getCert(mUntrustedDB);

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
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	    System.out.println("Dev Test CACertsTest has completed ...");
	    /* 
	     *  sleep a few seconds so that junit summary output
	     *  is printed after testcase output
	     */
	    Thread.sleep(3500);
	}

	@Before
	public void setUp() throws Exception {
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
			System.out.println("WARNING:  Unable to initialize CSR for all the tests, suite will fail!!!!");
		}}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testGetCACerts() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server
		 *
		 * get cacerts, ipv4, good TA, no srp cred, no http cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2001");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setTrustAnchor(mCerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2001");
	}

	@Test
	public void testGetCACerts_TAandTLS() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server
		 *
		 * get cacerts, ipv4, good TA, no srp cred, no http cred, good TLS cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2002");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;

		assertNotNull(ec);

		ec.setTrustAnchor(mCerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		// get a good cert to use for tls credentials
		myCert1 = getTrustedCert();
		ec.setTLSAuthenticationCredentials(myCert1, mKey);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2002");
	}

	@Test
	public void testGetCACerts_HTTPandTA() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server
		 * 
		 * get cacerts, ipv4, good TA, good http cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2003");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setTrustAnchor(mCerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2003");
	}
	



	@Test
	public void testGetCACerts_noTA() {
		/*
		 * Attempt to retrieve CA certs but use a NULL trust anchor
		 * 
		 * get cacerts, ipv4, no TA, no srp
		 * 
		 * Expect: failure to get cacerts
		 * 
		 */
		System.out.println("Beginning TC2010");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		// ec.setTrustAnchor(certs);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (CACertsException cae) {
			System.out.println("Caught CACertsException as expected: "
					+ cae.getMessage());
		}
		assertNull(newCACerts);
		System.out.println("Ending TC2010");
	}

	@Test
	public void testGetCACerts_ClientCert() {
		/*
		 * This is a basic negative path test case
		 *
		 * get cacerts, ipv4, no TA, no srp cred, no http cred
		 * good client cert
		 * 
		 * Expect: failure getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2011");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;
		
		assertNotNull(ec);
		// get a good cert to use for tls authentication
		myCert1 = getTrustedCert();

		assertNotNull(myCert1);

		System.out.println("\nSetting TLS authentication credentials ...");

		ec.setTLSAuthenticationCredentials(myCert1, mKey);
		
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (Exception e) {
			System.out.println("Caught Exception as expected: "
					+ e.getMessage());
		}
		assertNull(newCACerts);
		
		System.out.println("Ending TC2011");
	}
	
	@Test
	public void testGetCACerts_HTTPandNoTA() {
		/*
		 * This is a basic negative path test case
		 * 
		 * get cacerts, ipv4, no TA, good http cred
		 * 
		 * Expect: failure getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2012");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setHTTPCredentials("estuser", "estpwd");
		//ec.setTrustAnchor(mCerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (Exception e) {
			System.out.println("Caught Exception as expected: "
					+ e.getMessage());
		}
		assertNull(newCACerts);
		System.out.println("Ending TC2012");
	}
	
	@Test
	public void testGetCACerts_untrustedTA() {
		/*
		 * Attempt to retrieve CA certs but use a trust anchor that will not
		 * validate the EST server
		 * 
		 * get cacerts, ipv4, untrusted TA, no srp
		 * 
		 * Expect: failure to get cacerts
		 * 
		 */
		System.out.println("Beginning TC2013");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		// note - using untrusted trust anchor
		ec.setTrustAnchor(mUntrustedCerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (CACertsException cae) {
			System.out.println("Caught CACertsException as expected: "
					+ cae.getMessage());
		}
		assertNull(newCACerts);
		System.out.println("Ending TC2013");
	}

	@Test
	public void testGetCACerts_unTA_ClientCert() {
		/*
		 * This is a basic negative path test case
		 *
		 * get cacerts, ipv4, untrusted TA, no srp cred, no http cred
		 * good client cert
		 * 
		 * Expect: failure getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2017");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;
		
		assertNotNull(ec);
		// get a good cert to use for tls authentication
		myCert1 = getTrustedCert();

		assertNotNull(myCert1);

		System.out.println("\nSetting TLS authentication credentials ...");

		ec.setTLSAuthenticationCredentials(myCert1, mKey);
		
		// note - using untrusted trust anchor
		ec.setTrustAnchor(mUntrustedCerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (Exception e) {
			System.out.println("Caught Exception as expected: "
					+ e.getMessage());
		}
		assertNull(newCACerts);
		
		System.out.println("Ending TC2017");
	}
	
	@Test
	public void testGetCACerts_unTAandHTTP() {
		/*
		 * This is a basic negative path test case
		 * 
		 * get cacerts, ipv4, untrusted TA, good http cred
		 * 
		 * Expect: failure getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2018");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setHTTPCredentials("estuser", "estpwd");
		//ec.setTrustAnchor(mCerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (Exception e) {
			System.out.println("Caught Exception as expected: "
					+ e.getMessage());
		}
		assertNull(newCACerts);
		System.out.println("Ending TC2018");
	}
	
	@Test
	public void testGetCACerts_simpleEnroll() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server.  We then use those certs to do a 
		 * simple enroll.
		 * 
		 * get cacerts + simple enroll, ipv4, good TA, no srp cred
		 * good http cred, httponly auth, no PoP
		 * 
		 * Expect: success getting cacerts and successful enroll
		 * 
		 */
		System.out.println("Beginning TC2019");
		ArrayList<X509Certificate> newCACerts = null;
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setTrustAnchor(mCerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		
		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
			return;
		}
		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		
		/*
		 * OK, we have the new trust anchor.  Let's start a new session
		 * using this TA and attempt a simple enroll.
		 */
		ec = new ESTClient();
		assertNotNull(ec);

		ec.setTrustAnchor(newCACerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException | CertificateException | IOException
				| EncodingException | EnrollException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
		System.out.println("Ending TC2019");
	}
	
	@Test
	public void testGetCACerts_simpleEnroll_PoP() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server.  We then use those certs to do a 
		 * simple enroll.
		 * 
		 * get cacerts + simple enroll, ipv4, good TA, no srp cred
		 * good http cred, httponly auth, PoP on
		 * 
		 * Expect: success getting cacerts and successful enroll
		 * 
		 */
		System.out.println("Beginning TC2020");
		ArrayList<X509Certificate> newCACerts = null;
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setTrustAnchor(mCerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		
		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
			return;
		}
		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		
		/*
		 * OK, we have the new trust anchor.  Let's start a new session
		 * using this TA and attempt a simple enroll.
		 */
		ec = new ESTClient();
		assertNotNull(ec);

		ec.setTrustAnchor(newCACerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.TRUE);
		} catch (InvalidKeyException | CertificateException | IOException
				| EncodingException | EnrollException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
		System.out.println("Ending TC2020");
	}

	
	
	@Test
	public void testGetCACerts_simpleEnroll_TLS() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server.  We then use those certs to do a 
		 * simple enroll.
		 * 
		 * get cacerts + simple enroll, ipv4, good TA, no srp cred
		 * no http cred, good TLS cred, TLS auth, no PoP
		 * 
		 * Expect: success getting cacerts and successful enroll
		 * 
		 */
		System.out.println("Beginning TC2023");
		ArrayList<X509Certificate> newCACerts = null;
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;

		assertNotNull(ec);

		ec.setTrustAnchor(mCerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		
		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
			return;
		}
		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		
		/*
		 * OK, we have the new trust anchor.  Let's start a new session
		 * using this TA and attempt a simple enroll.
		 */
		ec = new ESTClient();
		assertNotNull(ec);

		ec.setTrustAnchor(newCACerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		// get a good cert to use for tls credentials
		myCert1 = getTrustedCert();
		ec.setTLSAuthenticationCredentials(myCert1, mKey);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException | CertificateException | IOException
				| EncodingException | EnrollException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
		System.out.println("Ending TC2023");
	}
	
	@Test
	public void testGetCACerts_simpleEnroll_TLSwPoP() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server.  We then use those certs to do a 
		 * simple enroll.
		 * 
		 * get cacerts + simple enroll, ipv4, good TA, no srp cred
		 * no http cred, good TLS cred, TLS auth, with PoP
		 * 
		 * Expect: success getting cacerts and successful enroll
		 * 
		 */
		System.out.println("Beginning TC2024");
		ArrayList<X509Certificate> newCACerts = null;
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;

		assertNotNull(ec);

		ec.setTrustAnchor(mCerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		
		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
			return;
		}
		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		
		/*
		 * OK, we have the new trust anchor.  Let's start a new session
		 * using this TA and attempt a simple enroll.
		 */
		ec = new ESTClient();
		assertNotNull(ec);

		ec.setTrustAnchor(newCACerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		// get a good cert to use for tls credentials
		myCert1 = getTrustedCert();
		ec.setTLSAuthenticationCredentials(myCert1, mKey);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (InvalidKeyException | CertificateException | IOException
				| EncodingException | EnrollException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
		System.out.println("Ending TC2024");
	}
	
	@Test
	public void testGetCACertsV6() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server
		 *
		 * get cacerts, ipv6, good TA, no srp cred, no http cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2025");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setTrustAnchor(mCerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2025");
	}
	
	@Test
	public void testGetCACerts_TAandTLSv6() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server
		 *
		 * get cacerts, ipv6, good TA, no srp cred, no http cred, good TLS cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2026");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;

		assertNotNull(ec);

		ec.setTrustAnchor(mCerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		// get a good cert to use for tls credentials
		myCert1 = getTrustedCert();
		ec.setTLSAuthenticationCredentials(myCert1, mKey);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2026");
	}

	@Test
	public void testGetCACerts_HTTPandTAv6() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server
		 * 
		 * get cacerts, ipv6, good TA, good http cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2027");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setTrustAnchor(mCerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2027");
	}

	@Test
	public void testGetCACerts_noTAv6() {
		/*
		 * Attempt to retrieve CA certs but use a NULL trust anchor
		 * 
		 * get cacerts, ipv6, no TA, no srp
		 * 
		 * Expect: failure to get cacerts
		 * 
		 */
		System.out.println("Beginning TC2034");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		// ec.setTrustAnchor(certs);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (CACertsException cae) {
			System.out.println("Caught CACertsException as expected: "
					+ cae.getMessage());
		}
		assertNull(newCACerts);
		System.out.println("Ending TC2034");
	}

	@Test
	public void testGetCACerts_ClientCertV6() {
		/*
		 * This is a basic negative path test case
		 *
		 * get cacerts, ipv6, no TA, no srp cred, no http cred
		 * good client cert
		 * 
		 * Expect: failure getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2035");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;
		
		assertNotNull(ec);
		// get a good cert to use for tls authentication
		myCert1 = getTrustedCert();

		assertNotNull(myCert1);

		System.out.println("\nSetting TLS authentication credentials ...");

		ec.setTLSAuthenticationCredentials(myCert1, mKey);
		
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (Exception e) {
			System.out.println("Caught Exception as expected: "
					+ e.getMessage());
		}
		assertNull(newCACerts);
		
		System.out.println("Ending TC2035");
	}
	
	@Test
	public void testGetCACerts_HTTPandNoTAv6() {
		/*
		 * This is a basic negative path test case
		 * 
		 * get cacerts, ipv6, no TA, good http cred
		 * 
		 * Expect: failure getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2036");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setHTTPCredentials("estuser", "estpwd");
		//ec.setTrustAnchor(mCerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (Exception e) {
			System.out.println("Caught Exception as expected: "
					+ e.getMessage());
		}
		assertNull(newCACerts);
		System.out.println("Ending TC2036");
	}
	
	@Test
	public void testGetCACerts_untrustedTAv6() {
		/*
		 * Attempt to retrieve CA certs but use a trust anchor that will not
		 * validate the EST server
		 * 
		 * get cacerts, ipv6, untrusted TA, no srp
		 * 
		 * Expect: failure to get cacerts
		 * 
		 */
		System.out.println("Beginning TC2037");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		// note - using untrusted trust anchor
		ec.setTrustAnchor(mUntrustedCerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		} catch (CACertsException cae) {
			System.out.println("Caught CACertsException as expected: "
					+ cae.getMessage());
		}
		assertNull(newCACerts);
		System.out.println("Ending TC2037");
	}

	
	@Test
	public void testGetCACerts_unTA_ClientCertV6() {
		/*
		 * This is a basic negative testcase
		 *
		 * get cacerts, ipv6, untrusted TA, no srp cred, no http cred
		 * good client cert
		 * 
		 * Expect: failure getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2041");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;
		
		assertNotNull(ec);
		// get a good cert to use for tls authentication
		myCert1 = getTrustedCert();

		assertNotNull(myCert1);

		System.out.println("\nSetting TLS authentication credentials ...");

		ec.setTLSAuthenticationCredentials(myCert1, mKey);
		
		// note - using untrusted trust anchor
		ec.setTrustAnchor(mUntrustedCerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (Exception e) {
			System.out.println("Caught Exception as expected: "
					+ e.getMessage());
		}
		assertNull(newCACerts);
		
		System.out.println("Ending TC2041");
	}
	
	@Test
	public void testGetCACerts_unTAandHTTPv6() {
		/*
		 * This is a basic negative testcase
		 * 
		 * get cacerts, ipv6, untrusted TA, good http cred
		 * 
		 * Expect: failure getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2042");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setHTTPCredentials("estuser", "estpwd");
		//ec.setTrustAnchor(mCerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (Exception e) {
			System.out.println("Caught Exception as expected: "
					+ e.getMessage());
		}
		assertNull(newCACerts);
		System.out.println("Ending TC2042");
	}
	
	@Test
	public void testGetCACerts_simpleEnrollV6() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server.  We then use those certs to do a 
		 * simple enroll.
		 * 
		 * get cacerts + simple enroll, ipv6, good TA, no srp cred
		 * good http cred, httponly auth, no PoP
		 * 
		 * Expect: success getting cacerts and successful enroll
		 * 
		 */
		System.out.println("Beginning TC2043");
		ArrayList<X509Certificate> newCACerts = null;
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setTrustAnchor(mCerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		
		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
			return;
		}
		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		
		/*
		 * OK, we have the new trust anchor.  Let's start a new session
		 * using this TA and attempt a simple enroll.
		 */
		ec = new ESTClient();
		assertNotNull(ec);

		ec.setTrustAnchor(newCACerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException | CertificateException | IOException
				| EncodingException | EnrollException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
		System.out.println("Ending TC2043");
	}
	
	@Test
	public void testGetCACerts_simpleEnroll_PoPv6() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server.  We then use those certs to do a 
		 * simple enroll.
		 * 
		 * get cacerts + simple enroll, ipv6, good TA, no srp cred
		 * good http cred, httponly auth, PoP on
		 * 
		 * Expect: success getting cacerts and successful enroll
		 * 
		 */
		System.out.println("Beginning TC2044");
		ArrayList<X509Certificate> newCACerts = null;
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setTrustAnchor(mCerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		
		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
			return;
		}
		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		
		/*
		 * OK, we have the new trust anchor.  Let's start a new session
		 * using this TA and attempt a simple enroll.
		 */
		ec = new ESTClient();
		assertNotNull(ec);

		ec.setTrustAnchor(newCACerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.TRUE);
		} catch (InvalidKeyException | CertificateException | IOException
				| EncodingException | EnrollException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
		System.out.println("Ending TC2044");
	}

	@Test
	public void testGetCACerts_simpleEnroll_TLSv6() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server.  We then use those certs to do a 
		 * simple enroll.
		 * 
		 * get cacerts + simple enroll, ipv6, good TA, no srp cred
		 * no http cred, good TLS cred, TLS auth, no PoP
		 * 
		 * Expect: success getting cacerts and successful enroll
		 * 
		 */
		System.out.println("Beginning TC2047");
		ArrayList<X509Certificate> newCACerts = null;
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;

		assertNotNull(ec);

		ec.setTrustAnchor(mCerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		
		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
			return;
		}
		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		
		/*
		 * OK, we have the new trust anchor.  Let's start a new session
		 * using this TA and attempt a simple enroll.
		 */
		ec = new ESTClient();
		assertNotNull(ec);

		ec.setTrustAnchor(newCACerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		// get a good cert to use for tls credentials
		myCert1 = getTrustedCert();
		ec.setTLSAuthenticationCredentials(myCert1, mKey);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.FALSE);
		} catch (InvalidKeyException | CertificateException | IOException
				| EncodingException | EnrollException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
		System.out.println("Ending TC2047");
	}
	
	@Test
	public void testGetCACerts_simpleEnroll_TLSwPoPv6() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server.  We then use those certs to do a 
		 * simple enroll.
		 * 
		 * get cacerts + simple enroll, ipv6, good TA, no srp cred
		 * no http cred, good TLS cred, TLS auth, with PoP
		 * 
		 * Expect: success getting cacerts and successful enroll
		 * 
		 */
		System.out.println("Beginning TC2048");
		ArrayList<X509Certificate> newCACerts = null;
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;

		assertNotNull(ec);

		ec.setTrustAnchor(mCerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		
		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
			return;
		}
		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		
		/*
		 * OK, we have the new trust anchor.  Let's start a new session
		 * using this TA and attempt a simple enroll.
		 */
		ec = new ESTClient();
		assertNotNull(ec);

		ec.setTrustAnchor(newCACerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		// get a good cert to use for tls credentials
		myCert1 = getTrustedCert();
		ec.setTLSAuthenticationCredentials(myCert1, mKey);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authTLS, mKey, Boolean.TRUE);
		} catch (InvalidKeyException | CertificateException | IOException
				| EncodingException | EnrollException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
		System.out.println("Ending TC2048");
	}
	
	@Test
	public void testGetCACerts_TAandUntrustedTLS() {
		/*
		 * This is a basic positive testcase
		 *
		 * get cacerts, ipv4, good TA, no srp cred, no http cred, untrusted TLS cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2049");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		ec.setTrustAnchor(mCerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		// Use an untrusted cert for the client
		ec.setTLSAuthenticationCredentials(mUntrustedCert1, mKey);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (Exception e) {
			System.out.println("Caught Exception as expected: "
					+ e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCACerts);
		System.out.println("Ending TC2049");
	}

	
	@Test
	public void testGetCACerts_TAandUntrustedTLSv6() {
		/*
		 * This is a basic positive testcase
		 *
		 * get cacerts, ipv6, good TA, no srp cred, no http cred, untrusted TLS cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2051");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		ec.setTrustAnchor(mCerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		// Use an untrusted cert for the client
		ec.setTLSAuthenticationCredentials(mUntrustedCert1, mKey);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (Exception e) {
			System.out.println("Caught Exception as expected: "
					+ e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCACerts);
		System.out.println("Ending TC2051");
	}

	
    /*******************************************************************/
    /*******************************************************************/
    /*******************************************************************/
    /*******************************************************************/
	
	
	/*
	 * This helper routine is used by some testcases using TLS authentication
	 * 
	 *  used like this:  X509Certificate myCert1 = getTrustedCert();
	 * 
	 */
	private X509Certificate getTrustedCert() {
		System.out.println("Beginning getTrustedCert ...");
		ESTClient ec = new ESTClient();
		X509Certificate newCert = null;
		
		assertNotNull(ec);
		
		mCerts = Helpers.loadTA(mTrustDB);
		ec.setTrustAnchor(mCerts);
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

	
	/* ***** End of Class CACertsTest ******** */
}
