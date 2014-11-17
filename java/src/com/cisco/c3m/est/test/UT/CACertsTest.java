package com.cisco.c3m.est.test.UT;

/*
 * CACertsTest.java
 *
 *  Created on: Aug 12, 2014
 *      Author: foleyj
 *
 * Copyright (c) 2014 by cisco Systems, Inc.
 * All rights reserved.
 *
 */

import static org.junit.Assert.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

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
	private static String mTrustDB;
	private static String mUntrustedDB;
	private static String mTestServer = new String("127.0.0.1");
	private static int mTestPort = 0;
	private static KeyPair mKey;
	private PKCS10CertificateRequest mCSR;
	private KeyStore mStore;
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		System.out.println("Initializing CACertsTest for "
				+ ESTClient.getVersion() + "...");

		/*
		 * Get location of WORKSPACE on local file system
		 */
		mTrustDB = System.getenv("EST_TRUST");
		mUntrustedDB = System.getenv("EST_UNTRUSTED");
		mTestServer = System.getenv("EST_ADDR");
		mTestPort = Integer.parseInt(System.getenv("EST_PORT"));
		mCerts = Helpers.loadTA(mTrustDB);
		mUntrustedCerts = Helpers.loadTA(mUntrustedDB);

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
		
		/*
		 * Let's make sure we can import the certs into a JKS
		 */
		try {
			String pass = "changeit";
			InputStream rs = new FileInputStream(mTrustDB);
			mStore = KeyStore.getInstance("JKS");
			mStore.load(rs, pass.toCharArray());
		} catch (KeyStoreException e) {
			fail(e.getMessage());
			e.printStackTrace();
			System.out.println("WARNING:  Unable to init keystore, suite will fail!!!!");
		}
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testGetCACerts() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server
		 */
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
			
			/*
			 * Add this cert to the keystore
			 */
			KeyStore.TrustedCertificateEntry caEntry = new KeyStore.TrustedCertificateEntry(c);
			try {
				mStore.setEntry(c.getSerialNumber().toString(), caEntry, null);
			} catch (KeyStoreException e) {
				fail(e.getMessage());
				e.printStackTrace();
				return;
			}
		}
	}

	@Test
	public void testGetCACerts_SRP() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server
		 */
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setSRPCredentials("srpuser", "srppwd");
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
	}

	@Test
	public void testGetCACerts_SRPandTA() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server
		 */
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setSRPCredentials("srpuser", "srppwd");
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
	}

	@Test
	public void testGetCACerts_noTA() {
		/*
		 * Attempt to retrieve CA certs but use a NULL trust anchor
		 */
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
	}

	@Test
	public void testGetCACerts_untrustedTA() {
		/*
		 * Attempt to retrieve CA certs but use a trust anchor that will not
		 * validate the EST server
		 */
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

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
	}

	@Test
	public void testGetCACerts_simpleEnroll() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server.  We then use those certs to do a 
		 * simple enroll.
		 */
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
	}
}
