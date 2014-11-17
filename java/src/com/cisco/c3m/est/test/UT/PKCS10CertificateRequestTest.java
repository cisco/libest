package com.cisco.c3m.est.test.UT;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.InvalidKeyException;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.cisco.c3m.est.*;


public class PKCS10CertificateRequestTest {

	/*
	 * This is a hard-coded CSR in DER format that's used with some
	 * of the test cases.
	 */
	private final byte mTestCSR1[] = new byte[] {
			48, -126, 1, 39, 48, -126, 1, 27, 2, 1, 0, 48, 114, 49, 19, 48, 17, 6, 3, 85, 4, 3, 19, 10, 99, 111, 109, 109, 111, 110, 78, 97, 109, 101, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 16, 48, 14, 6, 3, 85, 4, 7, 19, 7, 82, 97, 108, 101, 105, 103, 104, 49, 11, 48, 9, 6, 3, 85, 4, 8, 19, 2, 78, 67, 49, 14, 48, 12, 6, 3, 85, 4, 10, 19, 5, 84, 82, 73, 65, 68, 49, 31, 48, 29, 6, 3, 85, 4, 11, 19, 22, 70, 79, 82, 32, 84, 69, 83, 84, 32, 80, 85, 82, 80, 79, 83, 69, 83, 32, 79, 78, 76, 89, 48, -127, -97, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 3, -127, -115, 0, 48, -127, -119, 2, -127, -127, 0, -122, 88, 79, 10, 14, -104, -2, 23, -121, 89, -96, 57, 10, -42, -104, -45, 20, 110, 25, 102, -5, -90, -87, -81, 36, 6, 101, 75, 79, 21, 56, -19, 16, 94, 95, -92, -63, 17, -93, 75, -17, -118, -56, 99, 95, 28, -90, -115, 44, 31, -7, 108, -46, 117, 54, -53, -70, 38, 111, 22, 16, -82, -23, 90, 103, -75, 64, -52, -119, -107, 18, 32, 98, 85, -87, -87, 18, 122, 69, 14, 10, 101, 6, -117, -30, 105, -78, 11, -109, 104, -40, 60, -41, -47, 31, -32, -115, 34, 60, 65, 54, -13, 57, -28, 19, 44, -70, -126, 70, 8, 69, 58, -101, -121, -17, 90, 101, 67, 46, -37, -84, -46, -119, 33, -68, -76, -60, -113, 2, 3, 1, 0, 1, -96, 0, 48, 3, 6, 1, 0, 3, 1, 0
	};
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		System.out.println("Initializing PKCS10CertificateTest for " + ESTClient.getVersion() + "...");
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		System.out.println("Test completed.");
	}

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testPKCS10CertificateRequest() {
		PKCS10CertificateRequest csr = new PKCS10CertificateRequest();
		assertNotNull(csr); 
	}

	@Test
	public void testPKCS10CertificateRequestByteArray() {
		PKCS10CertificateRequest csr = new PKCS10CertificateRequest(mTestCSR1);
		assertNotNull(csr); 
}

	/*
	@Test
	public void testPKCS10CertificateRequestInputStream() {
		fail("Not yet implemented");
	}
	*/

	@Test
	public void testGenerateNewCSR() {
		KeyPairGenerator keyGen;
		SecureRandom rnd;
		KeyPair newKey;
		
		try {
			//Create a new keypair
			keyGen = KeyPairGenerator.getInstance("RSA");
			rnd = SecureRandom.getInstance("SHA1PRNG");
			keyGen.initialize(1024, rnd);
			newKey = keyGen.generateKeyPair();
		} catch (NoSuchAlgorithmException nsa) {
			fail("No such algorithm exception when generating RSA key");
			return;
		}

		//Set the SubjectName values that will be in the certificate
		PKCS10CertificateRequest csr = new PKCS10CertificateRequest();
		try {
			csr.generateNewCSR ("commonName", "US", "Raleigh", "NC", "TRIAD", "FOR TEST PURPOSES ONLY", newKey);
		} catch (PKCS10CreationException | InvalidKeyException | BufferSizeException e) {
			fail("Exception while generating new CSR");
			e.printStackTrace();
		}
		
	}

	@Test
	public void testGetBytes() {
		PKCS10CertificateRequest csr = new PKCS10CertificateRequest(mTestCSR1);
		assertNotNull(csr); 
		byte csrPEM[]; 
			
		/*
		 * Get the PEM representation of the CSR
		 */
		try {
			csrPEM = csr.getBytes(PKCS10CertificateRequest.Encoding.PEM);
		} catch (EncodingException ee) {
			fail("EncodingException while trying to PEM decode the CSR");
			return;
		} catch (IOException ioe) {
			fail("IOException while trying to PEM decode the CSR");
			return;
		}

		/*
		 * Parse the PEM output to see if it actually contains a CSR
		 */
		String PEM = new String(csrPEM);
		String s1 = new String("END CERTIFICATE REQUEST");
		int pos = PEM.indexOf(s1);
		assertTrue(pos > 0);
	}
}

/*
try {
	int i;
	byte t[] = csr.getBytes(PKCS10CertificateRequest.Encoding.DER);
	StringBuilder sb = new StringBuilder();
    for (byte b : t) {
        sb.append(String.format("%d, ", b));
    }
    System.out.println(sb.toString());
} catch (Exception e) {	}
*/


