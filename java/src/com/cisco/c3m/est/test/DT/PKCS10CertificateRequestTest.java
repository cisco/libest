package com.cisco.c3m.est.test.DT;

import org.junit.*;
import static org.junit.Assert.*;

import java.io.*;

import java.util.logging.*;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

import org.junit.rules.ExpectedException;

import com.cisco.c3m.est.*;

public class PKCS10CertificateRequestTest {
    
    /*
     * This is a hard-coded CSR in DER format that's used with some
     * of the test cases.
     */
    private final byte mTestCSR1[] = new byte[] {
    		48, -126, 1, 39, 48, -126, 1, 27, 2, 1, 0, 48, 114, 49, 19, 48, 17, 6, 3, 85, 4, 3, 19, 10, 99, 111, 109, 109, 111, 110, 78, 97, 109, 101, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 16, 48, 14, 6, 3, 85, 4, 7, 19, 7, 82, 97, 108, 101, 105, 103, 104, 49, 11, 48, 9, 6, 3, 85, 4, 8, 19, 2, 78, 67, 49, 14, 48, 12, 6, 3, 85, 4, 10, 19, 5, 84, 82, 73, 65, 68, 49, 31, 48, 29, 6, 3, 85, 4, 11, 19, 22, 70, 79, 82, 32, 84, 69, 83, 84, 32, 80, 85, 82, 80, 79, 83, 69, 83, 32, 79, 78, 76, 89, 48, -127, -97, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 3, -127, -115, 0, 48, -127, -119, 2, -127, -127, 0, -122, 88, 79, 10, 14, -104, -2, 23, -121, 89, -96, 57, 10, -42, -104, -45, 20, 110, 25, 102, -5, -90, -87, -81, 36, 6, 101, 75, 79, 21, 56, -19, 16, 94, 95, -92, -63, 17, -93, 75, -17, -118, -56, 99, 95, 28, -90, -115, 44, 31, -7, 108, -46, 117, 54, -53, -70, 38, 111, 22, 16, -82, -23, 90, 103, -75, 64, -52, -119, -107, 18, 32, 98, 85, -87, -87, 18, 122, 69, 14, 10, 101, 6, -117, -30, 105, -78, 11, -109, 104, -40, 60, -41, -47, 31, -32, -115, 34, 60, 65, 54, -13, 57, -28, 19, 44, -70, -126, 70, 8, 69, 58, -101, -121, -17, 90, 101, 67, 46, -37, -84, -46, -119, 33, -68, -76, -60, -113, 2, 3, 1, 0, 1, -96, 0, 48, 3, 6, 1, 0, 3, 1, 0
    };
    
    // The logger and stream handler are neede
    private static final Logger logger = Logger.getLogger(PKCS10CertificateRequestTest.class.getName());
    private static StreamHandler shOut = new StreamHandler(System.out, new SimpleFormatter());
    private static StreamHandler shErr = new StreamHandler(System.err, new SimpleFormatter());
    
    // vars for use in reading in a pkcs10 file
    private String fileNameAndPath01 = null;
    
    @BeforeClass
	public static void setUpBeforeClass() throws Exception {
        logger.setLevel(Level.INFO);
		System.out.println("Testing CiscoJEST Version " + ESTClient.getVersion() + "   !!!");
    }
    
    @AfterClass
	public static void tearDownAfterClass() throws Exception {
	    Thread.sleep(3500);
    }
    
    @Before
	public void setUp() throws Exception {
        logger.info("****************************************************************");
        logger.addHandler(shOut);
        logger.addHandler(shErr);
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
     * Make sure we can instantiate a new pkcs10 csr
     */
    @Test
	public void testPKCS10CertificateRequest() {
    	System.out.println("Beginning TC3554 ");
    	
    	PKCS10CertificateRequest csr0 = new PKCS10CertificateRequest();
    	System.out.println("This is a message to standard out 01...");
    	PKCS10CertificateRequest csr1 = new PKCS10CertificateRequest();
    	PKCS10CertificateRequest csr2 = new PKCS10CertificateRequest();
    	PKCS10CertificateRequest csr3 = new PKCS10CertificateRequest();
    	PKCS10CertificateRequest csr4 = new PKCS10CertificateRequest();
    	assertNotNull(csr0); 
    	assertNotNull(csr1); 
    	assertNotNull(csr2); 
    	assertNotNull(csr3); 
    	assertNotNull(csr4); 
    	System.out.println("This is a message to standard out 02...");
   	
    	System.out.println("Ending TC3554 ");
    }
    
    /*
     * Make sure we can create a pkcs10 csr from a byte array
     */
    @Test
	public void testPKCS10CertificateRequestByteArray() {
        System.out.println("Beginning TC3555");

        PKCS10CertificateRequest csr = new PKCS10CertificateRequest(mTestCSR1);
    	assertNotNull(csr); 

    	System.out.println("Ending TC3555 ");
    }
    
    /*
     *  For now just make sure we catch the appropriate exception
     *  until this method is fully implemented.
     */
    @Test
	public void testPKCS10CertificateRequestInputStream() throws FileNotFoundException {
        System.out.println("Beginning TC3556");
    	// use an env var to set full path and name of file to read
	
    	String fileNameAndPath01 = System.getenv("EST_DT_PKCS10_FILE01");
    	if (fileNameAndPath01 == null ) {
    		System.out.println("Make sure EST_DT_PKCS10_FILE01 is defined as environment var before running test...");
    	}
	
    	// we need an input stream to test this method so turn file into input stream
    	InputStream is1 = new FileInputStream(new File(fileNameAndPath01));
    	BufferedReader myReader1 = new BufferedReader(new InputStreamReader(is1));
	
    	/*
    	 * we do not really need to print out the file yet but we will put this in for later
    	 */
    	StringBuilder out1 = new StringBuilder();
	
    	// read in all lines from the file to print out for debugging
    	String line1;
    	try {
    		while ((line1 = myReader1.readLine()) != null) {
    			out1.append(line1);
    		}
    	} catch (IOException e0) {
    		e0.printStackTrace();
    	}
	
	
    	// Now make sure that we either get a valid csr or that we get expected exception
    	try {
    		// test using an input stream to read in a file and create a pkcs10 cert request
    		PKCS10CertificateRequest csr1 = new PKCS10CertificateRequest(is1);
    		// should not be null when PKCS10CertificateRequest implements this method
    		assertNotNull(csr1);
    	} catch (UnsupportedOperationException uoe1) {
    		System.out.println("UnsupportedOperationException caught as expected");
    	}
	
    	// must close the reader when done
    	try {
    		myReader1.close();
    	} catch (IOException e1) {
    		e1.printStackTrace();
    	}
	
        System.out.println("Ending TC3556");
    }
    
    

    /*
     * Verify basic population of a CSR
     */
    @Test
	public void testGenerateNewCSR() {
        System.out.println("Beginning TC3557");
    	KeyPairGenerator keyGen;
    	SecureRandom rnd;
    	KeyPair newKey;
    	
    	try {
    		//Create a new keypair
    		keyGen = KeyPairGenerator.getInstance("RSA");
    		rnd = SecureRandom.getInstance("SHA1PRNG");
    		keyGen.initialize(2048, rnd);
    		newKey = keyGen.generateKeyPair();
    	} catch (NoSuchAlgorithmException nsa) {
    		fail("No such algorithm exception when generating RSA key");
    		return;
    	}
	
    	//Set the SubjectName values that will be in the certificate
    	PKCS10CertificateRequest csr = new PKCS10CertificateRequest();
    	try {
    		csr.generateNewCSR ("commonName", "US", "Raleigh", "NC", "SandTO", "FOR TEST PURPOSES ONLY", newKey);
    	} catch (PKCS10CreationException | BufferSizeException | InvalidKeyException e) {
    		fail("Exception while generating new CSR");
    		e.printStackTrace();
    	}
	
        System.out.println("Ending TC3557");
    }
    
    /*
     *  This test may not work if the java.security file does not point
     *  to a valid security provider that can do EC keys
     */
    @Test
	public void testGenerateNewCSRwithECC() throws Exception {
        System.out.println("Beginning TC3558");
    	KeyPairGenerator keyGen;
    	KeyPair newKey;
    	System.out.println("We are starting testGenerateNEWCSRwithECC ...");
    	try {
	    
    		//Create a new ECC key pair 
    		keyGen = KeyPairGenerator.getInstance("EC");
    		System.out.println("Called KeyPairGenerator ...");
    		ECGenParameterSpec ecSpec1;
    		ecSpec1 = new ECGenParameterSpec("secp192r1");
    		System.out.println("Called ECGenParameterSpec secp192r1 ...");
    		keyGen.initialize(ecSpec1);
    		System.out.println("Called keyGen.initialize ...");
	    
    		newKey = keyGen.genKeyPair();
    		System.out.println("Called keyGen.genKeyPair ...");
	    
    	} catch (Exception e1) {
    		e1.printStackTrace();
    		fail("No such algorithm exception when generating ECC key");
    		return;
    	}
	
    	//Set the SubjectName values that will be in the certificate
    	PKCS10CertificateRequest csr = new PKCS10CertificateRequest();
    	try {
    		csr.generateNewCSR ("commonName", "US", "Raleigh", "NC", "SandTO", "FOR TEST PURPOSES ONLY", newKey);
    	} catch (PKCS10CreationException pce) {
    		fail("PKCS10CreationException while generating new CSR with ECC keypair");
    	} catch (InvalidKeyException ike) {
    		fail("InvalidKeyException while generating CSR with ECC keypair");
    	}
	
        System.out.println("Ending TC3558");
    }
    
    
    /*
     *  Send in bogus parameters to testGenerateNewCSR
     *  and see if we catch the expected exceptions
     */

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
	public void testGenerateNewCSRwithBadParms() {
        System.out.println("Beginning TC3559");
    	System.out.println("TC3559");
    	KeyPairGenerator keyGen;
    	SecureRandom rnd;
    	KeyPair newKey = null;
	
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
    		csr.generateNewCSR ("", "", "", "", "", "", newKey);
		fail("TC3559: failed to generate exception as expected.");
    	} catch (PKCS10CreationException pce) {
    		pce.getMessage();
    		System.out.println("TC3559: PKCS10CreationException while generating new CSR as expected");
	        pce.printStackTrace();
    	} catch (Exception e) {
	        System.out.println("TC3559: Exception caught as expected.");
	        e.printStackTrace();
    	} catch (Throwable e2) {
	        System.out.println("TC3559: Error caught as expected.");
	        e2.printStackTrace();    		
    	}
        System.out.println("Ending TC3559");
    }
    
    
    @Test
	public void testGetBytes() {
        System.out.println("Beginning TC3560");
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
        System.out.println("Ending TC3560");
    }
}

