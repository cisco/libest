import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.*;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import com.cisco.c3m.est.*;
import com.cisco.c3m.est.ESTClient.NativeLogLevel;

import javax.net.ssl.*;


import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSet;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;





public class JESTTest {
	private static X509Certificate[] certs;

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
	
	
	/*
	 * This function will test the new cert and keypair.  It creates a new
	 * keystore and uses that to establish a TLS session.  It's hard-coded to
	 * use 127.0.0.1:4433, which is the s_server default.  You'll need to run
	 * s_server using a cert/key that's bound to the same CA that issued
	 * the cert passed into this function.
	 */
	private static void testCert(X509Certificate cert, KeyPair key) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, KeyManagementException {
		/*
		 * Create a new keystore
		 */
		char[] password = "changeit".toCharArray();
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(null, password);

		/*
		 * Add our new cert to the keystore
		 */
		ks.setCertificateEntry("newcert", cert);
		int i;
		/*
		 * Add our trusted certs to the keystore
		 */
		for (i = 0; i < certs.length; i++) {
			ks.setCertificateEntry("trustcert" + i, certs[i]);
		}

		/*
		 * Create a new cert array containing only our new cert and use
		 * that to add the keypair to the keystore
		 */
		X509Certificate lCerts[] = new X509Certificate[1]; 
		lCerts[0] = cert;
		ks.setKeyEntry("newkey", key.getPrivate(), password, lCerts); 
		
		// Store away the keystore.
		//FileOutputStream fos = new FileOutputStream("/tmp/tmp.jks");
		//ks.store(fos, password);
		//fos.close();

		/*
		 * Create a key manager and trust manager, needed for TLS
		 */
  		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(ks, password);
		KeyManager[] km = kmf.getKeyManagers();
		MyTrustManager mtm;
		try {
			mtm = new MyTrustManager(ks);
		} catch (Exception e) {
			System.out.println(e.getMessage());
			return;
		}
		
		/*
		 * Initialize the TLS context
		 */
		SSLContext sc = SSLContext.getInstance("TLS");
		sc.init(km, new MyTrustManager[] {mtm}, null);
		
		/*
		 * This is simply some dumby data we'll send across the TLS tunnel
		 */
	    StringBuilder final_command = new StringBuilder();
		final_command.append("Send this string");
		    		
		/*
		 * Open the tunnel
		 */
		SSLSocketFactory sslsocketfactory = (SSLSocketFactory) sc.getSocketFactory();
		SSLSocket sslsocket = (SSLSocket) sslsocketfactory.createSocket("127.0.0.1", 4433);
		
		//InputStream inputstream = sslsocket.getInputStream();
		//InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
		//BufferedReader bufferedreader = new BufferedReader(inputstreamreader);

		/*
		 * Send some data across the tunnel
		 */
		OutputStream outputstream = sslsocket.getOutputStream();
		OutputStreamWriter outputstreamwriter = new OutputStreamWriter(outputstream);
		BufferedWriter bufferedwriter = new BufferedWriter(outputstreamwriter);

		bufferedwriter.write(final_command.toString() + '\n');
		bufferedwriter.flush();
		
		sslsocket.close();
	}
	
  	
	/*
	 * This method shows how to use bouncy castle to generate a
	 * PKCS10 certificate request that is unsigned.  CiscoJEST
	 * requires the CSR to be unsigned for PoP.  This method also
	 * shows how to add X509 extensions to the CSR.
	 */
	private static PKCS10CertificateRequest genUnsignedCSRUsingBC (KeyPair key) {
		PKCS10CertificateRequest csr = null;
		CertificationRequestInfo info;
		ASN1ObjectIdentifier doi;
		DERSequence ddoi;
		
		try {
			PublicKey pubKey = key.getPublic();
	        ExtensionsGenerator extGen = new ExtensionsGenerator();
	        
	        /*
	         * Create and add some extensions that will go on the CSR
	         */
	        extGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
	        extGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
	        extGen.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_capwapAC));
	        List attributes = new ArrayList();
	        attributes.add(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(extGen.generate())));
            ASN1EncodableVector av = new ASN1EncodableVector();
            for (Iterator it = attributes.iterator(); it.hasNext();)
            {
                av.add(Attribute.getInstance(it.next()));
            }
	        DERSet ds = new DERSet(av);
	   
			/*
			 * Create the CSR and provide a CommonName
			 */
			info = new CertificationRequestInfo(new X500Name("CN=BCCSRTest"), 
					SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()), ds);
			ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(info);		
			
			/*
			 * Add an empty itu-t signature to the CSR
			 */
			doi = new ASN1ObjectIdentifier("0.0");
			ddoi = new DERSequence(doi);
			v.add(ddoi);
			byte nosig[] = {};
			DERBitString dbs = new DERBitString(nosig);
			v.add(dbs);

			/*
			 * Create the ASN.1 sequence
			 */
			DERSequence d = new DERSequence(v);

			/* The following is for debug only.  We write the CSR to the local
			 * file system.  OpenSSL can be used to view the CSR:
			 * 
			 * openssl req -text -inform DER -in /tmp/csr-bc
			 * openssl asn1parse -dump -inform DER -in /tmp/csr-bc
			 */
		    //FileOutputStream fos = new FileOutputStream("/tmp/csr-bc");
		    //fos.write(d.getEncoded());
		    //fos.close();			

		    /*
		     * Instantiate new PKCS10CertificateRequest using DER encoded CSR from bouncycastle
		     */
		    csr = new PKCS10CertificateRequest(d.getEncoded());
		} catch (Exception e) {
			System.out.println("Exception in genCSRUsingBC: " + e.getMessage());
		}
		return csr;
	}
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		ESTClient ec = new ESTClient();
		PKCS10CertificateRequest csr = new PKCS10CertificateRequest();
		PKCS10CertificateRequest csrBC;
		KeyPair newKey;
		
		if (args.length != 6) {
			System.out.println("Usage:  JESTTest <jksfile> <server> <port> <HTTP uid> <HTTP pwd> <CN>");
			return;
		}
		
		System.out.println("[arg0] JKS file:  " + args[0]);
		System.out.println("[arg1] server:    " + args[1]);
		System.out.println("[arg2] port:      " + args[2]);
		System.out.println("[arg3] HTTP user: " + args[3]);
		System.out.println("[arg4] HTTP pass: " + args[4]);
		System.out.println("[arg5] CN:        " + args[5]);
		
		/*
		 * Specify the EST server parameters and HTTP user credentials
		 */
		ec.setServerName(args[1]);
		ec.setServerPort(Integer.parseInt(args[2]));
		ec.setHTTPCredentials(args[3], args[4]);

		/*
		 * For demonstration, let's set the max cert size to 5KB
		 */
		System.out.println("Current max cert length is " + ESTClient.getNativeMaxCertLength());
		ESTClient.setNativeMaxCertLength(5*1024);

		//This first argument is the name of the JKS file that contains
		//the trusted root certs that we'll use with EST.  You can create
		//the JKS file using the example estserver estCA root cert using
		//This command after converting the cert from PEM to DER:
		//
		//  keytool -import -alias estCA -keystore estkeystore -file estCA/cacert.der
		//
		//When prompted for the keystore password, use "changeit"
		//
		loadTA(args[0]);
		ec.setTrustAnchor(certs);
		
		try {
			ec.enableFIPS();
		} catch (Exception e) {
			System.out.println("Unable to enable FIPS: " + e.getMessage());
		}
		
		try {
			//Create a new keypair
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG", "SUN");
			keyGen.initialize(1024, rnd);
			System.out.println("Creating new RSA key pair...");
			newKey = keyGen.generateKeyPair();

			//Set the SubjectName values that will be in the certificate
			System.out.println("Creating CSR...");
			csr.generateNewCSR (args[5], "US", "Raleigh", "NC", "TRIAD", "FOR TEST PURPOSES ONLY", newKey);

			//Uncomment the following to use BC to generate a CSR
			//csrBC = genUnsignedCSRUsingBC(newKey);
		    
			//For demonstration only, let's bump up the log level to full info 
			ec.setNativeLogLevel(NativeLogLevel.logFull);
			
			//Attempt to provision a new certificate
			ec.setSRPCredentials("srpuser", "srppwd");
			X509Certificate newCert = ec.sendSimpleEnrollRequest(csr, ESTClient.AuthMode.authHTTPonly, newKey, Boolean.FALSE); 
			if (newCert != null) {
				System.out.println("New cert was provisioned by " + newCert.getIssuerDN());
				System.out.println("New cert subjName is " + newCert.getSubjectDN().getName());
				
				/* 
				 * Let's try to enroll again using TLS client auth
				 */
				ec.setTLSAuthenticationCredentials(newCert, newKey);
				X509Certificate newCert2 = ec.sendSimpleEnrollRequest(csr, ESTClient.AuthMode.authTLS, newKey, Boolean.FALSE);
				if (newCert2 != null) {
					System.out.println("New cert2 was provisioned by " + newCert.getIssuerDN());
					System.out.println("New cert2 subjName is " + newCert.getSubjectDN().getName());					
				} else {
					System.out.println("An error occurred while enrolling using TLS client auth!!!");
					System.exit(1);					
				}
			} else {
				System.out.println("An error occurred while enrolling!!!");
				System.exit(1);
			}
			
			//Uncomment this to test the cert using a TLS session.  You'll need
			//to have s_server running on local host port 4433
			//testCert(newCert, newKey);
			
			System.out.println("Done");
		} catch (Exception e) {
			System.out.println("Exception in JESTTest: " + e.getMessage());
			e.printStackTrace();
			System.exit(1);
		}
	}
}
