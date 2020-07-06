package com.cisco.c3m.est.test.DT;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class Helpers {
	/*
	 * This function will take the name of a file on the local system that is a Java keystore (JKS).
	 * It will load the file into a KeyStore object and pull out the trusted certificates.
	 * It returns an array of X509Certificate objects that contain these trusted certs.
	 */
	public static X509Certificate[] loadTA (String jksFile) {
		int c_count = 0;
		KeyStore store;
		String pass = "changeit";
		X509Certificate certs[] = null;

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
		return certs;
	}
	
	/*
	 * This function will take the name of a file on the local system that is a Java keystore (JKS).
	 * It will load the file into a KeyStore object and pull out the first certificate.
	 * It returns an X509Certificate object that contains the cert.
	 */
	public static X509Certificate getCert (String jksFile) {
		int c_count = 0;
		KeyStore store;
		String pass = "changeit";
		X509Certificate cert = null;

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
			e = store.aliases();
			c_count = 0;
			while (e.hasMoreElements() && c_count < 10) {
				String alias = (String)e.nextElement();
				// just take the first cert we find
				if (store.isCertificateEntry(alias)) {
					System.out.println("found " + alias + " is trust cert: " + store.isCertificateEntry(alias));
					cert = (java.security.cert.X509Certificate)store.getCertificate(alias);
					break;
				} else {
					c_count++;
				}
			}
			rs.close();
		} catch (Exception e) {
			System.out.println("Exception in JESTTest: " + e.getMessage());
			System.out.println(e.getStackTrace());			
		}
		return cert;
	}
	
	
	
}
