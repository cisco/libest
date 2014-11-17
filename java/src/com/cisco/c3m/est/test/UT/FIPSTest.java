package com.cisco.c3m.est.test.UT;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.cisco.c3m.est.ESTClient;


public class FIPSTest {
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		System.out.println("Initializing FIPSTest for " + ESTClient.getVersion() + "...");
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
	public void testEnableFIPS() {
		ESTClient ec = new ESTClient();
		assertNotNull(ec);
		try {
			ec.enableFIPS();	
		} catch (Exception e) {
			fail(e.getMessage());
		}	
	}
	
}
