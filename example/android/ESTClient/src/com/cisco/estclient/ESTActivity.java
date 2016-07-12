package com.cisco.estclient;

import java.io.*;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.app.Activity;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.EditText;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.content.Intent;
import android.text.method.ScrollingMovementMethod;


public class ESTActivity extends Activity implements View.OnClickListener,
		KeyChainAliasCallback {
	private Button btnEnroll;
	private Button btnInstall;
	private Button btnUseCert;
	private Button btnClearLog;
	private EditText etServer;
	private EditText etPort;
	private EditText etCN;
	private EditText etUID;
	private EditText etPWD;
	private TextView txtLog;
	private byte[] p12 = null;
	private byte[] cacerts = null;
	private boolean enroll_wait = false;


	static {
		System.loadLibrary("estwrap"); 
	}

	private LoggerThread lt;
	
	Handler loghndlr = new Handler() {
		@Override
		public void handleMessage(Message msg) {
			String detail;
			//android.util.Log.v("APP", "Handler message received");
			
			Bundle b = msg.getData();

			detail = b.getString("Detail");
			txtLog.append(detail);
			txtLog.append("\n");
			//sb.append(" " + b.getString("Results"));
			//sb.append("\n");
		}
	};
	
	Handler enrollhndlr = new Handler() {
		@Override
		public void handleMessage(Message msg) {
			//android.util.Log.v("APP", "Handler message received");
			
			Bundle b = msg.getData();

			p12 = b.getByteArray("Detail");
			enroll_wait = false;
			if (p12 != null) {
				logError("Enrollment complete, cert is ready to install.");
			} else {
				logError("Enrollment failed, please check the log.");
			}

			//sb.append(" " + b.getString("Results"));
			//sb.append("\n");
		}
	};
	
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_est);
		
		etServer = (EditText) findViewById(R.id.etServerName);
		etPort = (EditText) findViewById(R.id.etServerPort);
		etCN = (EditText) findViewById(R.id.etCN);
		etUID = (EditText) findViewById(R.id.etUID);
		etPWD = (EditText) findViewById(R.id.etPWD);
		txtLog = (TextView) findViewById(R.id.txtLog);
		txtLog.setMovementMethod(new ScrollingMovementMethod());
		
		btnEnroll = (Button) findViewById(R.id.btnEnroll);
		btnEnroll.setOnClickListener(this);
		btnInstall = (Button) findViewById(R.id.btnInstall);
		btnInstall.setOnClickListener(this);
		btnUseCert = (Button) findViewById(R.id.btnUseCert);
		btnUseCert.setOnClickListener(this);
		btnClearLog = (Button) findViewById(R.id.btnClearLog);
		btnClearLog.setOnClickListener(this);

		/* Add this in for stderr deubbing to logcat */
		new Thread() {
		    public void run() {
		        nativePipeSTDERRToLogcat();
		    }
		}.start(); 
		
		clearLogCat();
		lt = new LoggerThread(loghndlr);
		lt.start();
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		getMenuInflater().inflate(R.menu.activity_est, menu);
		return true;  
	}
	
	@Override
	public void alias(final String alias) {
		Log.d("TEST", "Thread: " + Thread.currentThread().getName());
		Log.d("TEST", "selected alias: " + alias);	
	}
 
	public void onClick(View view) {
		//byte[] tmp_bytes = new byte[16384]; // This may not be large enough
		//int c_len = 0;
		Integer port = Integer.valueOf(etPort.getText().toString());

		if (view.equals(btnUseCert)) {
			KeyChain.choosePrivateKeyAlias(this, this, new String[] { "RSA" },
					null, null, -1, null); 
		} 

		if (view.equals(btnClearLog)) {
			txtLog.setText("");
		} 
		
		if (view.equals(btnEnroll)) {
			if (!lt.isAlive()) lt.run();
/* This code uses the local asset file to retrieve the trusted certs
			try {
				AssetManager am = this.getAssets();
				InputStream cacertsIS = am.open("cacert.crt");
				c_len = cacertsIS.read(tmp_bytes, 0, tmp_bytes.length);
				cacertsIS.close();
				cacerts = new byte[c_len+1];
				for (int z = 0; z < c_len; z++) {
					cacerts[z] = tmp_bytes[z];
				}
				cacerts[c_len] = 0;
			} catch (IOException e) {
				logError("IO error: " + e.getMessage());
				return;
			}
*/
			if (cacerts == null) {
				//FIXME - we should probably do this on a background thread
				//        since reading the Android cert store is slow
				logError("Loading trust anchor from Android cert store...");
				cacerts = getTA();
			}
			if (enroll_wait) {
				logError("Enrollment currently in process, please wait...");
				return;
			}
			EnrollThread et = new EnrollThread(etCN.getText().toString(), 
					etUID.getText().toString().trim(),
					etPWD.getText().toString().trim(),
					etServer.getText().toString().trim(), port.intValue(), 
					cacerts,
					enrollhndlr);
			enroll_wait = true;
			logError("Please wait while the certificate is provisioned...");
			et.start();
		}
		if (view.equals(btnInstall)) {
		
			if (p12 != null) {
				Intent intent = KeyChain.createInstallIntent();
				intent.putExtra(KeyChain.EXTRA_PKCS12, p12);
				intent.putExtra(KeyChain.EXTRA_NAME, "MyNewCert");
				startActivity(intent);
			} else {
				logError("You must enroll a new cert first");
			}
			p12 = null;
		}
	}
	
	private String convertX509CertToPEM(X509Certificate cert) 
			throws CertificateEncodingException, IOException {
		StringBuilder lCert = new StringBuilder();
		byte[] encodedCert = cert.getEncoded();
		byte[] pem = Base64.encode(encodedCert);
		if (pem == null) return null;
		String pemstr = new String(pem, Charset.forName("US-ASCII"));
		lCert.append("-----BEGIN CERTIFICATE-----");
		lCert.append(System.getProperty("line.separator"));
		lCert.append(pemstr);
		lCert.append(System.getProperty("line.separator"));
		lCert.append("-----END CERTIFICATE-----");
		lCert.append(System.getProperty("line.separator"));	
		return (lCert.toString());
	}

	/*
	 * This method retrieves the trusted certs from the Android system
	 */
	private byte[] getTA() {
		StringBuilder lCerts = new StringBuilder();
		TrustManagerFactory tmf;
		X509TrustManager xtm;
		
		try {
			tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init((KeyStore) null);
			xtm = (X509TrustManager) tmf.getTrustManagers()[0];
			for (X509Certificate cert : xtm.getAcceptedIssuers()) {
				String x = convertX509CertToPEM(cert);
				if (x != null)
					lCerts.append(x);					
			}
			lCerts.append(0);
			lCerts.append(0); 
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			logError("An error occured: " + e.getMessage());
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			logError("An error occured: " + e.getMessage());
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			logError("An error occured: " + e.getMessage());
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			logError("An error occured: " + e.getMessage());
			e.printStackTrace();
		}
		
		return lCerts.toString().getBytes(Charset.forName("US-ASCII"));
	}
	
	private void clearLogCat() {
		Process p = null;
		try {
			p = Runtime.getRuntime().exec("logcat -c");
		}
		catch (IOException e) {
			txtLog.append(e.getMessage());
		}
		finally {
			if (p != null) p.destroy();
		}
		txtLog.setText("");
	}
	

	private void logError(String err) {
		Toast t;
		t = Toast.makeText(this, err, Toast.LENGTH_SHORT);
		t.show();
	}

	public static byte[] doEnroll(String commonName, 
			String UID,
			String PWD, 
			String serverName,
			int serverPort, 
			byte[] cacert) {
		byte[] p12;
		
		p12 = enrollCert(commonName, UID, PWD, serverName, serverPort, cacert);
		return p12;
	}
	private native void nativePipeSTDERRToLogcat();
	private static native byte[] enrollCert(String commonName, 
			String UID,
			String PWD, 
			String serverName,
			int serverPort, 
			byte[] cacert);
}
