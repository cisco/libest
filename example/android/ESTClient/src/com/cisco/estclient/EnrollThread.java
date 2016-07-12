package com.cisco.estclient;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import android.os.Bundle;
import android.os.Handler;
import android.os.Message;

public class EnrollThread extends Thread {
	private Handler hnd;
	private String CN;
	private String UID;
	private String PWD;
	private String Server;
	private Integer Port;
	private byte[] CACerts;
	
	public EnrollThread (String cn, String uid, String pwd, String server, Integer port, byte []cacerts, Handler h) {
		hnd = h;
		CN = cn;
		UID = uid;
		PWD = pwd;
		Server = server;
		Port = port;
		CACerts = cacerts;
	}
	
	static {
		System.loadLibrary("estwrap"); 
	}
	
	public void run () {
		byte[] p12 = null;
		
		p12 = ESTActivity.doEnroll(CN, UID, PWD, Server, Port, CACerts); 
		notifyCaller(p12);
		return;
	}
	
	private void notifyCaller (byte [] data) {
		Bundle b = new Bundle();
		Message m = hnd.obtainMessage();
		
		b.putByteArray("Detail", data);
		m.setData(b);
		hnd.sendMessage(m);
		//android.util.Log.v("DGTHREAD", "parent notified");
	}
	

}
