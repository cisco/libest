package com.cisco.estclient;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InputStream;

import android.os.Bundle;
import android.os.Handler;
import android.os.Message;

public class LoggerThread  extends Thread {
	private Handler hnd;	
	
	public LoggerThread (Handler h) {
		hnd = h;
	}
	
	public void run () {
		Process p = null;
		try {
			p = Runtime.getRuntime().exec("logcat");
			InputStream in = p.getInputStream();
			BufferedReader br = new BufferedReader(new InputStreamReader(in));
			String line;
			while ((line = br.readLine()) != null) {
				notifyCaller(line);
			}
		}
		catch (IOException e) {
			notifyCaller(e.getMessage());
		}
		finally {
			if (p != null) p.destroy();
		}		
		return;
	}
	
	private void notifyCaller (String detail) {
		Bundle b = new Bundle();
		Message m = hnd.obtainMessage();
		
		b.putString("Detail", detail);
		m.setData(b);
		hnd.sendMessage(m);
		//android.util.Log.v("DGTHREAD", "parent notified");
	}
}
