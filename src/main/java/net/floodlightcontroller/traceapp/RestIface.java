package net.floodlightcontroller.traceapp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;

public class RestIface {
	private static String baseurl = "http://0.0.0.0:8080/wm/";
	
	public static String HttpGet(String suburl) throws ClientProtocolException, IOException{
		HttpClient client = new DefaultHttpClient();
		System.out.println(baseurl.concat(suburl));
		
		HttpGet request = new HttpGet(baseurl.concat(suburl));
		HttpResponse response = client.execute(request);
		
		BufferedReader rd = new BufferedReader( new InputStreamReader(response.getEntity().getContent()));
		String res = "";
		String line = "";
		while((line = rd.readLine()) != null){
			res = res.concat(line);
		}
		return res;
	}
}
