package com.d2sec.vulnapp;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.webkit.WebView;
import android.webkit.WebSettings;

public class D2App extends Activity
{
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
    }

    public void onClickLoadUrl(View view)
    {
        WebView myWebView = (WebView) findViewById(R.id.webview);
        myWebView.clearCache(true); // Prevent Android to cache the page (force request)

        WebSettings webSettings = myWebView.getSettings();
        webSettings.setJavaScriptEnabled(true);

        myWebView.addJavascriptInterface(new WebAppInterface(this), "jsinterface");
        myWebView.loadUrl("http://10.0.2.2:8000");
    }

    public void onClickReset(View view)
    {
        WebView myWebView = (WebView) findViewById(R.id.webview);
        myWebView.loadUrl("about:blank");
    }

}
