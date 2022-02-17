package com.d2sec.vulnapp;

import android.content.Context;
import android.widget.Toast;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;

public class WebAppInterface
{
    Context context_;

    WebAppInterface(Context context)
    {
        context_ = context;
    }

    //@JavascriptInterface // New SDK ?!
    public void showToast(String filename)
    {
        Toast.makeText(context_, filename, Toast.LENGTH_SHORT).show();
    }
}
