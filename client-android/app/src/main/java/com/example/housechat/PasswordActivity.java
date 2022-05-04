package com.example.housechat;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.view.MotionEvent;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.Spinner;

public class PasswordActivity extends AppCompatActivity {
    Button btnChange;
    EditText oldPassword;
    EditText changePassword;
    boolean passwordVisible;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_password);


        oldPassword=findViewById(R.id.oldPassword);
        changePassword=findViewById(R.id.newPassword);
        btnChange=findViewById(R.id.btnChange);


        btnChange.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivity(new Intent(PasswordActivity.this, ChatActivity.class));
            }
        });

        oldPassword.setOnTouchListener(new View.OnTouchListener() {
            @Override
            public boolean onTouch(View view, MotionEvent event) {
                final int Right=2;
                if(event.getAction()== MotionEvent.ACTION_UP){
                    if(event.getRawX()>=oldPassword.getRight()- oldPassword.getCompoundDrawables()[Right].getBounds().width()){

                        int selection=oldPassword.getSelectionEnd();

                        if (passwordVisible){
                            //set drawable image here
                            oldPassword.setCompoundDrawablesRelativeWithIntrinsicBounds(0,0,R.drawable.ic_baseline_visibility_off_24,0);
                            //for hide password
                            oldPassword.setTransformationMethod(PasswordTransformationMethod.getInstance());
                            passwordVisible=false;
                        }else{
                            //set drawable image here
                            oldPassword.setCompoundDrawablesRelativeWithIntrinsicBounds(0,0,R.drawable.ic_baseline_visibility_24,0);
                            //for show password
                            oldPassword.setTransformationMethod(HideReturnsTransformationMethod.getInstance());
                            passwordVisible=true;

                        }
                        oldPassword.setSelection(selection);
                        return  true;
                    }
                }
                return false;
            }
        });

        changePassword.setOnTouchListener(new View.OnTouchListener() {
            @Override
            public boolean onTouch(View view, MotionEvent event) {
                final int Right=2;
                if(event.getAction()== MotionEvent.ACTION_UP){
                    if(event.getRawX()>=changePassword.getRight()- changePassword.getCompoundDrawables()[Right].getBounds().width()){

                        int selection=changePassword.getSelectionEnd();

                        if (passwordVisible){
                            //set drawable image here
                            changePassword.setCompoundDrawablesRelativeWithIntrinsicBounds(0,0,R.drawable.ic_baseline_visibility_off_24,0);
                            //for hide password
                            changePassword.setTransformationMethod(PasswordTransformationMethod.getInstance());
                            passwordVisible=false;
                        }else{
                            //set drawable image here
                            changePassword.setCompoundDrawablesRelativeWithIntrinsicBounds(0,0,R.drawable.ic_baseline_visibility_24,0);
                            //for show password
                            changePassword.setTransformationMethod(HideReturnsTransformationMethod.getInstance());
                            passwordVisible=true;

                        }
                        changePassword.setSelection(selection);
                        return  true;
                    }
                }
                return false;
            }
        });

    }
}