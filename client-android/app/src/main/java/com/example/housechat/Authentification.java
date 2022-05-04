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
import android.widget.ProgressBar;
import android.widget.Spinner;

public class Authentification extends AppCompatActivity {
    ImageView leftIcon;
    Button login;
    Spinner loginId;
    EditText loginPassword;

    boolean passwordVisible;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_authentification);

        leftIcon =findViewById(R.id.left_icon);
        login=findViewById(R.id.btnLogin);
        loginId=findViewById(R.id.loginId);
        loginPassword=findViewById(R.id.loginPassword);


        leftIcon.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivity(new Intent(Authentification.this, CreateAccount.class));
            }
        });
        login.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivity(new Intent(Authentification.this, ChatActivity.class));
            }
        });

        loginPassword.setOnTouchListener(new View.OnTouchListener() {
            @Override
            public boolean onTouch(View view, MotionEvent event) {
                final int Right=2;
                if(event.getAction()== MotionEvent.ACTION_UP){
                    if(event.getRawX()>=loginPassword.getRight()- loginPassword.getCompoundDrawables()[Right].getBounds().width()){

                        int selection=loginPassword.getSelectionEnd();

                        if (passwordVisible){
                            //set drawable image here
                            loginPassword.setCompoundDrawablesRelativeWithIntrinsicBounds(0,0,R.drawable.ic_baseline_visibility_off_24,0);
                            //for hide password
                            loginPassword.setTransformationMethod(PasswordTransformationMethod.getInstance());
                            passwordVisible=false;
                        }else{
                            //set drawable image here
                            loginPassword.setCompoundDrawablesRelativeWithIntrinsicBounds(0,0,R.drawable.ic_baseline_visibility_24,0);
                            //for show password
                            loginPassword.setTransformationMethod(HideReturnsTransformationMethod.getInstance());
                            passwordVisible=true;

                        }
                        loginPassword.setSelection(selection);
                        return  true;
                    }
                }
                return false;
            }
        });


    }
}