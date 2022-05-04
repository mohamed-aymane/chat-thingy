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

public class CreateAccount extends AppCompatActivity {
    ImageView leftIcon;

    Button create;
    EditText createId;
    EditText createPassword;
    boolean passwordVisible;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_create_accouant);
        leftIcon =findViewById(R.id.left_icon);
        create=findViewById(R.id.btnCreate);
        createId=findViewById(R.id.createId);
        createPassword=findViewById(R.id.createPassword);

        leftIcon.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivity(new Intent(CreateAccount.this,Authentification.class));
            }
        });
        create.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivity(new Intent(CreateAccount.this,Authentification.class));
            }
        });
        createId.setOnTouchListener(new View.OnTouchListener() {
            @Override
            public boolean onTouch(View view, MotionEvent motionEvent) {
                return false;
            }
        });

        createPassword.setOnTouchListener(new View.OnTouchListener() {
            @Override
            public boolean onTouch(View view, MotionEvent event) {
                final int Right=2;
                if(event.getAction()== MotionEvent.ACTION_UP){
                    if(event.getRawX()>=createPassword.getRight()- createPassword.getCompoundDrawables()[Right].getBounds().width()){

                        int selection=createPassword.getSelectionEnd();

                        if (passwordVisible){
                            //set drawable image here
                            createPassword.setCompoundDrawablesRelativeWithIntrinsicBounds(0,0,R.drawable.ic_baseline_visibility_off_24,0);
                            //for hide password
                            createPassword.setTransformationMethod(PasswordTransformationMethod.getInstance());
                            passwordVisible=false;
                        }else{
                            //set drawable image here
                            createPassword.setCompoundDrawablesRelativeWithIntrinsicBounds(0,0,R.drawable.ic_baseline_visibility_24,0);
                            //for show password
                            createPassword.setTransformationMethod(HideReturnsTransformationMethod.getInstance());
                            passwordVisible=true;

                        }
                        createPassword.setSelection(selection);
                        return  true;
                    }
                }
                return false;
            }
        });
    }

}