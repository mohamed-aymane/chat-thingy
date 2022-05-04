package com.example.housechat;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.content.ContextCompat;
import androidx.viewpager.widget.ViewPager;

import android.content.Intent;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.widget.Toast;

import com.google.android.material.tabs.TabItem;
import com.google.android.material.tabs.TabLayout;

public class ChatActivity extends AppCompatActivity {

    TabLayout tabLayout;
    TabItem mchat,mservers,mcalls;
    ViewPager viewPager;
    PagerAdapter pagerAdapter;
    androidx.appcompat.widget.Toolbar mtoolbar;



    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_chat);


        tabLayout=findViewById(R.id.tabLayout);

        mchat=findViewById(R.id.chat);
        mservers=findViewById(R.id.servers);
        mcalls=findViewById(R.id.calls);


        viewPager=findViewById(R.id.viewPager);
        mtoolbar=findViewById(R.id.toolbar);

        setSupportActionBar(mtoolbar);



        //when user swipe to right or left
        pagerAdapter= new PagerAdapter(getSupportFragmentManager(),tabLayout.getTabCount());
        //like someone click on serves he should move  to it directly
        viewPager.setAdapter(pagerAdapter);

        //if someone click on tab selected he should to move
        tabLayout.setOnTabSelectedListener(new TabLayout.OnTabSelectedListener() {
            @Override
            public void onTabSelected(TabLayout.Tab tab) {
                viewPager.setCurrentItem(tab.getPosition());

                if(tab.getPosition()==0||tab.getPosition()==1||tab.getPosition()==2){
                    pagerAdapter.notifyDataSetChanged();
                }

            }

            @Override
            public void onTabUnselected(TabLayout.Tab tab) {

            }

            @Override
            public void onTabReselected(TabLayout.Tab tab) {

            }
        });

        viewPager.addOnPageChangeListener(new TabLayout.TabLayoutOnPageChangeListener(tabLayout));


        //we should right a call
        Drawable drawable= ContextCompat.getDrawable(getApplicationContext(),R.drawable.ic_baseline_more_vert_24);
        //set the icon to the toolbar
        mtoolbar.setOverflowIcon(drawable);

    }
    //show icon for menu
    @Override
    public boolean onCreateOptionsMenu(Menu menu) {

        MenuInflater menuInflater=getMenuInflater();
        menuInflater.inflate(R.menu.menu,menu);
        return true;
    }

    //select item in menu and get what we want
    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {

        switch (item.getItemId()){

            case R.id.profile:
                Intent intent=new Intent(ChatActivity.this,ProfileActivity.class);
                startActivity(intent);
                break;
            case R.id.out:
                Intent intent1=new Intent(ChatActivity.this,Authentification.class);
                startActivity(intent1);
                break;
            case R.id.settings:
                Intent intent2=new Intent(ChatActivity.this,PasswordActivity.class);
                startActivity(intent2);
                break;
            case R.id.about:
                Intent intent3=new Intent(ChatActivity.this,AboutUs.class);
                startActivity(intent3);
                break;

        }
        return true;
    }


}