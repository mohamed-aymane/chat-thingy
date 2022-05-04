package com.example.housechat;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentPagerAdapter;
/**
 * this class is used to manage all java class*/
public class PagerAdapter extends FragmentPagerAdapter {
   int tabcount;

   public PagerAdapter(@NonNull FragmentManager fm, int behavior){
    super(fm, behavior);
    tabcount=behavior;
   }

    @NonNull
    @Override
    public Fragment getItem(int position) {

       switch (position){
           case 0:
               return new ChatFragment();
           case 1:
               return new ServersFragment();
           case 2:
               return  new CallsFragment();

           default:
               return null;



       }


    }

    @Override
    public int getCount() {
        return 0;
    }
}
