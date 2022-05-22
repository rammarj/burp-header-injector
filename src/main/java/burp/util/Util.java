/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp.util;

import java.util.SplittableRandom;

/**
 *
 * @author Joaquin R. Martinez
 */
public class Util {
    /**
     * Generates randomStr random string (for Multipart requests)
     * @param lenght the char number of the random string
     * @return the random string
     */
    public static String generateRandomString(int lenght) {
        SplittableRandom splittableRandom = new SplittableRandom();
        StringBuffer randomStr = new StringBuffer();
        int randInt, temp;
        for (int i = 0; i < lenght; i++) {
            randInt = splittableRandom.nextInt(0, 2);
            if (randInt == 1) {
                temp = splittableRandom.nextInt('A', 'Z');
            } else {
                temp = splittableRandom.nextInt('a', 'z');
            }
            randomStr.append((char) temp);
        }
        return randomStr.toString();
    }
    
    public static String[] getScriptMimes(){
        return new String[]{"script","JSON","CSS"};
    }
    
}
