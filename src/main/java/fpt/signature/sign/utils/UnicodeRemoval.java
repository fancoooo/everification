package fpt.signature.sign.utils;

import java.util.Arrays;

public class UnicodeRemoval {
    private static char[] SPECIAL_CHARACTERS;

    static {
        SPECIAL_CHARACTERS = new char[]{
                ' ', '!', '"', '#', '$', '%', '*', '+', ',', ':',
                '<', '=', '>', '?', '@', '[', '\\', ']', '^', '`',
                '|', '~'};
    }

    private static char[] REPLACEMENTS = new char[] {
            ' ', '!', '"', '#', '$', '%', '*', '+', ',', ':',
            '<', '=', '>', '?', '@', '[', '\\', ']', '^', '`',
            '|', '~', 'A', 'A', 'A', 'A', 'E', 'E', 'E', 'I',
            'I', 'O', 'O', 'O', 'O', 'U', 'U', 'Y', 'a', 'a',
            'a', 'a', 'e', 'e', 'e', 'i', 'i', 'o', 'o', 'o',
            'o', 'u', 'u', 'y', 'A', 'a', 'D', 'd', 'I', 'i',
            'U', 'u', 'O', 'o', 'U', 'u', 'A', 'a', 'A', 'a',
            'A', 'a', 'A', 'a', 'A', 'a', 'A', 'a', 'A', 'a',
            'A', 'a', 'A', 'a', 'A', 'a', 'A', 'a', 'A', 'a',
            'E', 'e', 'E', 'e', 'E', 'e', 'E', 'e', 'E', 'e',
            'E', 'e', 'E', 'e', 'E', 'e', 'I', 'i', 'I', 'i',
            'O', 'o', 'O', 'o', 'O', 'o', 'O', 'o', 'O', 'o',
            'O', 'o', 'O', 'o', 'O', 'o', 'O', 'o', 'O', 'o',
            'O', 'o', 'O', 'o', 'U', 'u', 'U', 'u', 'U', 'u',
            'U', 'u', 'U', 'u', 'U', 'u', 'U', 'u' };

    private static char removeAccent(char ch) {
        int index = Arrays.binarySearch(SPECIAL_CHARACTERS, ch);
        if (index >= 0)
            ch = REPLACEMENTS[index];
        return ch;
    }

    public static String removeAccent(String s) {
        StringBuilder sb = new StringBuilder(s);
        for (int i = 0; i < sb.length(); i++)
            sb.setCharAt(i, removeAccent(sb.charAt(i)));
        return sb.toString();
    }
}

