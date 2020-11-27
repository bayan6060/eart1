/*
Code for Creating data streams, anonymizing and uploading and downloading to server
 */
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import java.util.*;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;   // THis Base64 will be enabled for AES
import java.math.BigInteger;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;


import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//import org.apache.commons.codec.binary.Base64; // ENabled for DES

//import org.apache.commons.codec.binary.Base64;


public class DataTransfer {

    private String host;
    private Integer port;
    private String user;
    private String password;

    private JSch jsch;
    private Session session;
    private Channel channel;
    private ChannelSftp sftpChannel;

    private boolean find = false;
    private int Low = 0;
    private int High = 9;
    private int max_length = 127;
    private int delta = 32;
    private int const_offset = 32;
    private int var_offset = 32;
    private String[] str_const = {"+!+", "", "+#+", "+$+", "+%+", "+&+", "+'+", "+yy+", "+zz+", "+*+", "+++", "+''+", "+ww+", "+.+", "+xx+"};

    //   private char[] constant_array = {'!', 't', '#', '$', '%', '&', '~', 'Y', 'Z', '*', '+', '|', '^', '.', 'X'};
    //   private String str_const = new String(constant_array);
    private static SecretKeySpec secretKey;
    private static byte[] key;

    static long MEGABYTE = 1024L * 1024L;

    static int global_pos = 1;
    int pos_offset = 10;

    public DataTransfer(String host, Integer port, String user, String password) {
        this.host = host;
        this.port = port;
        this.user = user;
        this.password = password;
    }

    public void connect() {

        System.out.println("connecting..." + host);
        try {
            jsch = new JSch();
            session = jsch.getSession(user, host, port);
            session.setConfig("StrictHostKeyChecking", "no");
            session.setPassword(password);
            session.connect();

            channel = session.openChannel("sftp");
            channel.connect();
            sftpChannel = (ChannelSftp) channel;

        } catch (JSchException e) {
            e.printStackTrace();
        }
    }

    public void disconnect() {
        System.out.println("disconnecting...");
        sftpChannel.disconnect();
        channel.disconnect();
        session.disconnect();
    }

    public ArrayList<String> parse_data(String filename) {
        ArrayList<String> result = new ArrayList<>();

        try {
            Scanner s = new Scanner(new File(filename));

            while (s.hasNext()) {
                result.add(s.next());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public long pseudorandom(int seed, Random r) {
        // setting seed 
        //  long s = 24; 
       // byte [] bytes = new byte[16]; // 128 bits are converted to 16 bytes;
       // r.nextBytes(bytes);
        r.setSeed(seed);
        
        
        //return Math.abs(bytes[i]);
        
       return Math.abs(r.nextLong());
        


    }

    public void upload(String listString, String remoteDir) {

        //FileInputStream fis = null;
        InputStream stream = new ByteArrayInputStream(listString.getBytes(StandardCharsets.UTF_8));
        connect();
        try {
            // Change to output directory
            sftpChannel.cd(remoteDir);
            // Upload file
            sftpChannel.put(stream, "2224_hash.txt");

            stream.close();
            System.out.println("File uploaded successfully - ");

        } catch (Exception e) {
            e.printStackTrace();
        }
        disconnect();
    }

    public void upload_data_art(String localPath, String remotePath) {
        try {
            File myfile = new File(localPath);
            //    String str = FileUtils.readFileToString(myfile, StandardCharsets.UTF_8.name());
            String str = FileUtils.readFileToString(myfile, StandardCharsets.UTF_8);

            Random r = new Random();
            long pseudo = 0;
                        String[] string_array = str.split("");


            long beforeUsedMem = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();

            //    System.out.println(str);

           //try (FileWriter file = new FileWriter("C:/test/hello.pi")) {
            
            for (int i = 0; i < string_array.length ; i++) {
                pseudo = pseudorandom(i, r);
                
               //System.out.println(Long.toBinaryString(pseudo));
               //file.write(Long.toBinaryString(pseudo));
               // file.write("\r\n");

                string_array[i] = replaceCharAt(string_array[i], pseudo);
            }
                      // file.close();
           //}
              //catch (Exception e) {
            //e.printStackTrace();
        //}

            long afterUsedMem = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
            long actualMemUsed = afterUsedMem - beforeUsedMem;
            System.out.println(actualMemUsed / MEGABYTE);

            FileUtils.writeStringToFile(new File("C:/test/sample2000.txt"), convertArrayToStringMethod(string_array), "UTF-8");
            // upload(convertArrayToStringMethod(string_array), remotePath);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String replaceCharAt(String value, Long index) {

        int org_value = value.charAt(0);

        int reflected_value = (max_length - org_value) + 1;
        //     int lap_off = laplacian_offset() ;

        int lap_off = (int) (index % pos_offset);

        String str = "";
        StringBuilder sb = new StringBuilder();

        if ((reflected_value + var_offset + const_offset) > max_length) {

            if (((reflected_value + var_offset + const_offset) % max_length) < 32) {
                reflected_value = ((reflected_value + var_offset + const_offset) % max_length) + delta + lap_off;
                if (reflected_value >= 33 && reflected_value <= 47) {
                    str = str_const[reflected_value - delta - 1];
                } else {
                    str = sb.append((char) (reflected_value)).toString();
                }
            } else {
                reflected_value = ((reflected_value + var_offset + const_offset) % max_length) + lap_off;
                str = sb.append((char) (reflected_value)).toString();
            }
        } else {
            reflected_value = reflected_value + var_offset + const_offset + lap_off;
            str = sb.append((char) (reflected_value)).toString();
        }
        return str;
    }

    public static String convertArrayToStringMethod(String[] strArray) {

        StringBuilder stringBuilder = new StringBuilder();

        for (int i = 0; i < strArray.length; i++) {

            stringBuilder.append(strArray[i]);
            stringBuilder.append(",");
        }

        return stringBuilder.toString();
    }

    //  return s.substring(0, pos) + (char) (reflected_value + laplacian_offset()) + s.substring(pos + 1);
    //   return s.substring(0, pos) + (char) (reflected_value ) + s.substring(pos + 1);
    private int laplacian_offset() {

        global_pos++;
        return global_pos % pos_offset;
    }

    public void download_art(String fileName, String localDir) {

        global_pos = 1;
        //  byte[] buffer = new byte[1024];
        //  Buffere\InputStream bis;
//        String strFileContents;
        // connect();
        try {
            // Change to output directory
            //  String cdDir = fileName.substring(0, fileName.lastIndexOf("/") + 1);
            //  sftpChannel.cd(cdDir);

            // File file = new File(fileName);
            Random r = new Random();
            long pseudo = 0;

           String str = FileUtils.readFileToString(new File("C:/test/sample_art600.txt"), StandardCharsets.UTF_8.name());
           // String str = FileUtils.readFileToString(new File(fileName), StandardCharsets.UTF_8.name());
            //  bis = new BufferedInputStream(sftpChannel.get(file.getName()));
            //  String str = IOUtils.toString(bis, "UTF-8");
            //System.out.println(str);            
            //      System.out.println(str);

            StringBuilder stringBuilder = new StringBuilder();
            String[] string_array = str.split(",");
            long beforeUsedMem = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();

            for (int i = 0; i < string_array.length; i++) {
                pseudo = pseudorandom(i, r);
                stringBuilder.append(deidentify(string_array[i], pseudo));
            }

            String str_converted = stringBuilder.toString();

            str_converted = str_converted.replace("@", " ");
            str_converted = str_converted.replace("*", " ");

            //System.out.println(str_converted);
             long afterUsedMem = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
            long actualMemUsed = afterUsedMem - beforeUsedMem;
            System.out.println(actualMemUsed / MEGABYTE);
            FileUtils.writeStringToFile(new File("C:/test/sample_art600out.txt"), str_converted, "UTF-8");

            //    FileUtils.writeStringToFile(new File(localDir + "/" + file.getName()), str_converted, "UTF-8");
            //   bis.close();
            //   System.out.println("File downloaded successfully - " + file.getAbsolutePath());
        } catch (Exception e) {
            e.printStackTrace();
        }
        //  disconnect();
    }

    public char deidentify(String word, long index) {

        int int_value_anonymized = 0;
        char org_word = ' ';
        //      int lap_off = laplacian_offset() ;
        int lap_off = (int) (index % pos_offset);

        if (word.length() > 1) {
            word = word.substring(1, word.length() - 1);

            //     word = word.replace("|||", "|+uu+|");
            //String temp_array[] = word.split("\\|");
            // if (temp_array[0] == "") {
            ///   temp_array[0] = "|";
            //}
            if (word.length() == 2) {

                if (word.equals("xx")) {
                    int_value_anonymized = 47 - delta - lap_off;
                    org_word = replaceChar(int_value_anonymized);
                } else if (word.equals("ww")) {
                    int_value_anonymized = 45 - delta - lap_off;
                    org_word = replaceChar(int_value_anonymized);
                } else if (word.equals("yy")) {
                    int_value_anonymized = 40 - delta - lap_off;
                    org_word = replaceChar(int_value_anonymized);
                } else if (word.equals("zz")) {
                    int_value_anonymized = 41 - delta - lap_off;
                    org_word = replaceChar(int_value_anonymized);
                } else if (word.equals("''")) {
                    int_value_anonymized = 44 - delta - lap_off;
                    org_word = replaceChar(int_value_anonymized);
                } else if (word.equals("uu")) {
                    org_word = 'D';
                }
            } else {
                int_value_anonymized = (int) (word.charAt(0)) - delta - lap_off;
                org_word = replaceChar(int_value_anonymized);
            }

        } else if (word.length() > 0) {
            int_value_anonymized = (int) (word.charAt(0)) - lap_off;
            org_word = replaceChar(int_value_anonymized);
        }

        org_word = replaceChar(int_value_anonymized);
        return org_word;
    }

    private char replaceChar(int int_value_anonymized) {

        //  int offset = laplacian_offset();
        int quotient = 0;

        if ((int_value_anonymized - (const_offset + var_offset)) <= 0) {
            quotient = 1;
        } else {
            quotient = 0;
        }

        int_value_anonymized = (max_length * quotient + int_value_anonymized) - const_offset - var_offset;
        int org_value = (max_length - int_value_anonymized) + 1;

        if (org_value == 44) {
            org_value = org_value + 14;
        }

        if (org_value >= 0 && org_value <= 32) {
            org_value = org_value + delta;
        }

        return (char) (org_value);
    }

    public static void setKey(String myKey) {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String strToEncrypt, String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
          //return null;
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String decrypt(String strToDecrypt, String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            //return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
           return null;
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public void decrypt_main(String remoteFilePath, String localPath, String secretKey) {

        //  byte[] buffer = new byte[1024];
        // BufferedInputStream bis;
        //  String strFileContents; 
        //  connect();
        try {
            // Change to output directory
            //      String cdDir = remoteFilePath.substring(0, remoteFilePath.lastIndexOf("/") + 1);
            //      sftpChannel.cd(cdDir);

            File file = new File(remoteFilePath);
            String str = FileUtils.readFileToString(file, StandardCharsets.UTF_8.name());

            //   bis = new BufferedInputStream(sftpChannel.get(file.getName()));
            //bis = new BufferedInputStream(file);
            //long startTime = System.currentTimeMillis();  
            //   long beforeUsedMem = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
            //String encoded_data = IOUtils.toString(bis, "UTF-8");
            String decryptedString = decrypt(str, secretKey);

            FileUtils.writeStringToFile(new File("D:/test/sample_aes_dec.txt"), decryptedString, "UTF-8");
            /*long stopTime = System.currentTimeMillis();
        long elapsedTime = stopTime - startTime;
        System.out.println(elapsedTime);
        long afterUsedMem = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        long actualMemUsed = afterUsedMem - beforeUsedMem;
        System.out.println(actualMemUsed);
             */
            //   bis.close();
            //  bos.close();
            //   System.out.println("File downloaded successfully - " + file.getAbsolutePath());

        } catch (Exception e) {
            e.printStackTrace();
        }
        // disconnect();
    }

    public void encrypt_main(String localPath, String remotePath, String secretKey) {
        try {

            File myfile = new File(localPath);
            String str = FileUtils.readFileToString(myfile, StandardCharsets.UTF_8.name());
            String encryptedString = encrypt(str, secretKey);
            //System.out.println(encryptedString);
            FileUtils.writeStringToFile(new File("C:/test//size//sample_aes_enc2000.txt"), encryptedString, "UTF-8");

            //  upload(encryptedString, remotePath);
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }

    private String getMd5(String input) {
        try {

            // Static getInstance method is called with hashing MD5 
            MessageDigest md = MessageDigest.getInstance("MD5");

            // digest() method is called to calculate message digest 
            //  of an input digest() return array of byte 
            byte[] messageDigest = md.digest(input.getBytes());

            // Convert byte array into signum representation 
            BigInteger no = new BigInteger(1, messageDigest);

            // Convert message digest into hex value 
            String hashtext = no.toString(16);
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        } // For specifying wrong message digest algorithms 
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public void hashall_main(String localPath, String remotePath) {

        ArrayList<String> strList = parse_data(localPath);
        String listString = "";

        for (int i = 0; i < strList.size(); i++) {
            if (strList.get(i).isEmpty() == false) {
                listString += getMd5(strList.get(i)) + " ";
            }
        }
        System.out.println(listString);
        upload(listString, remotePath);
    }
    
    
    
    public String encrypt_des( String message, String SECRET_KEY) {
		try
                {
        final MessageDigest md = MessageDigest.getInstance("md5");
		final byte[] digestOfPassword = md.digest(SECRET_KEY.getBytes());
		final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);

		for (int j = 0, k = 16; j < 8;) {
			keyBytes[k++] = keyBytes[j++];
		}

		final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
		final IvParameterSpec iv = new IvParameterSpec(new byte[8]);

		final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);

		final byte[] plainTextBytes = message.getBytes();
		final byte[] cipherText = cipher.doFinal(plainTextBytes);
                return new String(Base64.encodeBase64(cipherText));

                }
                 catch (Exception ex) {
            System.out.print(ex);
        }
                
                return null;
                
	}

	public  String decrypt_des( String message, String SECRET_KEY) {
            try{
		final MessageDigest md = MessageDigest.getInstance("md5");
		final byte[] digestOfPassword = md.digest(SECRET_KEY.getBytes());
		final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);

		for (int j = 0, k = 16; j < 8;) {
			keyBytes[k++] = keyBytes[j++];
		}

		final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
		final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
		final Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
		decipher.init(Cipher.DECRYPT_MODE, key, iv);
		final byte[] plainText = decipher.doFinal(Base64.decodeBase64(message.getBytes()));
                		return new String(plainText, "UTF-8");

            }
            catch (Exception ex) {
            System.out.print(ex);
        }
            return null;
	}
        
    public static void main(String[] args) {

        String server = "162.144.57.226";
        int port = 22;
        String user = "nadeem";
        String pass = "bayan@123";
        String localPath = "C:/test/";
        String remotePath = "/home/nadeem/public_html/experiments/";

        final String secretKey = "abc";

        // "abc", "abb 1", "abo 2 " "abn 3"
        long startTime = System.currentTimeMillis();
        DataTransfer ftp = new DataTransfer(server, port, user, pass);
        long beforeUsedMem = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();

        /*
        try{
          File myfile = new File("D:/test//sample.txt");
          String str = FileUtils.readFileToString(myfile, StandardCharsets.UTF_8.name());
         String encrypted_des = ftp.encrypt_des(str, secretKey);
        System.out.println(encrypted_des );
            FileUtils.writeStringToFile(new File("D:/test//sample_des_enc.txt"), encrypted_des, "UTF-8");     
            
      //       File myfile = new File("D:/test//sample_des_enc.txt");
       //   String str = FileUtils.readFileToString(myfile, StandardCharsets.UTF_8.name());
      // String decrypted_des = ftp.decrypt_des(str, secretKey);
      //  System.out.print(decrypted_des);
          
        }
             catch (Exception ex) {
            System.out.print(ex);
        }
        */
         //ftp.upload_data_art(localPath + "sample_2000.txt", remotePath);
        ftp.download_art(localPath + "sample_art600.txt", localPath);
        //ftp.encrypt_main(localPath + "sample_2000.txt", remotePath, secretKey);
        System.out.println("------------------------------------------------");
//        ftp.download_art(remotePath + "2224_3.txt", localPath);

        // ftp.encrypt_main(localPath + "sample.txt", remotePath, secretKey);
        //ftp.decrypt_main(localPath + "sample_aes_enc.txt", localPath, secretKey);
        //  ftp.hashall_main(localPath + "sample.txt", remotePath);

        /*
        ftp.encrypt_main(localPath + "sample.txt", remotePath, secretKey);
        ftp.hashall_main(localPath + "sample.txt", remotePath);
        ftp.decrypt_main(remotePath + "2224.txt", localPath, secretKey);
        ftp.download_art(remotePath + "2224_3.txt", localPath);
         */
        long stopTime = System.currentTimeMillis();
        long elapsedTime = stopTime - startTime;
        System.out.println(" ");
        System.out.println("Time in milliseconds:--- " + elapsedTime);
        long afterUsedMem = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        long actualMemUsed = afterUsedMem - beforeUsedMem;
        System.out.println("Memory consumed in Mega Bytes: --- " + actualMemUsed / MEGABYTE);
    }

}
