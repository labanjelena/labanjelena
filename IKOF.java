import java.io.FileInputStream;
import java.security.*;

import javax.xml.bind.DatatypeConverter;

public class SampleGenerateIIC {

    private static final String KEYSTORE_LOCATION = "***.p12"; // putanja do vaseg sertifikata na hard disku
    private static final String KEYSTORE_TYPE = "PKCS12"; // tip sertifikata
    private static final String KEYSTORE_PASS = "***"; // lozinka za vaš sertifikat
    private static final String KEYSTORE_KEY_ALIAS = "***"; // alias za vaš sertifikat

    public static void main(String[] args) {

        String iicInput = "";

        // issuerTIN odnosno pib ili id firme ili pojedinca koji izdaje racun
        iicInput += "12345678";
        // dateTimeCreated odnosno vrijeme i datum kada je racun kreiran
        iicInput += "|2019-06-12T17:05:43+02:00";
        // invoiceNumber odnosno redni broj racuna
        iicInput += "|9952";
        // busiUnitCode odnosno kod poslovne jedinice
        iicInput += "|bb123bb123";
        // tcrCode odnosno kod kase/ENU
        iicInput += "|cc123cc123";
        // softCode odnosno kod softvera
        iicInput += "|ss123ss123";
        // totalPrice odnosno ukupna cijena za taj račun
        iicInput += "|99.01";

        try (FileInputStream fileInputStream = new FileInputStream(KEYSTORE_LOCATION)) { // pročitamo fajl sertifikata
                                                                                         // sa lokacije na HDD-u
            // Load a private from a key store
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE); // napravimo instancu KeyStore klase koja u JAVA
                                                                     // programskom jeziku služi za čuvanje ključeva i
                                                                     // sertifikata
            keyStore.load(fileInputStream, KEYSTORE_PASS.toCharArray()); // u ovu klasu učitamo Input stream fajla
                                                                         // sertifikata
            Key privateKey = keyStore.getKey(KEYSTORE_KEY_ALIAS, KEYSTORE_PASS.toCharArray()); // iz klase keyStore
                                                                                               // izvučemo privatni
                                                                                               // ključ na osnovu aliasa
                                                                                               // i lozinke

            // Create IIC signature according to RSASSA-PKCS-v1_5
            Signature signature = Signature.getInstance("SHA256withRSA"); // uzimamo instancu potpisa koji je propisan
                                                                          // specifikacijom
            signature.initSign((PrivateKey) privateKey); // inicijalizujemo potpis na osnovu privatnog ključa izvučenog
                                                         // iz sertifikata
            signature.update(iicInput.getBytes());// unutar potpisa ubacujemo nas IIC string kao niz bajtova
            byte[] iicSignature = signature.sign(); // kreiramo novi niz bajtova koji će se stvoriti nakon sto
                                                    // potpišeniemo naš string
            String iicSignatureString = DatatypeConverter.printHexBinary(iicSignature).toUpperCase(); // prebacujemo naš
                                                                                                      // niz bajtova u
                                                                                                      // heksadecimalni
                                                                                                      // zapis sa svim
                                                                                                      // velikim slovima
            System.out.println("The IIC signature is: " + iicSignatureString); // vraćamo IICSignature varijablu koja se
                                                                               // koristu unutar poruke računa

            // Hash IIC signature with MD5 to create IIC
            MessageDigest md = MessageDigest.getInstance("MD5"); // pravimo instancu heš metode
            byte[] iic = md.digest(iicSignature); // prema specifikaciji ove metode ona ce nam napraviti novi skraćeni
                                                  // niz potpisa koji se ne može vratiti u prvobitni oblik
            String iicString = DatatypeConverter.printHexBinary(iic).toUpperCase(); // pretvaramo iic bajtove u
                                                                                    // heksadecimalni zapis velikim
                                                                                    // slovima koji će imati 32 znaka po
                                                                                    // MD5 specifikaciji
            System.out.println("The IIC is: " + iicString); // vraćamo IIC varijablu koja se koristu unutar poruke
                                                            // računa
        } catch (Exception e) {
            e.printStackTrace();// u slučaju da dodje do bilo koje greške mi vraćamo stack trace greške
        }
    }
}