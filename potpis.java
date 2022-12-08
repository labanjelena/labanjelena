import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.*;
import org.xml.sax.InputSource;

/*
    Primjer poruke za registraciju računa:
         "<RegisterInvoiceRequest xmlns=\"https://efi.tax.gov.me/fs/schema\" xmlns:ns2=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"Request\" Version=\"1\">\r\n " +
                    "<Header SendDateTime=\"${now}\" UUID=\"${uuid}\"/>\r\n " +
                    "<Invoice TypeOfInv=\"${kes}\" BusinUnitCode=\"td304bn181\" IssueDateTime=\"${now}\" PayDeadline=\"${dueDateValue}\" IIC=\"${iic}\" IICSignature=\"${iics}\" InvNum=\"${invNumString}\" InvOrdNum=\"${invoiceNumberVal}\" IsIssuerInVAT=\"true\" IsReverseCharge=\"false\" IsSimplifiedInv=\"false\" OperatorCode=\"lr107cp202\" SoftCode=\"fg257dg974\"  TotPrice=\"${totalAll}\" TotPriceWoVAT=\"${totalNoVat}\" TotVATAmt=\"${totalVat}\" >\r\n " +
                    "<PayMethods>\r\n " +
                    "<PayMethod Amt=\"${totalAll}\" Type=\"FACTORING\"/>\r\n " +
                    "</PayMethods>\r\n " +
                    "<Seller Address=\"Bar bb\" Country=\"MNE\" IDNum=\"${pibValue}\" IDType=\"TIN\" Name=\"Visol\" Town=\"Bar\"/>\r\n " +
                    "<Items>\r\n " +
                    "${medjurezultat}\r\n " + //"<I C=\"${codeOFItem}\" N=\"${NameOfItem}\" PA=\"${totalValue}\" PB=\"${priceBeforeVatValue}\" Q=\"${quantityValue}\" R=\"${rabatValue}\" RR=\"${rabatReductionValue}\" U=\"${unitValue}\" UPB=\"${priceBeforeVatValueUnit}\" UPA=\"${totalValueUnit}\" VA=\"${vatValue}\" VR=\"${vatPercentValue}\"/>\n" ovaj tag je važno inicirati onoliko puta koliko ima različitih itema na računu
                    "</Items>\r\n " +
                    "<SameTaxes>\r\n " +
                    "${tax}\r\n " + // "<SameTax NumOfItems=\"${brojac}\" PriceBefVAT=\"${beforeVat}\" VATAmt=\"${amountOfVAT}\" VATRate=\"${stopa}\"/>" ovaj tag je važno ponoviti onoliko puta koliko imamo različitih itema po različitim stopama poreza
                    "</SameTaxes>\r\n " +
                    "</Invoice>\r\n " +
                    "</RegisterInvoiceRequest> "
*/
public class SampleGenerateSignature {

    private static final XMLSignatureFactory xmlSigFactory = XMLSignatureFactory.getInstance("DOM"); // instanca klase
                                                                                                     // XMLSignature
                                                                                                     // koja koristi za
                                                                                                     // potpisivanje xml
                                                                                                     // poruka i
                                                                                                     // mehanizmom DOM-a

    public static final String XML_SCHEMA_NS = "https://efi.tax.gov.me/fs/schema"; // šema na osnovu koje vršimo
                                                                                   // provjeru validnosti naše xml
                                                                                   // poruke
    public static final String XML_REQUEST_ELEMENT = "RegisterInvoiceRequest";// naziv elementa za koji vršimo
                                                                              // potpisivanje poruke u ovom slučaju je
                                                                              // to račun
    public static final String XML_REQUEST_ID = "Request"; // id dio xml poruke
    public static final String XML_SIG_METHOD = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"; // metod
                                                                                                     // potpisivanja
                                                                                                     // poruke

    private static final String REQUEST_TO_SIGN = // odavde do karaja ovog stringa na isti način kreirate sve poruke
                                                  // koje šaljete ka sistemu Poreske uprave
            "<RegisterInvoiceRequest " + // neophodno je staviti odgovarajući tag poruke zahtjeva koju želite
                                         // registrovati ili fiskalizovati
                    "       xmlns=\"https://efi.tax.gov.me/fs/schema\" " +
                    "       xmlns:ns2=\"http://www.w3.org/2000/09/xmldsig#\" " +
                    "       Id=\"Request\" " +
                    "       Version=\"3\">\r\n" +
                    "    <Header>...</Header>\r\n" +

                    "    <Invoice>...</Invoice>\r\n" +
                    "</RegisterInvoiceRequest>";

    private static final String KEYSTORE_LOCATION = "***.p12"; // putanja do vaseg sertifikata na hard disku
    private static final String KEYSTORE_TYPE = "PKCS12"; // tip sertifikata
    private static final String KEYSTORE_PASS = "***"; // lozinka za vaš sertifikat
    private static final String KEYSTORE_KEY_ALIAS = "***"; // alias za vaš sertifikat

    public static void main(String[] args) {

        try (FileInputStream fileInputStream = new FileInputStream(KEYSTORE_LOCATION)) {// pročitamo fajl sertifikata sa
                                                                                        // lokacije na HDD-u
            // Load a private from a key store
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);// napravimo instancu KeyStore klase koja u JAVA
                                                                    // programskom jeziku služi za čuvanje ključeva i
                                                                    // sertifikata
            keyStore.load(fileInputStream, KEYSTORE_PASS.toCharArray()); // u ovu klasu učitamo Input stream fajla
                                                                         // sertifikata
            Key privateKey = keyStore.getKey(KEYSTORE_KEY_ALIAS, KEYSTORE_PASS.toCharArray()); // iz klase keyStore
                                                                                               // izvučemo privatni
                                                                                               // ključ na osnovu aliasa
                                                                                               // i lozinke
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(KEYSTORE_KEY_ALIAS); // preko
                                                                                                         // keyStore
                                                                                                         // klase uzmemo
                                                                                                         // X509
                                                                                                         // sertifikat
                                                                                                         // iz fajla sa
                                                                                                         // sertifikatom
                                                                                                         // i privatnim
                                                                                                         // ključem

            // Load XML to DOC
            DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance(); // pravljenje instance klase
                                                                                      // DocumentBuilderFactory
            docFactory.setNamespaceAware(true);// omogućava da da parsirani string omogućava podršku za XML namespace
            DocumentBuilder docBuilder = docFactory.newDocumentBuilder(); // kreira instancu klase DocumentBuilder koja
                                                                          // omogućava čitanje XML poruke sa raznih
                                                                          // izvora (InputStream, Files, URLs, SAX
                                                                          // InputSources)
            Document doc = docBuilder.parse(new InputSource(new StringReader(REQUEST_TO_SIGN))); // dokument u klasi
                                                                                                 // Document nastao od
                                                                                                 // parsiranja ulaznog
                                                                                                 // stringa koji želimo
                                                                                                 // potpisati

            // Find root request element
            NodeList nodeToSignList = doc.getElementsByTagNameNS(XML_SCHEMA_NS, XML_REQUEST_ELEMENT);
            if (nodeToSignList.getLength() == 0) {// ako vrati praznu listu
                throw new Exception(String.format("XML element %s not found", XML_REQUEST_ELEMENT)); // vraća grešku da
                                                                                                     // nije nadjen
                                                                                                     // element
            }
            Node nodeToSign = nodeToSignList.item(0);// uzima prvi čvor liste koji treba potpisati odnosno u ovom
                                                     // slučaju će to biti root element odnosno "RegisterInvoiceRequest"

            // Create transform list
            List<Transform> transformList = new ArrayList<>(); // napravimo transform listu kao ArrayList
            transformList.add(xmlSigFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)); // uključimo
                                                                                                               // algoritam
                                                                                                               // ENVELOPED
            transformList
                    .add(xmlSigFactory.newTransform(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null)); // uključimo
                                                                                                                        // algoritam
                                                                                                                        // kanonizacije
                                                                                                                        // elementa
                                                                                                                        // xml-a

            // Create digest reference element
            Reference ref = xmlSigFactory.newReference(
                    "#" + XML_REQUEST_ID,
                    xmlSigFactory.newDigestMethod(DigestMethod.SHA256, null),
                    transformList,
                    null,
                    null);// referenciramo i hešujemo vrijednost unutar zaglavlja pojavljuje se kao
                          // <Reference URI="#Request"> unutar Signature elementa

            // Create signature method
            SignatureMethod signatureMethod = xmlSigFactory.newSignatureMethod(XML_SIG_METHOD,
                    (SignatureMethodParameterSpec) null); // inicijalizacija metoda za potpisivanje po algoritmu
                                                          // propisanom u specifikaciji

            // Create signed info element
            SignedInfo signedInfo = xmlSigFactory.newSignedInfo(
                    xmlSigFactory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                            (C14NMethodParameterSpec) null),
                    signatureMethod,
                    Collections.singletonList(ref)); // Kreiranje taga InfoElement u potpisu

            // Add certificate
            List<X509Certificate> certificateList = new ArrayList<>();
            certificateList.add(certificate); // dodajemo sertifikat kojim potpisujemo poruku

            // Create key info element
            KeyInfoFactory keyInfoFactory = xmlSigFactory.getKeyInfoFactory();// poyovemo klasu Key info factory i
                                                                              // napravimo njenu instancu
            X509Data x509Data = keyInfoFactory.newX509Data(certificateList);// ubacimo unutar klase nas sertifikat
            KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data)); // na osnovu toga kreiramo
                                                                                              // Key Info tag u potpisu

            // Create context for signing
            DOMSignContext dsc = new DOMSignContext(privateKey, nodeToSign);
            dsc.setIdAttributeNS((Element) nodeToSign, null, "Id"); // nalayimo ID u requestu poruke koju yelimo
                                                                    // potpisati

            // Sign document
            XMLSignature signature = xmlSigFactory.newXMLSignature(signedInfo, keyInfo);
            signature.sign(dsc);// potpisujemo poruku

            // Output to string
            TransformerFactory transformFactory = TransformerFactory.newInstance();
            Transformer transformer = transformFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            StringWriter sw = new StringWriter();
            StreamResult streamRes = new StreamResult(sw);
            transformer.transform(new DOMSource(doc), streamRes);
            System.out.println("Signed document is: " + sw.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}