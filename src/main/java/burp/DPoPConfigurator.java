package main.java.burp;

import burp.*;
import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.*;

import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.UUID;

public class DPoPConfigurator implements IBurpExtender,ITab, IHttpListener{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    PrintWriter stdout;
    PrintWriter stderr;
    private JPanel panel;
    private JTextField publicKeyTextField;
    private JTextField privateKeyTextField;
    private JTextField targetTextField;
    private JTextField targetHttpHeaderTextField;
    private JCheckBox regexCheckBox;
    private JLabel resultLabel;


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();


        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.setExtensionName("DPoP Configurator");
        callbacks.registerHttpListener(this);



        SwingUtilities.invokeLater(() -> {
            panel = new JPanel(new GridLayout(30, 3, 5, 5));
            panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10)); // Padding eklemek için

            JLabel infoPublic = new JLabel("Enter Public Key JWK:");
            JLabel infoPrivate = new JLabel("Enter Private Key JWK:");
            JLabel infoTarget = new JLabel("Enter Target URL or Target's regex:");
            JLabel infoRegex = new JLabel("Is Regex:");
            JLabel infoHTTPHeader = new JLabel("DPoP HTTP Header:");

            publicKeyTextField = new JTextField(10);
            privateKeyTextField = new JTextField(10);
            targetTextField = new JTextField(10);
            regexCheckBox = new JCheckBox();
            targetHttpHeaderTextField = new JTextField(10);


            resultLabel = new JLabel("", SwingConstants.CENTER); // Sonuç için etiket
            resultLabel.setForeground(Color.BLUE); // Mavi renkte metin

            panel.add(infoPublic);
            panel.add(publicKeyTextField);

            panel.add(infoPrivate);
            panel.add(privateKeyTextField);

            panel.add(infoTarget);
            panel.add(targetTextField);

            panel.add(infoRegex);
            panel.add(regexCheckBox);

            panel.add(infoHTTPHeader);
            panel.add(targetHttpHeaderTextField);


            callbacks.customizeUiComponent(panel);
            callbacks.addSuiteTab(DPoPConfigurator.this);

        });
    }

    @Override
   public String getTabCaption() {
        return "DPoP Configurator";
    }

    @Override
    public Component getUiComponent() {
        return panel;
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

        if (!messageIsRequest) {
            return;
        }
        IRequestInfo requestInfo = this.callbacks.getHelpers().analyzeRequest(messageInfo);
        String targetUrl = targetTextField.getText();
        boolean isRegex = regexCheckBox.isSelected();

        try {
            if (!targetUrl.isEmpty()){
                if (isRegex) {
                    String regexPattern = targetUrl.replace(".", "\\.")
                            .replace("*", ".*");


                    if (requestInfo.getUrl().toString().matches(targetUrl)) {
                        ArrayList<String> headers = editDPopJWT(requestInfo);
                        byte[] message = helpers.buildHttpMessage(headers, Arrays.copyOfRange(messageInfo.getRequest(), requestInfo.getBodyOffset(), messageInfo.getRequest().length));
                        messageInfo.setRequest(message);

                    }
                } else {

                    if (requestInfo.getUrl().toString().contains(targetUrl)) {

                        ArrayList<String> headers = editDPopJWT(requestInfo);
                        byte[] message = helpers.buildHttpMessage(headers, Arrays.copyOfRange(messageInfo.getRequest(), requestInfo.getBodyOffset(), messageInfo.getRequest().length));
                        messageInfo.setRequest(message);


                    }
                }
            }

        } catch (Exception e) {
            throw new RuntimeException(e);
        }


    }

    public ArrayList<String> editDPopJWT(IRequestInfo requestInfo) throws Exception {

        String privateKeyJson = privateKeyTextField.getText();
        String publicKeyJson = publicKeyTextField.getText();

        RSAPrivateKey privateKey = JWKToPrivateKey(privateKeyJson);
        RSAPublicKey publicKey = JWKToPublicKey(publicKeyJson);

        // Generate JWT

        String headerName = targetHttpHeaderTextField.getText();

        URL url = requestInfo.getUrl();
        String htu = url.getProtocol() + "://" + url.getHost() + url.getPath();

        String jwt = generateDPoPJWT(privateKey,publicKey, requestInfo.getMethod(),htu);
        ArrayList<String> headers = (ArrayList<String>) requestInfo.getHeaders();

        ArrayList<String> newHeaders = new ArrayList<>();

        for (int i = 0; i < headers.size(); i++) {
            if (!headers.get(i).startsWith(headerName)) {
                // there could be more than one header like this; remove and continue
                newHeaders.add(headers.get(i));
            }
        }
        String newHeader = headerName + ": "+ jwt;

        newHeaders.add(newHeader);

        return newHeaders;
    }


    private static RSAPrivateKey JWKToPrivateKey(String privateKeyJwk) throws Exception {
        RSAKey rsaJWK = RSAKey.parse(privateKeyJwk);
        return (RSAPrivateKey) rsaJWK.toPrivateKey();
    }
    private static RSAPublicKey JWKToPublicKey(String privateKeyJwk) throws Exception {
        RSAKey rsaJWK = RSAKey.parse(privateKeyJwk);
        return (RSAPublicKey) rsaJWK.toPublicKey();
    }

    public static String generateDPoPJWT(PrivateKey privateKey, PublicKey publicKey,String htm,String htu) throws JOSEException {
        String jwtID = UUID.randomUUID().toString();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issueTime(new Date())
                .jwtID(jwtID)
                .claim("htm", htm)
                .claim("htu", htu)
                .build();

        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256);
        JWK jwk = new RSAKey.Builder((RSAPublicKey) publicKey).build();
        headerBuilder.jwk(jwk);
        JOSEObjectType type = new JOSEObjectType("dpop+jwt");
        headerBuilder.type(type);

        JWSSigner signer = new RSASSASigner(privateKey);

        SignedJWT signedJWT = new SignedJWT(headerBuilder.build(), claimsSet);
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    public static PrivateKey privateKeyFromJson(String privateKeyJson) throws Exception {
        RSAKey rsaJWK = RSAKey.parse(privateKeyJson);
        return rsaJWK.toPrivateKey();
    }


}
