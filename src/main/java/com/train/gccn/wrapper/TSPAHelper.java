package com.train.gccn.wrapper;

import com.google.common.io.BaseEncoding;
import com.train.gccn.exceptions.DNSException;
import com.train.gccn.model.report.Report;
import com.train.gccn.model.report.StdOutReportObserver;
import com.train.gccn.model.trustscheme.TrustScheme;
import com.train.gccn.model.trustscheme.TrustSchemeClaim;
import com.train.gccn.model.trustscheme.TrustSchemeFactory;
import iaik.x509.X509Certificate;
import okhttp3.*;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.net.URL;

public class TSPAHelper {
    
    /**
     * Simple Helper to assist with publishing stuff on the TSPA
     * tracked at https://extgit.iaik.tugraz.at/LIGHTest/AutomaticTrustVerifier/issues/35
     */

    public static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    private static Logger logger = Logger.getLogger(TSPAHelper.class);
    private final String trustlistURL;
    private final String scheme;
    private final String claim;
    private final String tspa;
    private final OkHttpClient client;
    private String trustlistData; // downloaded from Web via trustlistURL
    private TrustScheme discoveredScheme;
    private String daneJSON;
    private boolean disablePostCheck = false;
    
    public TSPAHelper(String tspa, String claim, String scheme, String trustlistURL) {
        this.tspa = tspa;
        this.claim = claim;
        this.scheme = scheme;
        this.trustlistURL = trustlistURL;
        
        this.client = new OkHttpClient();
    }
    
    public void setDisablePostCheck(boolean disablePostCheck) {
        this.disablePostCheck = disablePostCheck;
    }
    
    public boolean publish() throws Exception {
        
        checkIfChainAlreadyExists();
        
        loadTrustlistData();
        
        calculateSMIMEArecord();
        
        publishClaim();
        
        publishScheme();
        
        if(!this.disablePostCheck) {
            verifyChain();
    
            if(this.discoveredScheme == null) {
                TSPAHelper.logger.error("Scheme not discovered ...");
                return false;
            }
            
            TSPAHelper.logger.info("Verification successful!");
            TSPAHelper.logger.info("  configured Claim:  " + this.claim);
            TSPAHelper.logger.info("  configured Scheme: " + this.scheme);
            TSPAHelper.logger.info("  discovered Scheme: " + this.discoveredScheme.getSchemeIdentifierCleaned());
            TSPAHelper.logger.info("  discovered TSL:    " + this.discoveredScheme.getTSLlocation());
        }
        
        return true;
    }
    
    private void loadTrustlistData() throws IOException {
        TSPAHelper.logger.info("Downloading TSL from " + this.trustlistURL);
        
        HTTPSHelper http = new HTTPSHelper();
        
        URL url = new URL(this.trustlistURL);
        this.trustlistData = http.get(url);
    }
    
    private void calculateSMIMEArecord() throws Exception {
        TSPAHelper.logger.info("Calculating SMIMEA record for TSL ...");
        
        XAdESHelper xAdESHelper = new XAdESHelper(this.trustlistData, XAdESHelper.XSD_SCHEME_ETSI_TSL);
        
        if(!xAdESHelper.verify()) {
            throw new Exception("Could not verify given TSL ...");
        }
        
        X509Certificate tslSigningCert = xAdESHelper.getCertificate();
        
        SMIMEAcert smimea = new SMIMEAcert(SMIMEAcert.CertUsage.Domain_issued_certificate,
                SMIMEAcert.Selector.Full,
                SMIMEAcert.MatchingType.SHA256,
                null);
        
        byte[] certAssociationData = smimea.calculateAssociationDataForCert(tslSigningCert);
        
        String usage = "dane-ee"; // always dane-ee
        String selector = "cert"; // cert or spki
        String matching = "sha256"; // full or sha256 or sha512
        String data = BaseEncoding.base16().encode(certAssociationData);
        
        this.daneJSON = "        {\n" +
                "            \"usage\":\"" + usage + "\",\n" +
                "            \"selector\":\"" + selector + "\",\n" +
                "            \"matching\":\"" + matching + "\",\n" +
                "            \"data\":\"" + data + "\"\n" +
                "        }\n";
    }
    
    private void sendRequest(String endpoint, String data) throws Exception {
        String url = this.tspa + endpoint;
        TSPAHelper.logger.info("Sending PUT request to " + url);
        TSPAHelper.logger.info("Data: " + data);
        
        RequestBody body = RequestBody.create(TSPAHelper.JSON, data);
        Request request = new Request.Builder()
                .url(url)
                .put(body)
                .build();
        Response response = this.client.newCall(request).execute();
        
        TSPAHelper.logger.info("TSPA Response: " + response.body().string());
        if(!response.isSuccessful()) {
            throw new Exception("Error code: " + response.code());
        }
    }
    
    private void publishClaim() throws Exception {
        TSPAHelper.logger.info("Publishing claim " + this.claim);
        
        String url = this.claim + "/schemes";
        String json = "" +
                "{\n" +
                "\"schemes\": [\"" + this.scheme + "\"]\n" +
                "}\n";
        
        sendRequest(url, json);
    }
    
    private void publishScheme() throws Exception {
        TSPAHelper.logger.info("Publishing scheme " + this.scheme);
        
        String url = this.scheme + "/trust-list/";
        String json = "" +
                "{\n" +
                "\"url\": \"" + this.trustlistURL + "\",\n" +
                "\"certificate\":[\n" +
                this.daneJSON +
                "    ]\n" +
                "}\n";
        
        sendRequest(url, json);
    }
    
    private boolean checkIfChainAlreadyExists() {
        TSPAHelper.logger.info("Verifying if chain already exists ...");
        try {
            verifyChain();
            if(this.discoveredScheme == null) {
                TSPAHelper.logger.info("Chain does not yet exist. ");
                return false; // null = it does not exist
                
            }
        } catch(IOException | DNSException e) {
            TSPAHelper.logger.info("Chain does not yet exist. ");
            return false; // error = it does not exist
            
        }
        TSPAHelper.logger.warn("Chain already exists! Re-publishing anyway ...");
        return true; // no error = it exists
        
    }
    
    
    private void verifyChain() throws IOException, DNSException {
        TSPAHelper.logger.info("Verifying claim " + this.claim);
        
        TrustSchemeClaim claim = new TrustSchemeClaim(this.claim);
        
        Report report = new Report();
        StdOutReportObserver stdout_reporter = new StdOutReportObserver();
        report.addObserver(stdout_reporter);
        
        this.discoveredScheme = TrustSchemeFactory.createTrustScheme(claim, report);
    }
}
