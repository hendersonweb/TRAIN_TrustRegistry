package com.train.gccn.wrapper;

import com.train.gccn.ATVConfiguration;
import com.train.gccn.exceptions.DNSException;
import com.train.gccn.model.report.Report;
import com.train.gccn.model.report.ReportStatus;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.net.URL;
import java.util.List;

public class TrustDiscoveryWrapper {
    
    private static Logger logger = Logger.getLogger(TrustDiscoveryWrapper.class);
    private static DNSHelper dns;
    
    private static void init() throws IOException {
        if(TrustDiscoveryWrapper.dns == null) {
            TrustDiscoveryWrapper.dns = new DNSHelper();
        }
    }
    
    public static String loadAndVerify(String pointerHostname, Report report) {
        try {
            TrustDiscoveryWrapper.init();
        } catch(IOException e) {
            TrustDiscoveryWrapper.logger.error("Error initializing loader: ", e);
            return null;
        }
        
        String url = TrustDiscoveryWrapper.discover(pointerHostname);
        
        if(url != null) {
            report.addLine("Trust Document discovered.", ReportStatus.OK);
        } else {
            report.addLine("Trust Document discovery failed for " + pointerHostname, ReportStatus.FAILED);
            return null;
        }
        
        String document = TrustDiscoveryWrapper.load(pointerHostname, url);
        
        if(document != null) {
            report.addLine("Trust Document loaded.", ReportStatus.OK);
        } else {
            report.addLine("Trust Document loading failed from " + url, ReportStatus.FAILED);
            return null;
        }
        
        if(ATVConfiguration.get().getBoolean("dane_verification_enabled") == true) {
            boolean translationValid = TrustDiscoveryWrapper.verify(pointerHostname, document);
            
            if(translationValid == true) {
                report.addLine("Trust Document Signature validation successful.", ReportStatus.OK);
            } else {
                report.addLine("Trust Document Signature validation failed.", ReportStatus.FAILED);
                return null;
            }
        } else {
            TrustDiscoveryWrapper.logger.warn("Trust Document Signature validation disabled. ");
        }
        
        return document;
    }
    
    private static boolean verify(String hostname, String document) {
        try {
            return SMIMEAHelper.verifyXMLdocument(hostname, document);
        } catch(IOException e) {
            TrustDiscoveryWrapper.logger.error("Error verifying document: " + e.getMessage());
            return false;
        }
    }
    
    private static String load(String hostname, String translationURL) {
        HTTPSHelper https = new HTTPSHelper();
        
        try {
            return https.getXML(new URL(translationURL));
        } catch(IOException e) {
            TrustDiscoveryWrapper.logger.error("Error loading document: " + e.getMessage());
            return null;
        }
    }
    
    private static String discover(String hostname) {
        TrustDiscoveryWrapper.logger.info("Discovering document at hostname: " + hostname);
        
        List<String> records = null;
        try {
            records = TrustDiscoveryWrapper.dns.queryURI(hostname);
        } catch(IOException | DNSException e) {
            TrustDiscoveryWrapper.logger.error("Error discovering document: " + e.getMessage());
            return null;
        }
        
        int numTranslations = records.size();
        
        if(numTranslations <= 0) {
            TrustDiscoveryWrapper.logger.info("found no trust document for this pointer ...");
            return null;
        }
        
        for(String tsl : records) {
            TrustDiscoveryWrapper.logger.info("found document: " + tsl);
        }
        
        if(numTranslations > 1) {
            TrustDiscoveryWrapper.logger.warn(numTranslations + " documents found, but currently only 1 supported. Returning first ...");
        }
        
        return records.get(0);
    }
    
    
}
