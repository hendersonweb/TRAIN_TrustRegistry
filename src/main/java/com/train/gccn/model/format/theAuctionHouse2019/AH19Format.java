package eu.lightest.verifier.model.format.theAuctionHouse2019;

import eu.lightest.horn.specialKeywords.HornApiException;
import eu.lightest.verifier.model.format.AbstractFormatParser;
import eu.lightest.verifier.model.format.Delegation.DelegationXMLFormat;
import eu.lightest.verifier.model.format.FormatParser;
import eu.lightest.verifier.model.format.JaxbUtil;
import eu.lightest.verifier.model.format.eIDAS_qualified_certificate.EidasCertFormat;
import eu.lightest.verifier.model.report.Report;
import eu.lightest.verifier.model.report.ReportStatus;
import eu.lightest.verifier.model.transaction.ASiCSignature;
import eu.lightest.verifier.model.transaction.TransactionContainer;
import eu.lightest.verifier.model.transaction.TransactionFactory;
import org.apache.log4j.Logger;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.List;

public class AH19Format extends AbstractFormatParser {
    
    private static final String PATH_CERT = "certificate";
    private static final String PATH_BID = "bid"; // TPL path
    private static final String PATH_LOTNR = "lot"; // lot_number
    private static final String PATH_DELEGATION = "delegation";
    private static final String FILEPATH_FORM = "bid.xml"; // Path to file inside container
    private static final String FORMAT_ID = "theAuctionHouse2019";
    private static Logger logger = Logger.getLogger(AH19Format.class);
    private TransactionContainer transaction = null;
    private Form form; // unmarshaled XML
    
    public AH19Format(Object transactionFile, Report report) {
        super(transactionFile, report);
        if(transactionFile instanceof File) {
            this.transaction = TransactionFactory.getTransaction((File) transactionFile);
        } else {
            throw new IllegalArgumentException("Transaction of type:" + transactionFile.getClass().toString() + ",  expected: File");
        }
    }
    
    @Override
    public boolean onExtract(List<String> path, String query, List<String> output) throws HornApiException {
        if(path.size() == 0) {
            switch(query) {
                case AH19Format.PATH_BID:
                case AH19Format.PATH_CERT:
                case AbstractFormatParser.QUERY_FORMAT:
                case AH19Format.PATH_DELEGATION:
                    return true;
            }
        }
    
        String parserId = path.get(0);
        AH19Format.logger.info("delegating to parser: " + parserId);
        return getParser(parserId).onExtract(pop(path), query, output);
    }
    
    @Override
    public boolean onPrint(PrintObj printObj) {
        AH19Format.logger.info("onPrint:");
        //printList("path", path);
        
        if(printObj.mPath.size() == 1 && printObj.mPath.get(0).equals(AH19Format.PATH_BID)) {
            this.report.addLine("Bid: " + this.form.getBid(), ReportStatus.PRINT);
            return true;
        }
        
        FormatParser parser = getParser(printObj.mPath.get(0));
        printObj.mPath = pop(printObj.mPath);
        AH19Format.logger.info("calling onPrint on " + parser.getClass().toString());
        
        boolean status = parser.onPrint(printObj);
        
        if(status == false) {
            AH19Format.logger.error("Path " + String.join(".", printObj.mPath) + " not available in this format.");
        }
        return status;
    }
    
    @Override
    public boolean onVerifySignature(List<String> pathToSubject, List<String> pathToCert) throws HornApiException {
    
        if(pathToSubject.size() == 0) {
        
            ResolvedObj sigObj = this.rootListener.resolveObj(pathToCert);
            if(sigObj == null || !sigObj.mType.equals(EidasCertFormat.RESOLVETYPE_X509CERT) || !(sigObj.mValue instanceof X509Certificate)) {
                AH19Format.logger.error("Could not resolve certificate from " + String.join(".", pathToCert));
                this.report.addLine("Signature Verification failed: Certificate error.", ReportStatus.FAILED);
                return false;
            }
        
            X509Certificate cert = (X509Certificate) sigObj.mValue;
            AH19Format.logger.info("Verifying signature using cert: " + cert.getSubjectDN());
        
            for(ASiCSignature signature : this.transaction.getSignatures()) {
                if(signature.getSigningX509Certificate().equals(cert)) {
                    AH19Format.logger.info("Found signature for given cert.");
                    if(!this.transaction.verifySignature(cert, signature)) {
                        this.report.addLine("Signature Verification failed.", ReportStatus.FAILED);
                        return false;
                    }
                }
            }
        
            this.report.addLine("AH19 Container Signature Verification successful.");
            return true;
        } else if(pathToSubject.size() == 1) {
            String parserId = pathToSubject.get(0);
            AH19Format.logger.info("delegating to parser: " + parserId);
            return getParser(parserId).onVerifySignature(pop(pathToSubject), pathToCert);
        }
    
        AH19Format.logger.warn("Invalid path: " + String.join(".", pathToSubject));
        return false;
    }
    
    @Override
    public ResolvedObj resolveObj(List<String> path) {
        //AH19Format.logger.info("resolveObj: " + String.join(".", path));
        
        if(path.size() > 1) {
            String parserId = path.get(0);
            FormatParser parser = getParser(parserId);
            
            return parser.resolveObj(pop(path));
        }
        
        switch(path.get(0)) {
            case AH19Format.PATH_BID:
                return genResolvedObj(AH19Format.this.form.getBid(), "INT");
            case AH19Format.PATH_LOTNR:
                return genResolvedObj(AH19Format.this.form.getLotNumber(), "INT");
            case AH19Format.PATH_CERT:
                return genResolvedObj(this.transaction.getSigningCertificate(), EidasCertFormat.RESOLVETYPE_X509CERT);
            case AbstractFormatParser.QUERY_FORMAT:
                return genResolvedObj(getFormatId(), "STRING");
            case AH19Format.PATH_DELEGATION:
                List<String> files = this.transaction.getFileList();
                for(String f : files) {
                    if(f.contains("delegation.xml") == true) {
                        return genResolvedObj(this.transaction.extractFileString(f), DelegationXMLFormat.RESOLVETYPE_DELEGATION);
                    }
                }
        }
        
        return null;
    }
    
    @Override
    public String getFormatId() {
        return AH19Format.FORMAT_ID;
    }
    
    @Override
    public void init() throws Exception {
        String formXML = this.transaction.extractFileString(AH19Format.FILEPATH_FORM);
        if(formXML == null) {
            throw new Exception("Error while parsing form. Wrong format? (" + AH19Format.FILEPATH_FORM + " not found.)");
        }
    
        this.form = JaxbUtil.unmarshal(formXML, Form.class);
    
        if(!this.form.getFormat().equals(AH19Format.FORMAT_ID)) {
            throw new Exception("Error while parsing form. Wrong format? (" + AH19Format.FILEPATH_FORM + " not found.)");
        }
    }
    
}
