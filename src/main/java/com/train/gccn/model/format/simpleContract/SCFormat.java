package eu.lightest.verifier.model.format.simpleContract;

import eu.lightest.verifier.model.format.AbstractFormatParser;
import eu.lightest.verifier.model.format.FormatParser;
import eu.lightest.verifier.model.report.Report;
import eu.lightest.verifier.model.report.ReportStatus;
import eu.lightest.verifier.model.transaction.TransactionContainer;
import eu.lightest.verifier.model.transaction.TransactionFactory;
import org.apache.log4j.Logger;

import java.io.File;
import java.util.List;

public class SCFormat extends AbstractFormatParser {
    
    public static final String PATH_CONTRACT = "contract"; // TPL path
    private static final String FILEPATH_CONTRACT = "contract.txt"; // Path to file inside container
    private static final String FORMAT_ID = "simpleContract";
    private static Logger logger = Logger.getLogger(SCFormat.class);
    private final TransactionContainer transaction;
    private String contract;
    
    public SCFormat(Object transactionFile, Report report) {
        super(transactionFile, report);
        if(transactionFile instanceof File) {
            this.transaction = TransactionFactory.getTransaction((File) transactionFile);
        } else {
            throw new IllegalArgumentException("Transaction of type:" + transactionFile.getClass().toString() + ",  expected: File");
        }
    }
    
    @Override
    public boolean onExtract(List<String> path, String query, List<String> output) {
        if(path.size() == 0 && (query.equals(SCFormat.PATH_CONTRACT) || query.equals(this.QUERY_FORMAT))) {
            return true;
        }
        
        return false;
    }
    
    @Override
    public boolean onPrint(PrintObj printObj) {
        SCFormat.logger.info("onPrint:");
        //printList("path", path);
        
        if(printObj.mPath.size() == 1 && printObj.mPath.get(0).equals(SCFormat.PATH_CONTRACT)) {
            this.report.addLine("Contract: " + this.contract, ReportStatus.PRINT);
            return true;
        }
        
        FormatParser parser = getParser(printObj.mPath.get(0));
        printObj.mPath = pop(printObj.mPath);
        SCFormat.logger.info("calling onPrint on " + parser.getClass().toString());
        
        boolean status = parser.onPrint(printObj);
        
        if(status == false) {
            SCFormat.logger.error("Path " + String.join(".", printObj.mPath) + " not available in this format.");
        }
        return status;
    }
    
    
    @Override
    public String getFormatId() {
        return SCFormat.FORMAT_ID;
    }
    
    @Override
    public void init() throws Exception {
        this.contract = this.transaction.extractFileString(SCFormat.FILEPATH_CONTRACT);
        if(this.contract == null) {
            throw new Exception("Error while parsing form. Wrong format? (" + SCFormat.FILEPATH_CONTRACT + " not found.)");
        }
    }
    
    
}
