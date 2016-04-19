package simpleapdu;

import applets.SimpleApplet;
import javax.smartcardio.ResponseAPDU;
import java.lang.System;

/**
 *
 * @author xsvenda
 */
public class SimpleAPDU {
    static CardMngr cardManager = new CardMngr();

    private static byte DEFAULT_USER_PIN[] = {(byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30};
    private static byte NEW_PIN[] = {(byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31};
    private static byte APPLET_AID[] = {(byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B,
        (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
   
    private static byte ID[] = {(byte) 0x4C, (byte) 0x4C, (byte) 0x4C, (byte) 0x4C, (byte) 0x4C,
        (byte) 0x4C, (byte) 0x4C, (byte) 0x4C, (byte) 0x4C, (byte) 0x4C, 
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
    private static byte PWD[] = {(byte) 0x35, (byte) 0x35, (byte) 0x35, (byte) 0x35, (byte) 0x35};
    
    private static byte ID2[] = {(byte) 0x4C, (byte) 0x4C, (byte) 0x4C, (byte) 0x4C, (byte) 0x4C,
        (byte) 0x4C, (byte) 0x4C, (byte) 0x4C, (byte) 0x00, (byte) 0x00, 
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
    private static byte PWD2[] = {(byte) 0x36, (byte) 0x36, (byte) 0x36, (byte) 0x36};
    
    private static byte ID3[] = {(byte) 0x4C, (byte) 0x4C, (byte) 0x4C, (byte) 0x4C, (byte) 0x4C,
        (byte) 0x4C, (byte) 0x4C, (byte) 0x4C, (byte) 0x00, (byte) 0x00, 
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
    private static byte PWD3[] = {(byte) 0x37, (byte) 0x37, (byte) 0x37, (byte) 0x37, (byte) 0x37, (byte) 0x37};
    
    
    public static void main(String[] args) {
        try {
            // Prepare simulated card 
            byte[] installData = new byte[10]; // no special install data passed now - can be used to pass initial keys etc.
            //identifikator, nejake data (ma byt aspon 9), trieda pre applet
            cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, SimpleApplet.class);      
            
            /*
                    final static byte INS_VERIFYPIN                  = (byte) 0x55;
                    final static byte INS_SETPIN                     = (byte) 0x56;
                    final static byte INS_CHANGEPIN                     = (byte) 0x57;
                final static byte INS_SAVE_PWD                     = (byte) 0x58;
            */
            
            short additionalDataLen = (short)DEFAULT_USER_PIN.length;
            byte apduSetPin[] = GetHeaderSetPin(additionalDataLen);
            
            System.arraycopy(DEFAULT_USER_PIN, 0, apduSetPin, CardMngr.OFFSET_DATA, additionalDataLen);
            byte[] response = cardManager.sendAPDUSimulator(apduSetPin); 
  
            
            additionalDataLen = (short) (ID.length + PWD.length);
            byte apduNewPwd[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
            apduNewPwd[CardMngr.OFFSET_CLA] = (byte) 0xB0;//CLA_SIMPLEAPPLET  
            apduNewPwd[CardMngr.OFFSET_INS] = (byte) 0x58; //store pwd
            apduNewPwd[CardMngr.OFFSET_P1] = (byte) 0x00;
            apduNewPwd[CardMngr.OFFSET_P2] = (byte) 0x00;
            apduNewPwd[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
            
            System.arraycopy(ID, 0, apduNewPwd, CardMngr.OFFSET_DATA, ID.length);
            System.arraycopy(PWD, 0, apduNewPwd, CardMngr.OFFSET_DATA+ID.length, PWD.length);
            response = cardManager.sendAPDUSimulator(apduNewPwd); 
            
            additionalDataLen = (short) (ID2.length + PWD2.length);
            byte apduNewPwd2[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
            apduNewPwd2[CardMngr.OFFSET_CLA] = (byte) 0xB0;//CLA_SIMPLEAPPLET  
            apduNewPwd2[CardMngr.OFFSET_INS] = (byte) 0x58; //store pwd
            apduNewPwd2[CardMngr.OFFSET_P1] = (byte) 0x00;
            apduNewPwd2[CardMngr.OFFSET_P2] = (byte) 0x00;
            apduNewPwd2[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
            
            System.arraycopy(ID2, 0, apduNewPwd2, CardMngr.OFFSET_DATA, ID2.length);
            System.arraycopy(PWD2, 0, apduNewPwd2, CardMngr.OFFSET_DATA+ID2.length, PWD2.length);
            response = cardManager.sendAPDUSimulator(apduNewPwd2); 
            
            
            additionalDataLen = (short) (ID.length);
            byte apduDelete[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
            apduDelete[CardMngr.OFFSET_CLA] = (byte) 0xB0;//CLA_SIMPLEAPPLET  
            apduDelete[CardMngr.OFFSET_INS] = (byte) 0x59; //store pwd
            apduDelete[CardMngr.OFFSET_P1] = (byte) 0x00;
            apduDelete[CardMngr.OFFSET_P2] = (byte) 0x00;
            apduDelete[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
            
            System.arraycopy(ID, 0, apduDelete, CardMngr.OFFSET_DATA, ID.length);
            response = cardManager.sendAPDUSimulator(apduDelete); 
            
            /*apdu[CardMngr.OFFSET_INS] = (byte) 0x55; //VERIFY PIN 
            response = cardManager.sendAPDUSimulator(apdu);
  
            additionalDataLen = (short) (DEFAULT_USER_PIN.length + NEW_PIN.length);
            apdu = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
            apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;//CLA_SIMPLEAPPLET  
            apdu[CardMngr.OFFSET_INS] = (byte) 0x57;//change pin
            apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
            System.arraycopy(DEFAULT_USER_PIN, 0, apdu, CardMngr.OFFSET_DATA, DEFAULT_USER_PIN.length);
            System.arraycopy(NEW_PIN, 0, apdu, CardMngr.OFFSET_DATA+DEFAULT_USER_PIN.length, NEW_PIN.length);

            response =  cardManager.sendAPDUSimulator(apdu); */


        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }
    
    static byte[] GetHeaderSetPin(short additionalDataLen){
        byte apduSetPin[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
        apduSetPin[CardMngr.OFFSET_CLA] = (byte) 0xB0;//CLA_SIMPLEAPPLET  
        apduSetPin[CardMngr.OFFSET_INS] = (byte) 0x56; //SET PIN
        apduSetPin[CardMngr.OFFSET_P1] = (byte) 0x00;
        apduSetPin[CardMngr.OFFSET_P2] = (byte) 0x00;
        apduSetPin[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
            
        return apduSetPin; 
    }
    
    



}
