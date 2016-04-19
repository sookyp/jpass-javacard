/*
 * PACKAGEID: 4C 61 62 61 6B
 * APPLETID: 4C 61 62 61 6B 41 70 70 6C 65 74
 */
package applets;
//

/*
 * Imported packages
 */
// specific import for Javacard API access
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class SimpleApplet extends javacard.framework.Applet
{
    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET                = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_VERIFYPIN                  = (byte) 0x55;
    final static byte INS_SETPIN                     = (byte) 0x56;
    final static byte INS_CHANGEPIN                     = (byte) 0x57;
    final static byte INS_SAVE_PWD                     = (byte) 0x58;
    final static byte INS_DELETE                     = (byte) 0x59;
    final static byte INS_LOGOFF                     = (byte) 0x60;
    final static byte INS_GET_DATA                     = (byte) 0x61;
    final static byte INS_GET_RANDOM                     = (byte) 0x62;

    final static short ARRAY_LENGTH                   = (short) 0xff;
    final static short SW_BAD_PIN                    = (short) 0x6900;
    final static short SW_BAD_STATE                  = (short) 0x6901;
    final static short SW_SLOTS_FULL                 = (short) 0x6902;
    final static short SW_ID_NOT_FOUND                  = (short) 0x6903;

    private   OwnerPIN       m_pin = null;
    private short m_pinLen=0;
    
    private   byte       m_ramArray[] = null;
    
    final static short ID_LEN = 20;
    final static short SLOTS_COUNT = 30;
    private byte       m_ids[][]=null;
    private byte       m_pwds[][]=null;
    private short m_freeSlots;
    
    private   RandomData     m_secureRandom = null;
    
    private enum AppletState {NEW, BASIC, AUTHENTICATED}
   
    private AppletState m_appletState;
        
    /**
     * LabakApplet default constructor
     * Only this class's install method should create the applet object.
     */
    protected SimpleApplet(byte[] buffer, short offset, byte length)
    {
        // initialization with default offset (AID offset).
        short dataOffset = offset;
        boolean isOP2 = false;

        if(length > 9) {
           
            // shift to privilege offset
            dataOffset += (short)( 1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short)( 1 + buffer[dataOffset]);

            // go to proprietary data
            dataOffset++;


            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);//ma za zmazat ked sa zavola deselect

            m_ids = new byte[SLOTS_COUNT][ID_LEN];
            m_pwds = new byte[SLOTS_COUNT][];
            m_freeSlots = SLOTS_COUNT;
            
            m_appletState = AppletState.NEW;
            
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
            
            isOP2 = true;

        } else {
        }
        
        // register this instance
          register();
    }

    /**
     * Method installing the applet.
     * @param bArray the array constaining installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
    {
        // applet  instance creation 
        new SimpleApplet (bArray, bOffset, bLength);
    }

    /**
     * Select method returns true if applet selection is supported.
     * @return boolean status of selection.
     */
    public boolean select()
    {
      Clear();
      
      return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect()
    {
        Clear();
    }

    void Clear(){
        m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);
      
        if(m_appletState == AppletState.AUTHENTICATED)
            m_appletState = AppletState.BASIC;
    }
    
    /**
     * Method processing an incoming APDU.
     * @see APDU
     * @param apdu the incoming APDU
     * @exception ISOException with the response bytes defined by ISO 7816-4
     */
    public void process(APDU apdu) throws ISOException
    {
        // get the APDU buffer
        byte[] apduBuffer = apdu.getBuffer();
        
        // ignore the applet select command dispached to the process
        if (selectingApplet())
            return;

        // APDU instruction parser
        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) {
            switch ( apduBuffer[ISO7816.OFFSET_INS] )
            {
                case INS_VERIFYPIN: VerifyPIN(apdu); break;
                case INS_SETPIN: SetPIN(apdu); break;
                case INS_CHANGEPIN: ChangePIN(apdu); break;
                case INS_LOGOFF: Logoff(); break;
                case INS_SAVE_PWD: SavePwd(apdu); break;
                case INS_DELETE: Delete(apdu); break;
                case INS_GET_DATA: GetData(apdu); break;
                case INS_GET_RANDOM: GetRandom(apdu); break;
                default :
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
                break ;

            }
        }
        else ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED);
    }

   /**
    * changes current state from AUTHENTICATED to PREPARED
    */
    void Logoff(){
        Clear();
    }
   
    void GetRandom(APDU apdu){
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();

        m_secureRandom.generateData(apdubuf, ISO7816.OFFSET_CDATA, apdubuf[ISO7816.OFFSET_P1]);

        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, apdubuf[ISO7816.OFFSET_P1]);
    }
    
    void GetData(APDU apdu){
        if(m_appletState != AppletState.AUTHENTICATED)
            ISOException.throwIt(SW_BAD_STATE);
        
        byte[] apdubuf = apdu.getBuffer();
        
        short LE = apdu.setOutgoing();
        short toSend = GetDataSize();

        if(LE != toSend){
            apdu.setOutgoingLength(toSend);
        }
        
        short actualDataSize = 0;
        for(short i=0; i<SLOTS_COUNT; i++){
            if(m_ids[i][0]!=0x00){
                Util.arrayCopy(m_ids[i], (short) 0, apdubuf, (short) 0, ID_LEN);
                Util.arrayCopy(m_pwds[i], (short) 0, apdubuf, ID_LEN, (short) m_pwds[i].length);
                
                actualDataSize = (short) (ID_LEN+m_pwds[i].length);
                apdu.sendBytes((short) 0, actualDataSize);
                toSend-= actualDataSize;
            }
        }
        
    }
    
    short GetDataSize(){
        short result = 0;
    
        for(short i = 0; i< SLOTS_COUNT; i++){
            if(m_ids[i][0]!=0x00){
                result += m_ids[i].length;
                result += m_pwds[i].length;
            }
        }
        return result;
    }
    
    
    void SavePwd(APDU apdu){
        if(m_appletState != AppletState.AUTHENTICATED)
            ISOException.throwIt(SW_BAD_STATE);
        
        byte[]    apdubuf = apdu.getBuffer();//buffer starts with old pin, then new pin
        short     dataLen = apdu.setIncomingAndReceive();//oldpinlength+newpinlength
        
        //byte[] id = new byte[ID_LEN];
        byte[] id = JCSystem.makeTransientByteArray(ID_LEN, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopy(apdubuf, ISO7816.OFFSET_CDATA, id, (short) 0, ID_LEN);

        short slotPosition = GetSlotPosition(id);
        if(slotPosition==SLOTS_COUNT)//no suitable position for new password found
            ISOException.throwIt(SW_SLOTS_FULL);
        
        Util.arrayFillNonAtomic(m_ids[slotPosition], (short) 0, ID_LEN, (byte) 0);//clear slot for id
        Util.arrayCopy(id, (short) 0, m_ids[slotPosition], (short) 0, ID_LEN);//copy id to internal structure
        
        short pwdLen = (short) (dataLen - ID_LEN);
        m_pwds[slotPosition] = new byte[pwdLen];//new slot for pwd
        Util.arrayCopy(apdubuf, (short) (ISO7816.OFFSET_CDATA + ID_LEN), m_pwds[slotPosition], (short) 0, pwdLen);//copy pwd from apdu to internal structure
    }
    
    void Delete(APDU apdu){
        if(m_appletState != AppletState.AUTHENTICATED)
            ISOException.throwIt(SW_BAD_STATE);
        
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();
        
        for(short i = 0; i<SLOTS_COUNT; i++){
            if(Util.arrayCompare(apdubuf, ISO7816.OFFSET_CDATA, m_ids[i], (short) 0, ID_LEN)==0){
                m_ids[i][0] = 0x00;
                return;
            }
        }
      
        ISOException.throwIt(SW_ID_NOT_FOUND);//trying to delete non existing id
    }
    
    short GetSlotPosition(byte[] id){
        short freeIndex = SLOTS_COUNT;
        short updateIndex = SLOTS_COUNT;
    
        for(short i = 0; i<SLOTS_COUNT; i++){
            //lowest free slot
            if(freeIndex== SLOTS_COUNT && m_ids[i][0]==0x00)
                freeIndex=i;
            //lowest slot for update
            if((updateIndex == SLOTS_COUNT) && (Util.arrayCompare(id, (short) 0, m_ids[i], (short) 0, ID_LEN)==0))
                updateIndex = i;
        }
        
        if(updateIndex!=SLOTS_COUNT)//if slot for update found
            return updateIndex;
        
        //else return free position
        m_freeSlots--;
        return freeIndex;
    }
    
    
    void ChangePIN(APDU apdu) {
        if(m_appletState != AppletState.AUTHENTICATED){
            ISOException.throwIt(SW_BAD_STATE);
        }
        
        byte[] apdubuf = apdu.getBuffer();//buffer starts with old pin, then new pin
        short dataLen = apdu.setIncomingAndReceive();//oldpinlength+newpinlength
    
        //byte[] oldPin = new byte[m_pinLen];
        byte[] oldPin = JCSystem.makeTransientByteArray(m_pinLen, JCSystem.CLEAR_ON_DESELECT);
        short newPinLen = (short) (dataLen-m_pinLen);
        //byte[] newPin = new byte[newPinLen];
        byte[] newPin = JCSystem.makeTransientByteArray(newPinLen, JCSystem.CLEAR_ON_DESELECT);
        
        Util.arrayCopy(apdubuf, ISO7816.OFFSET_CDATA, oldPin, (short) 0, m_pinLen);
        Util.arrayCopy(apdubuf, (short) (ISO7816.OFFSET_CDATA + m_pinLen), newPin, (short) 0, newPinLen);
    
        VerifyPIN(oldPin, m_pinLen, (short) 0);
        SetPIN(newPin, newPinLen, (short) 0);
    }
    
    // VERIFY PIN
     void VerifyPIN(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      VerifyPIN(apdubuf, dataLen, ISO7816.OFFSET_CDATA);
    }

    void VerifyPIN(byte[] buf, short dataLen, short pinOffset)
    {
      m_pin.resetAndUnblock();//infinite number2 of trials

      // VERIFY PIN
      if (m_pin.check(buf, pinOffset, (byte) dataLen) == false){
          ISOException.throwIt(SW_BAD_PIN);
      }
      
      m_appletState = AppletState.AUTHENTICATED;
    }
    
     // SET PIN
    void SetPIN(APDU apdu) {
      if(m_appletState != AppletState.NEW && m_appletState!=AppletState.AUTHENTICATED){
          ISOException.throwIt(SW_BAD_STATE);
      }   
         
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      
      SetPIN(apdubuf, dataLen, ISO7816.OFFSET_CDATA);
    }
    
    void SetPIN(byte[] buf, short dataLen, short pinOffset){
      m_pin = new OwnerPIN((byte) 50, (byte) dataLen);
      m_pin.update(buf, pinOffset, (byte) dataLen);
      m_pinLen = dataLen;
      
      m_appletState = AppletState.AUTHENTICATED;
    }
    

}

