/*
 * PACKAGEID: 4C 61 62 61 6B
 * APPLETID: 4C 61 62 61 6B 41 70 70 6C 65 74
 */
package applets;

import javacard.framework.*;
import javacard.security.*;

public class JpassApplet extends javacard.framework.Applet {
	// MAIN INSTRUCTION CLASS
	final static byte CLA_APPLET = (byte) 0xB0;

	// INSTRUCTIONS
	final static byte INS_SETPIN = (byte) 0x56;
	final static byte INS_VERIFYPIN = (byte) 0x55;
	final static byte INS_SAVE_DATA = (byte) 0x58;
	final static byte INS_LOAD_DATA = (byte) 0x61;
	final static byte INS_GENERATE = (byte) 0x62;
	final static byte INS_LOGOFF = (byte) 0x60;

	final static short ARRAY_LENGTH = (short) 0x400;
	final static short SW_BAD_PIN = (short) 0x6900;
	final static short SW_BAD_STATE = (short) 0x6901;
	final static short SW_ID_NOT_FOUND = (short) 0x6903;
	final static short SW_NO_PIN = (short) 0x6904;
	final static short SW_BLOCKED = (short) 0xffff;
	final static short SW_NO_MORE = (short) 0x6906;

	private OwnerPIN m_pin = null;
	private byte m_ramArray[] = null;

	final static short ENTRY_LENGTH = 20;
	final static short SLOTS_COUNT = 30;

	private RandomData m_secureRandom = null;

	final static byte STATE_NEW = (byte) 0x00;
	final static byte STATE_BASIC = (byte) 0x0f;
	final static byte STATE_AUTH = (byte) 0xff;

	static private boolean blocked = false;
	static private byte m_appletState = STATE_NEW;

	private byte m_dataArray[];
	private short data = 0;
	private byte data_size[];

	protected JpassApplet(byte[] buffer, short offset, byte length) {
		short dataOffset = offset;

		if (length > 9) {
			dataOffset += (short) (1 + buffer[offset]);
			dataOffset += (short) (1 + buffer[dataOffset]);
			dataOffset++;

			// TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
			m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);

			m_dataArray = new byte[ARRAY_LENGTH];
			Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);

			data_size = new byte[SLOTS_COUNT];
			Util.arrayFillNonAtomic(data_size, (short) 0, SLOTS_COUNT, (byte) 0);

			m_appletState = STATE_NEW;
			m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		} else {
			ISOException.throwIt((short) (ISO7816.SW_WRONG_LENGTH + length));
		}
		register();
	}

	/**
	 * Method installing the applet.
	 * 
	 * @param bArray
	 *            the array constaining installation parameters
	 * @param bOffset
	 *            the starting offset in bArray
	 * @param bLength
	 *            the length in bytes of the data parameter in bArray
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
		// applet instance creation
		new JpassApplet(bArray, bOffset, bLength);
	}

	/**
	 * Select method returns true if applet selection is supported.
	 * 
	 * @return boolean status of selection.
	 */
	public boolean select() {
		if (m_pin.getTriesRemaining() == 0) {
			blocked = true;
			return true;
		}
		Clear();
		return true;
	}

	/**
	 * Deselect method called by the system in the deselection process.
	 */
	public void deselect() {
		m_pin.resetAndUnblock();
		Clear();
	}

	void Clear() {
		m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);

		if (m_appletState == STATE_AUTH)
			m_appletState = STATE_BASIC;
	}

	/**
	 * Method processing an incoming APDU.
	 * 
	 * @see APDU
	 * @param apdu
	 *            the incoming APDU
	 * @exception ISOException
	 *                with the response bytes defined by ISO 7816-4
	 */
	public void process(APDU apdu) throws ISOException {
		// get the APDU buffer
		byte[] apduBuffer = apdu.getBuffer();

		// ignore the applet select command dispached to the process
		if (selectingApplet())
			return;

		if (blocked) {
			ISOException.throwIt(SW_BLOCKED);
			return;
		}

		// APDU instruction parser
		if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_APPLET) {
			switch (apduBuffer[ISO7816.OFFSET_INS]) {
			// check for PIN validity
			case INS_VERIFYPIN: {
				VerifyPIN(apdu);
				break;
			}
			// set PIN for saved data
			case INS_SETPIN: {
				SetPIN(apdu);
				break;
			}
			// kill session
			case INS_LOGOFF: {
				Logoff();
				break;
			}
			// store data
			case INS_SAVE_DATA: {
				SavePwd(apdu);
				break;
			}
			// load data - PIN required
			case INS_LOAD_DATA: {
				GetData(apdu);
				break;
			}
			// generate password
			case INS_GENERATE: {
				GetRandom(apdu);
				break;
			}
			default: {
				// The INS code is not supported by the dispatcher
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
				break;
			}
			}
		} else
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
	}

	/**
	 * changes current state from AUTHENTICATED to PREPARED
	 */
	void Logoff() {
		Clear();
	}

	void GetRandom(APDU apdu) {
		byte[] apdubuf = apdu.getBuffer();
		apdu.setIncomingAndReceive();

		m_secureRandom.generateData(apdubuf, ISO7816.OFFSET_CDATA, apdubuf[ISO7816.OFFSET_P1]);
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, apdubuf[ISO7816.OFFSET_P1]);
	}

	void GetData(APDU apdu) {
		if (m_appletState != STATE_AUTH)
			ISOException.throwIt(SW_BAD_STATE);

		byte[] apdubuf = apdu.getBuffer();
		apdu.setIncomingAndReceive();

		byte temp_data = (apdubuf[ISO7816.OFFSET_P1]); // entry number

		if (data_size[temp_data] != 0x00) {
			Util.arrayCopyNonAtomic(m_dataArray, (short) (temp_data * data_size[temp_data]), apdubuf, ISO7816.OFFSET_CDATA, (short) data_size[temp_data]);
			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) data_size[temp_data]);
		} else {
			ISOException.throwIt(SW_NO_MORE);
		}
	}

	void SavePwd(APDU apdu) {
		if (m_appletState != STATE_AUTH)
			ISOException.throwIt(SW_BAD_STATE);

		byte[] apdubuf = apdu.getBuffer();
		short dataLen = apdu.setIncomingAndReceive();

		data = (short) (apdubuf[ISO7816.OFFSET_P1]); // number of entries
		data_size[data] = (byte) dataLen; // length of entries

		Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, m_dataArray, (short) (dataLen * apdubuf[ISO7816.OFFSET_P1]), dataLen);
	}

	// VERIFY PIN
	void VerifyPIN(APDU apdu) {
		byte[] apdubuf = apdu.getBuffer();
		short dataLen = apdu.setIncomingAndReceive();
		VerifyPIN(apdubuf, dataLen, ISO7816.OFFSET_CDATA);
	}

	void VerifyPIN(byte[] buf, short dataLen, short pinOffset) {
		m_pin.resetAndUnblock();// infinite number2 of trials

		// VERIFY PIN
		if (m_pin.check(buf, pinOffset, (byte) dataLen) == false) {
			ISOException.throwIt(SW_BAD_PIN);
		}

		m_appletState = STATE_AUTH;
	}

	// SET PIN
	void SetPIN(APDU apdu) {
		if (m_appletState != STATE_NEW && m_appletState != STATE_AUTH) {
			ISOException.throwIt(SW_BAD_STATE);
		}

		byte[] apdubuf = apdu.getBuffer();
		short dataLen = apdu.setIncomingAndReceive();

		SetPIN(apdubuf, dataLen, ISO7816.OFFSET_CDATA);
	}

	void SetPIN(byte[] buf, short dataLen, short pinOffset) {
		m_pin = new OwnerPIN((byte) 50, (byte) dataLen);
		m_pin.update(buf, pinOffset, (byte) dataLen);
		m_appletState = STATE_AUTH;
	}

}
