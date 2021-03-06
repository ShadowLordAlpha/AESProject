package tests;

import static org.junit.Assert.fail;

import java.nio.ByteBuffer;

import org.junit.Assert;
import org.junit.Test;

import cse.aes.AES;

public class AESTests {

	@Test
	public void nullArgumentTest() {
		// First we test the encrypt function
		try {
			AES.encrypt(null, new byte[1]);
			fail("Null encrypt key did not throw exception.");
		} catch (NullPointerException e) {

		}

		try {
			AES.encrypt(new byte[1], null);
			fail("Null encrypt data did not throw exception.");
		} catch (NullPointerException e) {

		}

		try {
			AES.encrypt(null, null);
			fail("Null encrypt did not throw exception.");
		} catch (NullPointerException e) {

		}

		// Now we test the decrypt function.
		try {
			AES.decrypt(null, new byte[1]);
			fail("Null decrypt key did not throw exception.");
		} catch (NullPointerException e) {

		}

		try {
			AES.decrypt(new byte[1], null);
			fail("Null decrypt data did not throw exception.");
		} catch (NullPointerException e) {

		}

		try {
			AES.decrypt(null, null);
			fail("Null decrypt did not throw exception.");
		} catch (NullPointerException e) {

		}
	}

	@Test
	public void keyExpanTest() {
		// 128 bit key
		byte[] key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6, (byte) 0xab, (byte) 0xf7, 0x15, (byte) 0x88, 0x09, (byte) 0xcf, 0x4f, 0x3c };
		ByteBuffer w = AES.keyExpansion(key, (4 * (10 + 1)), 4);
		// TODO:
		
		// 192
		
		// 256
	}
	
	@Test
	public void encTest() {
		byte[] key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6, (byte) 0xab, (byte) 0xf7, 0x15, (byte) 0x88, 0x09, (byte) 0xcf, 0x4f, 0x3c };
		byte[] data = { 0x32, 0x43, (byte) 0xf6, (byte) 0xa8, (byte) 0x88, 0x5a, 0x30, (byte) 0x8d, 0x31, 0x31, (byte) 0x98, (byte) 0xa2, (byte) 0xe0, 0x37, 0x07, 0x34 };
		Assert.assertEquals("3925841D02DC09FBDC118597196A0B32", bytesToHex(AES.encrypt(key, data)));
	}
	
	@Test
	public void encdecTest() {
		byte[] key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
		byte[] data = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff };
		String expecteds = bytesToHex(data);
		Assert.assertEquals(expecteds, bytesToHex(AES.decrypt(key, AES.encrypt(key, data))));
	}
	
	// useful for debugging
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
}
