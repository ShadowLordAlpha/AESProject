package tests;

import static org.junit.Assert.fail;

import org.junit.Test;

import cse.aes.AES;

public class AESTests {

	@Test
	public void nullArgumentTest() {
		// First we test the encrypt function
		try {
			AES.encrypt(null, new byte[1]);
			fail("Null encrypt key did not throw exception.");
		} catch(NullPointerException e) {
			
		}
		
		try {
			AES.encrypt(new byte[1], null);
			fail("Null encrypt data did not throw exception.");
		} catch(NullPointerException e) {
			
		}
		
		try {
			AES.encrypt(null, null);
			fail("Null encrypt did not throw exception.");
		} catch(NullPointerException e) {
			
		}
		
		// Now we test the decrypt function.
		try {
			AES.decrypt(null, new byte[1]);
			fail("Null decrypt key did not throw exception.");
		} catch(NullPointerException e) {
			
		}
		
		try {
			AES.decrypt(new byte[1], null);
			fail("Null decrypt data did not throw exception.");
		} catch(NullPointerException e) {
			
		}
		
		try {
			AES.decrypt(null, null);
			fail("Null decrypt did not throw exception.");
		} catch(NullPointerException e) {
			
		}
	}
	
	
}
