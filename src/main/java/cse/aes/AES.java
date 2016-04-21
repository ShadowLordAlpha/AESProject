package cse.aes;

public final class AES {
	
	public static final int AES128 = 1;
	public static final int AES192 = 2;
	public static final int AES256 = 3;
	
	/*
	 * No instances of this class should ever be created.
	 */
	private AES() {}

	public static final void encrypt(byte[] key, byte[] data) {
		/*
		 * We do not allow for the key or the data to be null
		 */
		if(key == null || data == null) {
			throw new NullPointerException("Key/Data can not be null.");
		}
		
		/*
		 * Validate AES Key length. As we allow for all 3 lengths the key can be at most 256 bits long or 32 bytes
		 */
		if(!(key.length == 32) || !(key.length == 16) || !(key.length == 24)) {
			throw new IllegalArgumentException("Key must be 16, 24, or 32 bytes long.");
		}
		
		
		
	}

	public static final void decrypt(byte[] key, byte[] data) {
		/*
		 * We do not allow for the key or the data to be null
		 */
		if(key == null || data == null) {
			throw new NullPointerException("Key/Data can not be null.");
		}
		
		/*
		 * Validate AES Key length. As we allow for all 3 lengths the key can be at most 256 bits long or 32 bytes
		 */
		if(!(key.length == 32) || !(key.length == 16) || !(key.length == 24)) {
			throw new IllegalArgumentException("Key must be 16, 24, or 32 bytes long.");
		}
		
		
	}
	
	// generate a random key of the proper length
	public static final void gen(int aesType) {
		
	}
	
	private static final class Cypher {
		
	}
	
	private static final class InvCypher {
		
	}
}
