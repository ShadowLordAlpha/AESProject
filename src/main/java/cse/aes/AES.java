package cse.aes;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;

public final class AES {

	private static final int[] rcon = { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000,
			0x40000000, 0x80000000, 0x1b000000, 0x36000000 };

	/*
	 * Both the s box and inverse s box are hardcoded as char arrays though it
	 * is possible to generate each array using an equation.
	 */
	private static final char[] invSBox = { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E,
			0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE,
			0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
			0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8,
			0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50,
			0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC,
			0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
			0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2,
			0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8,
			0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18,
			0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
			0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, 0x60, 0x51,
			0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D,
			0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77,
			0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D };

	public static final int AES128 = 1;
	public static final int AES192 = 2;
	public static final int AES256 = 3;

	/*
	 * No instances of this class should ever be created.
	 */
	private AES() {
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
	
	public static final byte[] encrypt(byte[] key, byte[] data) {
		/*
		 * We do not allow for the key or the data to be null
		 */
		if (key == null || data == null) {
			throw new NullPointerException("Key/Data can not be null.");
		}

		/*
		 * Validate AES Key length. As we allow for all 3 lengths the key can be
		 * at most 256 bits long or 32 bytes
		 */
		if (!(key.length == 32) && !(key.length == 16) && !(key.length == 24)) {
			throw new IllegalArgumentException("Key must be 16, 24, or 32 bytes long: " + key.length);
		}

		// TODO split and pad data blocks as needed
		return Cypher.encrypt(key, data);
	}

	public static final void decrypt(byte[] key, byte[] data) {
		/*
		 * We do not allow for the key or the data to be null
		 */
		if (key == null || data == null) {
			throw new NullPointerException("Key/Data can not be null.");
		}

		/*
		 * Validate AES Key length. As we allow for all 3 lengths the key can be
		 * at most 256 bits long or 32 bytes
		 */
		if (!(key.length == 32) && !(key.length == 16) && !(key.length == 24)) {
			throw new IllegalArgumentException("Key must be 16, 24, or 32 bytes long.");
		}

	}

	public static final ByteBuffer keyExpansion(byte[] key, int size, int nK) {
		ByteBuffer buffer = ByteBuffer.allocate(size * 4);
		IntBuffer bufferInt = buffer.asIntBuffer();

		buffer.put(key);

		for (int i = nK; i < size; i++) {
			int temp = bufferInt.get(i - 1);
			//System.out.printf("[ %d ]\t%8x", i, temp); // DEBUG
			if ((i % nK) == 0) {
				// This is the rotWord function
				ByteBuffer work = ByteBuffer.allocate(4).putInt(temp);
				byte workTemp = work.get(0);
				work.put(0, work.get(1));
				work.put(1, work.get(2));
				work.put(2, work.get(3));
				work.put(3, workTemp);
				// End rotWord function
				int rotWord = work.getInt(0);
				// This is here so we can reuse another function and the work done for rotWord.
				Cypher.subBytes(work.array());
				// End
				int subWord = work.getInt(0);
				int rcon = AES.rcon[(i / nK) - 1];
				temp = subWord ^ rcon;
				//System.out.printf("\t%8x\t%8x\t%8x\t%8x", rotWord, subWord, rcon, temp); // DEBUG
			} else if ((nK > 6) && ((i % nK) == 4)) {
				// This is only used for 256bit keys
				ByteBuffer work = ByteBuffer.allocate(4).putInt(temp);
				Cypher.subBytes(work.array());
				int subWord = work.getInt(0);
				temp = subWord;
				//System.out.printf("\t%8x\t%8x\t%8x\t%8x", 0, subWord, 0, temp); // DEBUG
			} else {
				//System.out.printf("\t%8x\t%8x\t%8x\t%8x", 0, 0, 0, 0); // DEBUG (this makes it look nice)
			}

			int wink = bufferInt.get(i - nK);
			int w = temp ^ wink;
			bufferInt.put(i, w);
			//System.out.printf("\t%8x\t%8x\n", wink, w); // DEBUG
		}

		return buffer;
	}

	private static final class Cypher {

		/**
		 * The s-box used for the subByte method.
		 * 
		 * Note:
		 * <p>
		 * This table is not the actual s-box table but the s-box table after
		 * the affine transformation is done on each element in the table. This
		 * makes its use easier and cuts down on the number of operations that
		 * need to be done.
		 */
		private static final short[] sBox = { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
				0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C,
				0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8,
				0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2,
				0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
				0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0,
				0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3,
				0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13,
				0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC,
				0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49,
				0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5,
				0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4,
				0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
				0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B,
				0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99,
				0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };

		public static final byte[] encrypt(byte[] key, byte[] state) {
			// number of words in the key
			int nK = (key.length * 8) / 32;
			// number of words per block
			int nB = 4; // this is always 4 as the block size is constant in AES
						// though it could be different
			// number of rounds to do
			int nR = nK + 6; // random equation that is currently always right

			ByteBuffer w = keyExpansion(key, (nB * (nR + 1)), nK);

			
			state = addRoundKey(state, w, 0);

			//System.out.println("[ 1 ] "+AES.bytesToHex(state));
			for (int round = 1; round <= nR - 1; round++) {
				
				state = subBytes(state);
				state = shiftRows(state);
				state = mixColumns(state);
				state = addRoundKey(state, w, round);
				//System.out.println("[ " + (round + 1) +" ] "+AES.bytesToHex(state));
			}
			
			state = subBytes(state);
			state = shiftRows(state);
			state = addRoundKey(state, w, nR);
			//System.out.println(AES.bytesToHex(state));
			return state;
		}

		/**
		 * Implementation of section 5.1.1 using a pre-calculated s-box with
		 * affine transformation already applied and placed into a 1d array for easy access.
		 * 
		 * @param state
		 * @return
		 */
		private static final byte[] subBytes(byte[] state) {

			for (int i = 0; i < state.length; i++) {
				state[i] = (byte) sBox[state[i] & 0xFF];
			}
			
			return state;
		}

		/**
		 * Implementation of section 5.1.2 using two for loops in place of
		 * hardcoding the transformations.
		 * 
		 * @param state
		 * @return
		 */
		private static final byte[] shiftRows(byte[] state) {

			// This is the current "row" we are working on. `i` is also the
			// shift amount for each row
			for (int i = 0; i < 4; i++) {
				// actually run the shift.
				for (int j = 0; j < i; j++) {
					// NOTE: This could also be hardcoded to properly shift all
					// values instead of a loop
					byte temp = state[i]; // get the first element in
													// a row
					// Shift the matrix row
					state[i + 0] = state[i + 4];
					state[i + 4] = state[i + 8];
					state[i + 8] = state[i + 12];
					state[i + 12] = temp;
				}
			}

			return state;
		}
		
		/**
		 * Helper method to do multiplication because for some reason it needs to be complicated
		 * 
		 * @param a
		 * @param b
		 * @return
		 */
		private static final byte GMul(byte a, byte b) { // Galois Field (256) Multiplication of two Bytes
			   byte p = 0;
			   byte counter;
			   byte hi_bit_set;
			   for (counter = 0; counter < 8; counter++) {
			      if ((b & 1) != 0) {
			         p ^= a;
			      }
			      hi_bit_set = (byte) (a & 0x80);
			      a <<= 1;
			      if (hi_bit_set != 0) {
			         a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
			      }
			      b >>= 1;
			   }
			   return p;
			}

		/**
		 * implementation of section 5.1.3
		 */
		private static final byte[] mixColumns(byte[] state) {
			
			for(int i = 0; i < 4; i++) {
				byte s0 = state[0 + (i * 4)];
	byte s1 = state[1 + (i * 4)];
				byte s2 = state[2 + (i * 4)];
				byte s3 = state[3 + (i * 4)];
				
				state[0 + (i * 4)] = (byte) (GMul((byte) (2), s0) ^ GMul((byte) (3), s1) ^ s2 ^ s3);
				state[1 + (i * 4)] = (byte) (s0 ^ GMul((byte) (2), s1) ^ GMul((byte) (3), s2) ^ s3);
				state[2 + (i * 4)] = (byte) (s0 ^ s1 ^ GMul((byte) (2), s2) ^ GMul((byte) (3), s3));
				state[3 + (i * 4)] = (byte) (GMul((byte) (3), s0) ^ s1 ^ s2 ^ GMul((byte) (2), s3));
			}
			
			return state;
		}

		private static final byte[] addRoundKey(byte[] state, ByteBuffer w, int round) {

			ByteBuffer work = ByteBuffer.wrap(state);
			for(int i = 0; i < 4; i++) {
				work.putInt(work.getInt(i * 4) ^ w.getInt(round * 16 + (i * 4)));
			}
			
			return state;
		}
	}

	private static final class InvCypher {

	}
}
