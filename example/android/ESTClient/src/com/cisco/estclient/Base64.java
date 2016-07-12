package com.cisco.estclient;

/*
Copyright (c) 2000 - 2013 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
*/

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;

class Base64 {
	protected static final byte[] encodingTable = { (byte) 'A', (byte) 'B',
			(byte) 'C', (byte) 'D', (byte) 'E', (byte) 'F', (byte) 'G',
			(byte) 'H', (byte) 'I', (byte) 'J', (byte) 'K', (byte) 'L',
			(byte) 'M', (byte) 'N', (byte) 'O', (byte) 'P', (byte) 'Q',
			(byte) 'R', (byte) 'S', (byte) 'T', (byte) 'U', (byte) 'V',
			(byte) 'W', (byte) 'X', (byte) 'Y', (byte) 'Z', (byte) 'a',
			(byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f',
			(byte) 'g', (byte) 'h', (byte) 'i', (byte) 'j', (byte) 'k',
			(byte) 'l', (byte) 'm', (byte) 'n', (byte) 'o', (byte) 'p',
			(byte) 'q', (byte) 'r', (byte) 's', (byte) 't', (byte) 'u',
			(byte) 'v', (byte) 'w', (byte) 'x', (byte) 'y', (byte) 'z',
			(byte) '0', (byte) '1', (byte) '2', (byte) '3', (byte) '4',
			(byte) '5', (byte) '6', (byte) '7', (byte) '8', (byte) '9',
			(byte) '+', (byte) '/' };

	protected static byte padding = (byte) '=';

	/**
	 * encode the input data producing a base 64 output stream.
	 * 
	 * @return the number of bytes produced.
	 */
	public static byte[] encode(byte[] data) throws IOException {
		int length = data.length;
		int modulus = length % 3;
		int dataLength = (length - modulus);
		int a1, a2, a3;
		int len = (length + 2) / 3 * 4;
		int bytes_written = 0;
		ByteArrayOutputStream out = new ByteArrayOutputStream(len);

		for (int i = 0; i < dataLength; i += 3) {
			a1 = data[i] & 0xff;
			a2 = data[i + 1] & 0xff;
			a3 = data[i + 2] & 0xff;

			out.write(encodingTable[(a1 >>> 2) & 0x3f]);
			out.write(encodingTable[((a1 << 4) | (a2 >>> 4)) & 0x3f]);
			out.write(encodingTable[((a2 << 2) | (a3 >>> 6)) & 0x3f]);
			out.write(encodingTable[a3 & 0x3f]);
			bytes_written += 4;
			if (((bytes_written % 72) == 0) && ((i+3) < dataLength)) {
				out.write(System.getProperty("line.separator").getBytes(Charset.forName("US-ASCII")));
			}
		}

		/*
		 * process the tail end.
		 */
		int b1, b2, b3;
		int d1, d2;

		switch (modulus) {
		case 0: /* nothing left to do */
			break;
		case 1:
			d1 = data[dataLength] & 0xff;
			b1 = (d1 >>> 2) & 0x3f;
			b2 = (d1 << 4) & 0x3f;

			out.write(encodingTable[b1]);
			out.write(encodingTable[b2]);
			out.write(padding);
			out.write(padding);
			break;
		case 2:
			d1 = data[dataLength] & 0xff;
			d2 = data[dataLength + 1] & 0xff;

			b1 = (d1 >>> 2) & 0x3f;
			b2 = ((d1 << 4) | (d2 >>> 4)) & 0x3f;
			b3 = (d2 << 2) & 0x3f;

			out.write(encodingTable[b1]);
			out.write(encodingTable[b2]);
			out.write(encodingTable[b3]);
			out.write(padding);
			break;
		}
		return out.toByteArray();
	}
}

