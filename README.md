# LightServer
Low level server setup to control the ikea trådfri hub, the protocol is quite simple:
The client:
1. send the length of instructions it will be sending as multiple of AES blocks, if you only need to send turn light up/down for all, 2 will be sufficient, however you can 0 pad and set it high if in doubt.
2. send ec public key picked from SECP384R1, and recieve 120 bytes. Load in the server public key in DER format. Calculate the shared key from ECDHE with this.
3. send IV for AES
4. send an AES encrypted instruction (with len as specified at 1), with the following format:
	1. Lenth of struct format and format
	2. Struct (always starts with 3 bytes to identify RPC)
5. repeat 4. and close connection
