#ELLIPTIC CURVES CRYPTOGRAPHY

## JAVA program realising some Elliptic curves algorithm: **Diffie Hellman, Elgamal, ECDSA, STS**

## Directories:
**./src/classes**: contains some classes representing:  
	-- A point in Elliptic curve (Point.java)
	-- An equation (Equation.java)
	-- **Specific Algorithms** : they run in **client/server** mode   
		-- AES_Agent.java : realising the AES encryption and decryption  
		-- DH_Agent.java : for Diffie Hellman  
		-- DSA_Agent.java : for Digital Signature  
		-- DSA_Signer.java: signing program  
		--DSA_Verifier.java: verification program
		-- ELGML.java: for Elgamal 
		-- STS_Agent.java: for Station-To-Station  
		-- *_Server.java: server program of the corresponding algorithm  
		-- *_Client.java: client program of the corresponding algorithm  
		-- Main.java: main program for running the algorithms
**./key/**: where the cryptographic keys will be stored
**wc**: a collection of weirstrass's equations to be used  
**Elliptic curves**: a database of elliptic curves