Example test files for RSADP Decryption Operation Primitive Component

1. The file wRSADPComponent800_56B.rsp is the response file in the proper format for CAVS validation.

2. The file RSADPComponent800_56B.txt contains values for RSADP component testing with the following additional values used in the generation of the k value:

	a. 'd' -- The private key.
	
	b. 'c^d' -- an intermediate value in the calculation of k = c^d mod n.

	c. 'k^e' -- an intermediate value in the calculation of c = k^e mod n.

	See Section 7.1.2 of the NIST SP 800-56B: Recommendation for Pair-Wise Key Establishment Schemes Using Integer Factorization Cryptography (August 2009). 