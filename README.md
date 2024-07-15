- This Java project simulates the Trivial File Transfer Protocol (TFTP) on images using the following instructions:

Write a file transfer program. To demonstrate, you'll need a client and a server program:
- The server awaits connections.
- A client connects, and indicates the name of a file to upload or download.
- The client sends or receives the file.
  
Wherever applicable, use the commands and protocol for TFTP (IETF RFC 1350), with the following modifications. You will need to design and use additional packet header information than that in TFTP; use the IETF 2347 TFTP Options Extension when possible.
- Use TCP-style sliding windows rather than the sequential acks used in TFTP. Test with at least two different max window sizes.
- Arrange that each session begins with a sender ID and (random) number exchange to generate a key to be used for encrypting data. You can use Xor to create key, or anything better, and use this as the basis for randomized xoring or similar protocols.
- Support only binary (octet) transmission.
- Support a command line argument controlling whether to pretend to drop 1 percent of the packets;
- When receiving files, place them in a temporary directory (for example /tmp) to avoid overwriting in place on shared file systems. Validate that they have the same contents.

Create a web page showing throughput across varying conditions: at least 2 different pairs of hosts, different window sizes; drops vs no drops.

- The results of the TFTP test are in the Results folder
