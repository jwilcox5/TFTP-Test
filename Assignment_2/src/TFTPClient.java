import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Random;
import java.util.Scanner;

public class TFTPClient 
{
    public static void main(String[] args) throws Exception 
    {   
        /////////////////////// Starting the Client ////////////////////////////////

        String host = "localhost"; // The name of the server
        int port    = 26931;       // The port that will be accessed on the server

        Selector selector = Selector.open();
        DatagramChannel client = DatagramChannel.open();
        client.bind(null);
        client.configureBlocking(false);
        client.register(selector, SelectionKey.OP_READ);
        InetSocketAddress serverAddress = new InetSocketAddress(host, port);
        System.out.println("Server Connected");

        /////////////////////// Creating the Shared Secret Key ////////////////////////////////

        Random random  = new Random();

        long senderID = random.nextLong();
        System.out.println("Client's Sender ID: " + senderID);

        // Send the client's key to the server
        ByteBuffer senderIDBuffer = ByteBuffer.wrap(String.valueOf(senderID).getBytes("ISO-8859-1"));
        client.send(senderIDBuffer, serverAddress);
        selector.selectedKeys().clear();
        selector.select(1000000);
        client.receive(senderIDBuffer);

        // Generate the random key for the client
        long clientKey = random.nextLong();
        long serverKey = 0;

        // Send the client's key to the server
        ByteBuffer clientKeyBuffer = ByteBuffer.wrap(String.valueOf(clientKey).getBytes("ISO-8859-1"));
        client.send(clientKeyBuffer, serverAddress);

        // Receive the server's key
        ByteBuffer serverKeyBuffer = ByteBuffer.allocate(2048);
        selector.selectedKeys().clear();
        selector.select(1000000);
        client.receive(serverKeyBuffer);

        serverKeyBuffer.flip();
        int sKLimits = serverKeyBuffer.limit();
        byte sKBytes[] = new byte[sKLimits];
        serverKeyBuffer.get(sKBytes, 0, sKLimits);
        String sKey = new String(sKBytes, "ISO-8859-1");
        serverKey = Long.parseLong(sKey);

        // XOR the two keys together to create a shared encrypting/decrypting key
        long sharedKey = clientKey ^ serverKey;

        /////////////////////// Local Constants and Variables Needed For TFTP ////////////////////////////////

        Scanner scan = new Scanner(System.in);

        // Opcodes for different Packet types (Read Requests, Write Requests, Data, and ACK)
        final byte READ_REQUEST_OPCODE  = 1;
	    final byte WRITE_REQUEST_OPCODE = 2;
	    final byte DATA_OPCODE          = 3;
        final byte ACK_OPCODE           = 4;

        Path file = null;

        String requestType       = "";      // The request the user is making (Read or Write)
        byte[] filename          = null;    // The name of the file to be transferred as a byte array
        String filenameStr       = "";      // The name of the file to be transferred as a string
        byte[] mode              = null;    // The mode the data is transferred as a byte array
        String modeStr           = "octet"; // The mode the data is transferred as a string
        int windowSize           = 0;
        int wsCounter            = 1;
        boolean hasWindowStarted = false;
        char willDropPackets     = ' ';

        int reqPackLen                         = 0;    // Length of the Request packet
        ByteArrayOutputStream reqPackOutStream = null; // ByteArrayOutputStream Object used to create the Request Packet

        byte[] readReqPack           = null; // Read Request Packet
        byte[] encryptedReadReqPack  = null; 
        ByteBuffer readReqPackBuffer = null; 

        byte[] writeReqPack           = null; // Write Request Packet
        byte[] encryptedWriteReqPack  = null; 
        ByteBuffer writeReqPackBuffer = null; 

        byte[] ackPack                         = null; // ACK Packet
        byte[] encryptedAckPack                = null;
        byte ackPackSeqNum                     = 0;    // Sequence Number of ACK Packet
        int aPLimits                           = 0;
        byte[] aPBytes                         = null;
        ByteBuffer ackPackBuffer               = ByteBuffer.allocate(2048);
        final int ackPackLen                   = 4;    // Length of the ACK Packet
        ByteArrayOutputStream ackPackOutStream = null; // ByteArrayOutputStream Object used to create the ACK Packet
        
        byte[] dataPack                         = null; // Data Packet from the Client
        byte[] tempDataPack                     = null;
        byte[] newDataPack                      = null;
        byte[] encryptedDataPack                = null;
        byte dataPackSeqNum                     = 0;    // Sequence Number of Data Packet
        byte[] data                             = null; // The bytes from the file that is being transferred
        int dPLimits                            = 0;
        byte[] dPBytes                          = null;
        ByteBuffer dataPackBuffer               = ByteBuffer.allocate(65536);
        final int dataPackLen                   = 516;  // Length of the Data Packet
        ByteArrayOutputStream dataPackOutStream = null; // ByteArrayOutputStream Object used to create the Data Packet

        byte[] fileBytes                            = null; // Byte array that stores all of the bytes of the file to be transferred
        double packetsToSend                        = 0;
        int packetsToSend1Per                       = 0;
        HashMap<Integer, Integer> randPacketsToDrop = new HashMap<>();;
        int randNum                                 = 0;
        int packetCounter                           = 1;
        int byteCounter                             = 0;    // Counter to keep track of how many bytes are being stored in the Data Packet
        int tempCounter;
        int numKeys                                 = 0;

        double startTime  = 0;
        double totalTime  = 0;
        double throughput = 0;

        /////////////////////// Starting TFTP ////////////////////////////////

        while(true)
        {
            // Ask user for which kind of request they want to make
            System.out.print("Which kind of request do you want make to the server (R/W)?: ");
            requestType = scan.next();

            // Ask user for which file they want to transfer
            System.out.print("What file would you like to transfer?: ");
            filenameStr = scan.next();

            // Ask user for which file they want to transfer
            System.out.print("What window size do you want?: ");
            windowSize = scan.nextInt();

            // Ask user for which file they want to transfer
            System.out.print("Do you want to simulate packet drops (Y/N)?: ");
            willDropPackets = scan.next().charAt(1);

            filename = filenameStr.getBytes("ISO-8859-1");
            mode = modeStr.getBytes("ISO-8859-1");

            // If user if making a read (Download) request
            if(requestType.equals("R"))
            {
                // Determine the length of the Read Request Packet
                reqPackLen = filename.length + mode.length + 4;

                // Create the Read Request Packet 
                reqPackOutStream = new ByteArrayOutputStream(reqPackLen);
                reqPackOutStream.write(0);
                reqPackOutStream.write(READ_REQUEST_OPCODE);
                reqPackOutStream.write(filename);
                reqPackOutStream.write(0);
                reqPackOutStream.write(mode);
                reqPackOutStream.write(0);
                reqPackOutStream.write(windowSize);

                if(willDropPackets == 'Y')
                {
                    reqPackOutStream.write(1);
                }

                else
                {
                    reqPackOutStream.write(0);
                }
                
                // Encrypt the Read Request Packet
                readReqPack = reqPackOutStream.toByteArray();
                encryptedReadReqPack = xorShiftBytes(readReqPack, sharedKey);

                // Send the Read Request Packet to the server and wait for the first Data Packet
                readReqPackBuffer = ByteBuffer.wrap(encryptedReadReqPack);
                client.send(readReqPackBuffer, serverAddress);

                // Start the timer immediately before sending the message and the random key to the server
                startTime = System.nanoTime();

                // Create a new file with the specified name to be written to
                file = Paths.get("C:/Users/jackh/Downloads/Networks Stuff/Assignment_2/Temp/" + filenameStr);
                Files.createFile(file);

                // Receive the Data Packets from the client
                selector.selectedKeys().clear();
                selector.select(1000000);
                client.receive(dataPackBuffer);

                // Decrypt the Data Packet
                dataPackBuffer.flip();
                dPLimits = dataPackBuffer.limit();
                dPBytes = new byte[dPLimits];
                dataPackBuffer.get(dPBytes, 0, dPLimits);
                dataPack = xorShiftBytes(dPBytes, sharedKey);

                while(true)
                {
                    // Check that the Data Packet's Opcode is correct
                    if(dataPack[1] == 3)
                    {
                        data = new byte[512];

                        if(newDataPack != null && newDataPack.length < 516)
                        {
                            // Extract the file's bytes from the Data Packet
                            for(int j = 4; j < dataPack.length; j++)
                            {
                                data[byteCounter] = dataPack[j];
                                byteCounter++;

                                if(byteCounter == 512 || j == dataPack.length - 1)
                                {
                                    // Append the files bytes to the newly created file
                                    Files.write(file, data, StandardOpenOption.APPEND);

                                    ackPackSeqNum++;

                                    byteCounter = 0;
                                    j = j + 4;

                                    if(dataPack.length - j < 512)
                                    {
                                        if(dataPack.length - j < 0)
                                        {
                                            data = null;
                                        }

                                        else
                                        {
                                            data = new byte[dataPack.length - j];
                                        }
                                    }

                                    else
                                    {
                                        data = new byte[512];
                                    }
                                }
                            }
                        }

                        else
                        {
                            // Extract the file's bytes from the Data Packet
                            for(int j = 4; j < data.length + 4; j++)
                            {
                                data[byteCounter] = dataPack[j];
                                byteCounter++;
                            }

                            // Append the files bytes to the newly created file
                            Files.write(file, data, StandardOpenOption.APPEND);

                            // Update the ACK Packet's Sequence Number
                            dataPackSeqNum = dataPack[3];
                            ackPackSeqNum = dataPackSeqNum;
                        }
                        
                        byteCounter = 0;

                        // Create a new ACK Packet
                        ackPackOutStream = new ByteArrayOutputStream(ackPackLen);
                        ackPackOutStream.write(0);
                        ackPackOutStream.write(ACK_OPCODE);
                        ackPackOutStream.write(0);
                        ackPackOutStream.write(ackPackSeqNum);

                        ackPack = ackPackOutStream.toByteArray();
                        encryptedAckPack = xorShiftBytes(ackPack, sharedKey);

                        // Send the ACK Packet to the client and wait for the next Data Packet
                        ackPackBuffer = ByteBuffer.wrap(encryptedAckPack);
                        client.send(ackPackBuffer, serverAddress);

                        dataPackBuffer.clear();
                        ackPackBuffer.clear();

                        // If a Data Packet is received where the number of file bytes is less than 512, then the file has been successfully transferred
                        if(data == null)
                        {
                            System.out.println("File Transferred Successfully!");
                            break;
                        }

                        selector.selectedKeys().clear();
                        numKeys = selector.select(1000000);
                        client.receive(dataPackBuffer);

                        // Decrypt the Data Packet
                        dataPackBuffer.flip();
                        dPLimits = dataPackBuffer.limit();
                        dPBytes = new byte[dPLimits];
                        dataPackBuffer.get(dPBytes, 0, dPLimits);
                        newDataPack = xorShiftBytes(dPBytes, sharedKey);

                        if(newDataPack[0] == 'Y')
                        {
                            tempDataPack = new byte[dataPack.length - 516 + newDataPack.length];

                            for(tempCounter = 0; tempCounter < dataPack.length - 516; tempCounter++)
                            {
                                tempDataPack[tempCounter] = dataPack[tempCounter + 516];
                            }

                            for(int i = 0; i < newDataPack.length; i++)
                            {
                                tempDataPack[tempCounter] = newDataPack[i];
                                tempCounter++;
                            }

                            dataPack = tempDataPack;

                            data = new byte[512];

                            // Extract the file's bytes from the Data Packet
                            for(int j = 4; j < data.length + 4; j++)
                            {
                                data[byteCounter] = dataPack[j];
                                byteCounter++;
                            }

                            // Append the files bytes to the newly created file
                            Files.write(file, data, StandardOpenOption.APPEND);

                            // Update the ACK Packet's Sequence Number
                            dataPackSeqNum = dataPack[3];
                            ackPackSeqNum = dataPackSeqNum;

                            byteCounter = 0;

                            // Create a new ACK Packet
                            ackPackOutStream = new ByteArrayOutputStream(ackPackLen);
                            ackPackOutStream.write(0);
                            ackPackOutStream.write(ACK_OPCODE);
                            ackPackOutStream.write(0);
                            ackPackOutStream.write(ackPackSeqNum);

                            ackPack = ackPackOutStream.toByteArray();
                            encryptedAckPack = xorShiftBytes(ackPack, sharedKey);

                            // Send the ACK Packet to the client and wait for the next Data Packet
                            ackPackBuffer = ByteBuffer.wrap(encryptedAckPack);
                            client.send(ackPackBuffer, serverAddress);

                            dataPackBuffer.clear();
                            ackPackBuffer.clear();

                            selector.selectedKeys().clear();
                            selector.select(1000000);
                            client.receive(dataPackBuffer);

                            // Decrypt the Data Packet
                            dataPackBuffer.flip();
                            dPLimits = dataPackBuffer.limit();
                            dPBytes = new byte[dPLimits];
                            dataPackBuffer.get(dPBytes, 0, dPLimits);
                            newDataPack = xorShiftBytes(dPBytes, sharedKey);
                        }

                        tempDataPack = new byte[dataPack.length - 516 + newDataPack.length];

                        for(tempCounter = 0; tempCounter < dataPack.length - 516; tempCounter++)
                        {
                            tempDataPack[tempCounter] = dataPack[tempCounter + 516];
                        }

                        for(int i = 0; i < newDataPack.length; i++)
                        {
                            tempDataPack[tempCounter] = newDataPack[i];
                            tempCounter++;
                        }

                        dataPack = tempDataPack;
                    }

                    // If the Sequence Number is out of order
                    else
                    {
                        System.out.println("***FATAL ERROR!***");
                        break;
                    }
                }
            }

            // If the user is making a Write (Upload) Request
            else if(requestType.equals("W"))
            {
                // Determine the length of the Write Request Packet
                reqPackLen = filename.length + mode.length + 4;

                // Create the Write Request Packet 
                reqPackOutStream = new ByteArrayOutputStream(reqPackLen);
                reqPackOutStream.write(0);
                reqPackOutStream.write(WRITE_REQUEST_OPCODE);
                reqPackOutStream.write(filename);
                reqPackOutStream.write(0);
                reqPackOutStream.write(mode);
                reqPackOutStream.write(0);

                // Encrypt the Write Request Packet
                writeReqPack = reqPackOutStream.toByteArray();
                encryptedWriteReqPack = xorShiftBytes(writeReqPack, sharedKey);

                // Send the Write Request Packet to the server and wait for the ACK Packet
                writeReqPackBuffer = ByteBuffer.wrap(encryptedWriteReqPack);
                client.send(writeReqPackBuffer, serverAddress);
                selector.selectedKeys().clear();
                selector.select(1000000);
                client.receive(ackPackBuffer);

                // Decrypt the ACK Packet
                ackPackBuffer.flip();
                aPLimits = ackPackBuffer.limit();
                aPBytes = new byte[aPLimits];
                ackPackBuffer.get(aPBytes, 0, aPLimits);
                ackPack = xorShiftBytes(aPBytes, sharedKey);

                // Extract the ACK Packet's Sequence Number
                ackPackSeqNum = ackPack[3];

                writeReqPackBuffer.clear();
                ackPackBuffer.clear();
                
                // Check to see if the ACK's Sequence Number is 0
                if(ackPack[1] == 4 && ackPackSeqNum == 0)
                {
                    // Find where the file is on the client's machine
                    Path filePath = Paths.get(filenameStr);
                    
                    // Turn the file to be transferred into a sequence of bytes
                    fileBytes = Files.readAllBytes(filePath.toAbsolutePath());

                    if(willDropPackets == 'Y')
                    {
                        packetsToSend = Math.ceilDiv(fileBytes.length, 512);
                        packetsToSend1Per = (int) (Math.round(packetsToSend / 100));

                        for(int i = 0; i < packetsToSend1Per; i++)
                        {
                            randNum = random.nextInt((int) (packetsToSend) - 1) + 1;

                            if(!(randPacketsToDrop.containsKey(randNum)))
                            {
                                randPacketsToDrop.put(randNum, randNum);
                            }

                            else
                            {
                                i--;
                            }
                        }
                    }

                    // Start the timer immediately before sending the message and the random key to the server
                    startTime = System.nanoTime();
                    
                    // Write the Opcode and the Sequence Number to the Data Packet
                    dataPackOutStream = new ByteArrayOutputStream(dataPackLen);

                    if(willDropPackets == 'Y' && randPacketsToDrop.containsKey(packetCounter))
                    {
                        dataPackOutStream.write('Y');
                    }

                    else
                    {
                        dataPackOutStream.write(0);
                    }

                    dataPackOutStream.write(DATA_OPCODE);
                    dataPackOutStream.write(0);

                    // Increase the Sequence Number to 1
                    dataPackSeqNum = (byte) (ackPackSeqNum + 1);
                    dataPackOutStream.write(dataPackSeqNum);
                    
                    for(int i = 0; i < fileBytes.length; i++)
                    {
                        // Write each byte of the file individually until you reach 512 bytes
                        dataPackOutStream.write(fileBytes[i]);
                        byteCounter++;

                        // If it's time to send the Data Packet
                        if((i != 0 && byteCounter == 512) || i == fileBytes.length - 1)
                        {
                            if(!(hasWindowStarted))
                            {
                                if(wsCounter == windowSize || i == fileBytes.length - 1)
                                {
                                    // Create the Data Packet and encrypt it
                                    dataPack = dataPackOutStream.toByteArray();
                                    encryptedDataPack = xorShiftBytes(dataPack, sharedKey);

                                    // Send the Data Packet to the server and wait for the ACK Packet
                                    dataPackBuffer = ByteBuffer.wrap(encryptedDataPack);

                                    client.send(dataPackBuffer, serverAddress);

                                    selector.selectedKeys().clear();
                                    numKeys = selector.select(10);

                                    if(numKeys == 0)
                                    {
                                        selector.selectedKeys().clear();
                                        numKeys = selector.select(1000000);
                                        client.receive(ackPackBuffer);
                                    }

                                    else
                                    {
                                        client.receive(ackPackBuffer);
                                    }

                                    // Decrypt the ACK Packet
                                    ackPackBuffer.flip();
                                    aPLimits = ackPackBuffer.limit();
                                    aPBytes = new byte[aPLimits];
                                    ackPackBuffer.get(aPBytes, 0, aPLimits);
                                    ackPack = xorShiftBytes(aPBytes, sharedKey);

                                    // Extract the ACK Packet's Sequence Number
                                    ackPackSeqNum = ackPack[3];

                                    // Check that the ACK's Sequence Number matches the Sequence Number of the last Data Packet sent
                                    if(ackPack[1] == 4 && ackPackSeqNum == 1)
                                    {
                                        dataPack = null;
                                        dataPackBuffer.clear();
                                        ackPackBuffer.clear();

                                        // Reset the byte counter
                                        byteCounter = 0;
                                        packetCounter++;
                                        hasWindowStarted = true;

                                        // Start creating the next Data Packet
                                        dataPackOutStream = new ByteArrayOutputStream(dataPackLen);

                                        if(willDropPackets == 'Y' && randPacketsToDrop.containsKey(packetCounter))
                                        {
                                            dataPackOutStream.write('Y');
                                        }

                                        else
                                        {
                                            dataPackOutStream.write(0);
                                        }

                                        dataPackOutStream.write(DATA_OPCODE);
                                        dataPackOutStream.write(0);

                                        // Update the Sequence Number
                                        dataPackSeqNum = (byte) (dataPackSeqNum + 1);
                                        dataPackOutStream.write(dataPackSeqNum);
                                    }

                                    // If the Sequence Number is out of order
                                    else
                                    {
                                        System.out.println("***FATAL ERROR!***");
                                        break;
                                    }
                                }

                                else
                                {
                                    packetCounter++;

                                    // Start creating the next Data Packet
                                    if(willDropPackets == 'Y' && randPacketsToDrop.containsKey(packetCounter))
                                    {
                                        dataPackOutStream.write('Y');
                                    }

                                    else
                                    {
                                        dataPackOutStream.write(0);
                                    }

                                    dataPackOutStream.write(DATA_OPCODE);
                                    dataPackOutStream.write(0);

                                    // Update the Sequence Number
                                    dataPackSeqNum = (byte) (dataPackSeqNum + 1);
                                    dataPackOutStream.write(dataPackSeqNum);

                                    wsCounter++;
                                    byteCounter = 0;
                                }
                            }

                            else
                            {
                                // Create the Data Packet and encrypt it
                                dataPack = dataPackOutStream.toByteArray();
                                encryptedDataPack = xorShiftBytes(dataPack, sharedKey);

                                // Send the Data Packet to the server and wait for the ACK Packet
                                dataPackBuffer = ByteBuffer.wrap(encryptedDataPack);

                                client.send(dataPackBuffer, serverAddress);

                                selector.selectedKeys().clear();
                                numKeys = selector.select(10);

                                if(numKeys == 0)
                                {
                                    selector.selectedKeys().clear();
                                    numKeys = selector.select(1000000);
                                    client.receive(ackPackBuffer);
                                }

                                else
                                {
                                    client.receive(ackPackBuffer);
                                }

                                // Decrypt the ACK Packet
                                ackPackBuffer.flip();
                                aPLimits = ackPackBuffer.limit();
                                aPBytes = new byte[aPLimits];
                                ackPackBuffer.get(aPBytes, 0, aPLimits);
                                ackPack = xorShiftBytes(aPBytes, sharedKey);

                                // Extract the ACK Packet's Sequence Number
                                ackPackSeqNum = ackPack[3];

                                // Check that the ACK's Sequence Number matches the Sequence Number of the last Data Packet sent
                                if(ackPack[1] == 4)
                                {
                                    dataPack = null;
                                    dataPackBuffer.clear();
                                    ackPackBuffer.clear();

                                    // Reset the byte counter
                                    byteCounter = 0;
                                    packetCounter++;

                                    // Start creating the next Data Packet
                                    dataPackOutStream = new ByteArrayOutputStream(dataPackLen);

                                    if(willDropPackets == 'Y' && randPacketsToDrop.containsKey(packetCounter))
                                    {
                                        dataPackOutStream.write('Y');
                                    }

                                    else
                                    {
                                        dataPackOutStream.write(0);
                                    }

                                    dataPackOutStream.write(DATA_OPCODE);
                                    dataPackOutStream.write(0);

                                    // Update the Sequence Number
                                    dataPackSeqNum = (byte) (dataPackSeqNum + 1);
                                    dataPackOutStream.write(dataPackSeqNum);
                                }

                                // If the Sequence Number is out of order
                                else
                                {
                                    System.out.println("***FATAL ERROR!***");
                                    break;
                                }
                            }
                        }
                    }

                    System.out.println("File Transferred Successfully!");
                }
            }

            // If the user doesn't choose either a Read or Write Request
            else
            {
                System.out.println("***THAT OPERATION IS NOT SUPPORTED!***");
            }

            totalTime = (System.nanoTime() - startTime) / 1000000.0;
            throughput = 302329 / totalTime;
            throughput = throughput * 8;

            System.out.println(throughput);

            /////////////////////// Resetting All Variables Back to their Default Values ////////////////////////////////

            file = null;

            requestType     = "";      
            filename        = null;   
            filenameStr     = "";    
            mode            = null;    
            modeStr         = "octet"; 
            windowSize      = 0;
            wsCounter       = 1;
            willDropPackets = ' ';

            reqPackLen       = 0;    
            reqPackOutStream = null; 

            readReqPack          = null; 
            encryptedReadReqPack = null; 
            readReqPackBuffer    = null; 

            writeReqPack          = null;
            encryptedWriteReqPack = null; 
            writeReqPackBuffer    = null; 

            ackPack          = null; 
            encryptedAckPack = null;
            ackPackSeqNum    = 0;    
            aPLimits         = 0;
            aPBytes          = null;
            ackPackBuffer    = ByteBuffer.allocate(2048);
            ackPackOutStream = null; 
            
            dataPack          = null;
            newDataPack       = null;
            encryptedDataPack = null;
            dataPackSeqNum    = 0;    
            data              = null; 
            dPLimits          = 0;
            dPBytes           = null;
            dataPackBuffer    = ByteBuffer.allocate(65536);
            dataPackOutStream = null; 

            fileBytes         = null; 
            packetsToSend     = 0;
            packetsToSend1Per = 0;
            randPacketsToDrop = new HashMap<>();;
            randNum           = 0;
            packetCounter     = 1;
            byteCounter       = 0;    
            numKeys = 0;  
        }
    }
    
    // Method to perform XOR Shift on a byte array
    public static byte[] xorShiftBytes(byte[] bytes, long sharedKey)
    {
        for(int i = 0; i < bytes.length; i++)
        {
            bytes[i] ^= sharedKey << 13;
            bytes[i] ^= sharedKey >>> 7;
            bytes[i] ^= sharedKey << 17;
        }

        return bytes;
    }

    // Method to perform XOR Shift on a string
    public static String xorShiftString(String message, long sharedKey)
    {
        char[] messageC = message.toCharArray();
        int keyCounter = 0;

        for(int i = 0; i < messageC.length; i++)
        {
            messageC[i] ^= sharedKey << 13;
            messageC[i] ^= sharedKey >>> 7;
            messageC[i] ^= sharedKey << 17;

            keyCounter += 2;

            if(keyCounter % 64 == 0)
            {
                sharedKey = xorShiftLong(sharedKey);
            }
        }

        return new String(messageC);
    }

    // Method to perform XOR Shift on a long
    public static long xorShiftLong(long l)
    {
        l ^= l << 13; 
        l ^= l >>> 7; 
        l ^= l << 17; 
        return l;
    }
}
