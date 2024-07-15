import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Random;

public class TFTPServer 
{
    public static void main(String[] args) throws Exception 
    {
        /////////////////////// Starting the Server ////////////////////////////////

        String host = "localhost"; // The name of the server
        int port    = 26931;       // The port that will be accessed on the server

        Selector selector = Selector.open();
        DatagramChannel server = DatagramChannel.open();
        InetSocketAddress iAdd = new InetSocketAddress(host, port);
        server.bind(iAdd);
        server.configureBlocking(false);
        server.register(selector, SelectionKey.OP_READ);
        System.out.println("Client Connected");

        /////////////////////// Creating the Shared Secret Key ////////////////////////////////

        // Receive the client's sender ID
        ByteBuffer senderIDBuffer = ByteBuffer.allocate(2048);
        selector.selectedKeys().clear();
        selector.select(1000000);
        SocketAddress remoteAdd = server.receive(senderIDBuffer);

        senderIDBuffer.flip();
        int sKLimits = senderIDBuffer.limit();
        byte sKBytes[] = new byte[sKLimits];
        senderIDBuffer.get(sKBytes, 0, sKLimits);
        String sKey = new String(sKBytes, "ISO-8859-1");
        long senderID = Long.parseLong(sKey);

        System.out.println("Client's Sender ID: " + senderID);
        
        senderIDBuffer.flip();
        server.send(senderIDBuffer, remoteAdd);

        // Generate the random key for the server
        Random random  = new Random();
        long serverKey = random.nextLong();
        long clientKey = 0;

        // Receive the client's key
        ByteBuffer clientKeyBuffer = ByteBuffer.allocate(2048);
        selector.selectedKeys().clear();
        selector.select(1000000);
        remoteAdd = server.receive(clientKeyBuffer);

        clientKeyBuffer.flip();
        int cKLimits = clientKeyBuffer.limit();
        byte cKBytes[] = new byte[cKLimits];
        clientKeyBuffer.get(cKBytes, 0, cKLimits);
        String cKey = new String(cKBytes, "ISO-8859-1");
        clientKey = Long.parseLong(cKey);

        // Send the server's key to the client
        ByteBuffer serverKeyBuffer = ByteBuffer.wrap(String.valueOf(serverKey).getBytes("ISO-8859-1"));
        server.send(serverKeyBuffer, remoteAdd);

        // XOR the two keys together to create a shared encrypting/decrypting key
        long sharedKey = clientKey ^ serverKey;

        /////////////////////// Local Constants and Variables Needed For TFTP ////////////////////////////////

        // Opcodes for different Packet types (Read Requests, Write Requests, Data, and ACK)
        final byte READ_REQUEST_OPCODE  = 1;
	    final byte WRITE_REQUEST_OPCODE = 2;
	    final byte DATA_OPCODE          = 3;
        final byte ACK_OPCODE           = 4;

        Path file = null;

        byte[] reqPack           = null; // Request Packet
        int rPLimits             = 0;
        byte[] rPBytes           = null;
        ByteBuffer reqPackBuffer = ByteBuffer.allocate(2048);

        byte opcode              = 0;             // Opcode of the Request Packet
        byte[] filename          = new byte[512]; // The name of the file to be transferred as a byte array
        int filenameLen          = 0;             // The length of the file's name
        String filenameStr       = "";            // The name of the file to be transferred as a string
        int windowSize           = 0;
        int wsCounter            = 1;
        boolean hasWindowStarted = false;
        int willDropPackets      = 0;

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
        int numKeys = 0;

        /////////////////////// Starting TFTP ////////////////////////////////

        while(true)
        {
            // Receive the Request Packet from the Client
            selector.selectedKeys().clear();
            selector.select(1000000);
            remoteAdd = server.receive(reqPackBuffer);

            // Decrypt the Request Packet
            reqPackBuffer.flip();
            rPLimits = reqPackBuffer.limit();
            rPBytes = new byte[rPLimits];
            reqPackBuffer.get(rPBytes, 0, rPLimits);
            reqPack = xorShiftBytes(rPBytes, sharedKey);

            // Extract the Opcode from the Request Packet
            opcode = reqPack[1];
            
            // Extract the name of the file from the Request Packet
            for(int i = 2; i < reqPack.length; i++)
            {
                if(reqPack[i] != 0)
                {
                    filenameLen++;
                }

                else
                {
                    filename = new byte[filenameLen];

                    for(int j = 2; j < filenameLen + 2; j++)
                    {
                        filename[j - 2] = reqPack[j];
                    }

                    filenameLen = 0;

                    break;
                }
            }

            filenameStr = new String(filename, "ISO-8859-1");
            
            reqPackBuffer.clear();

            // If the Opcode is 1 (Read Request)
            if(opcode == READ_REQUEST_OPCODE)
            {
                windowSize = reqPack[reqPack.length - 2];
                willDropPackets = reqPack[reqPack.length - 1];

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

                                server.send(dataPackBuffer, remoteAdd);

                                selector.selectedKeys().clear();
                                numKeys = selector.select(10);

                                if(numKeys == 0)
                                {
                                    selector.selectedKeys().clear();
                                    numKeys = selector.select(1000000);
                                    remoteAdd = server.receive(ackPackBuffer);
                                }

                                else
                                {
                                    remoteAdd = server.receive(ackPackBuffer);
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

                            server.send(dataPackBuffer, remoteAdd);

                            selector.selectedKeys().clear();
                            numKeys = selector.select(10);

                            if(numKeys == 0)
                            {
                                selector.selectedKeys().clear();
                                numKeys = selector.select(1000000);
                                remoteAdd = server.receive(ackPackBuffer);
                            }

                            else
                            {
                                remoteAdd = server.receive(ackPackBuffer);
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

            // If the Opcode is 2 (Write Request)
            else if(opcode == WRITE_REQUEST_OPCODE)
            {
                // Create the ACK Packet
                ackPackOutStream = new ByteArrayOutputStream(ackPackLen);
                ackPackOutStream.write(0);
                ackPackOutStream.write(ACK_OPCODE);
                ackPackOutStream.write(0);
                ackPackOutStream.write(ackPackSeqNum);

                // Encrypt the ACK Packet
                ackPack = ackPackOutStream.toByteArray();
                encryptedAckPack = xorShiftBytes(ackPack, sharedKey);

                // Send the ACK Packet to the client and wait for the first Data Packet
                ackPackBuffer = ByteBuffer.wrap(encryptedAckPack);
                server.send(ackPackBuffer, remoteAdd);

                // Create a new file with the specified name to be written to
                file = Paths.get("C:/Users/jackh/Downloads/Networks Stuff/Assignment_2/Temp/" + filenameStr);
                Files.createFile(file);

                // Receive the Data Packets from the client
                selector.selectedKeys().clear();
                selector.select(1000000);
                remoteAdd = server.receive(dataPackBuffer);

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
                        server.send(ackPackBuffer, remoteAdd);

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
                        remoteAdd = server.receive(dataPackBuffer);

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
                            server.send(ackPackBuffer, remoteAdd);

                            dataPackBuffer.clear();
                            ackPackBuffer.clear();

                            selector.selectedKeys().clear();
                            selector.select(1000000);
                            remoteAdd = server.receive(dataPackBuffer);

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

            /////////////////////// Resetting All Variables Back to their Default Values ////////////////////////////////

            file = null;

            reqPack       = null; 
            rPLimits      = 0;
            rPBytes       = null;
            reqPackBuffer = ByteBuffer.allocate(2048);

            opcode          = 0;             
            filename        = new byte[512]; 
            filenameLen     = 0;             
            filenameStr     = "";  
            windowSize      = 0;
            wsCounter       = 1;   
            willDropPackets = 0;       

            ackPack          = null; 
            encryptedAckPack = null;
            ackPackSeqNum    = 0;    
            aPLimits         = 0;
            aPBytes          = null;
            ackPackBuffer    = ByteBuffer.allocate(2048);
            ackPackOutStream = null; 

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
