
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Random;
import java.util.TreeMap;

class Client {
    int id;
    protected byte[] privateKey;
    protected Session currentSession;

    public Client(int id, byte[] privateKey) {
        this.id = id;
        this.privateKey = privateKey;
    }

    long getTime()
    {
        return System.currentTimeMillis();
    }

    int generateNonce()
    {
        return new Random().nextInt();
    }

    void initiateSession(MessageBody fromClient, MessageBody fromServer, Client partner) throws Exception
    {
        MessageBody decryptedMessageFromServer = Message.decryptMessage(fromServer,this.privateKey);
        MessageBody decryptedMessageFromPartner = Message.decryptMessage(fromClient, decryptedMessageFromServer.sessionKey);

        if(decryptedMessageFromPartner.identity != decryptedMessageFromServer.identity)
            throw new IllegalStateException("Idendity doesn't match");

        if(decryptedMessageFromServer.T <= getTime())
            throw new IllegalStateException("Lifetime from server is invalid");

        if(decryptedMessageFromPartner.T >= decryptedMessageFromServer.T)
            throw new IllegalStateException("Timestamp from client is invalid");

        this.currentSession = new Session(decryptedMessageFromServer.sessionKey,partner, decryptedMessageFromServer.T);
    }

    void checkCurrentSession(Client client)
    {
        if(currentSession == null)
            throw new IllegalStateException("Session isn't initiated");

        if(currentSession.partner != client)
            throw new IllegalStateException("Session partner isn't the same");
    }

    void receivesData(MessageBody data, Client sender) throws Exception
    {
        checkCurrentSession(sender);

        MessageBody decryptedMessage = Message.decryptMessage(data, this.currentSession.key);
        parseData(decryptedMessage, sender);
    }

    void initiateSessionWith(Client receiver, Server server) throws Exception
    {
        int nonce = generateNonce();
        long timestamp = getTime();

        Response response = server.request(this.id, receiver.id, nonce);
        MessageBody messageFromServer = Message.decryptMessage(response.messageA, privateKey);

        if(messageFromServer.nonce != nonce)
            throw new IllegalStateException("Nonce isn't equal");

        if(messageFromServer.identity != receiver.id)
            throw new IllegalStateException("Identity isn't equal");

        if(messageFromServer.T <timestamp)
            throw new IllegalStateException("Lifetime isn't valid");


        this.currentSession = new Session(messageFromServer.sessionKey, receiver, messageFromServer.T);

        MessageBody sessionInitiatioMessage = Message.encryptMessage(
                new MessageBody(null, 0, timestamp, this.id, null), currentSession.key
        );

        receiver.initiateSession(sessionInitiatioMessage, response.messageB, this);
    }


    void sendsDataTo(Client receiver, MessageBody data) throws Exception {
        checkCurrentSession(receiver);

        MessageBody encryptedData = Message.encryptMessage(data, this.currentSession.key);
        receiver.receivesData(encryptedData, this);
    }

    void parseData(MessageBody data, Client sender) throws Exception
    {
        System.out.println("Client ID: " + this.id + " received message from " + sender.id);
        System.out.println(new String(data.data, "UTF-8"));
    }
}

/*
    A session object that represents an initiated session (has a negotiated session key) with another side.

 */
final class Session {
    byte[] key;
    Client partner;
    long T;

    public Session(byte[] key, Client partner, long t) {
        this.key = key;
        this.partner = partner;
        T = t;
    }
}

/*
    The object that is passed between the clients. The object is generalized and some of the
    variables are not always used. When a variable is not applicable, it is ignored from the receiving side and nullified from
    the sending side.

    If the message is encrypted, it is serialized (together with the other attributes) and placed into the @data attribute of the object.
    The rest attributes are nullified, unless they need to be in plain format.

    If some of the attributes must be in plain format, they can be entered as so.
 */
class MessageBody implements Serializable{
    byte[] sessionKey;
    int nonce;
    long T;

    public MessageBody(byte[] sessionKey, int nonce, long t, int identity, byte[] data) {
        this.sessionKey = sessionKey;
        this.nonce = nonce;
        T = t;
        this.identity = identity;
        this.data = data;
    }

    int identity;
    byte[] data;
}



/*
    Class that implements the encryption and decryption of messages.
    The MessageBody object is first serialized to a byte[] object, and then the byte[] is encrypted.
    The decryption process is inverted.
 */
class Message {
    protected static Cipher encryptCipher;
    protected static Cipher decryptCipher;

    static MessageBody toMessage(byte[] stream) throws Exception
    {
        MessageBody message = null;
        ByteArrayInputStream bais = new ByteArrayInputStream(stream);
        ObjectInputStream ois = new ObjectInputStream(bais);
        try {
            message = (MessageBody) ois.readObject();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return message;
    }

    static byte[] toStream(MessageBody message) throws Exception
    {
        byte[] stream = null;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        try {
            oos.writeObject(message);
            stream = baos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return stream;
    }

    static MessageBody decryptMessage(MessageBody m, byte[] key) throws Exception {
        if(decryptCipher == null) {
            Message.decryptCipher = Cipher.getInstance("AES");
            decryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
        }

        byte[] decryptedStream = decryptCipher.doFinal(m.data);

        MessageBody decrypted = Message.toMessage(decryptedStream);
        return decrypted;
    }

    static MessageBody encryptMessage(MessageBody m, byte[] key) throws Exception {
        if(encryptCipher == null)
        {
            Message.encryptCipher = Cipher.getInstance("AES");
            encryptCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key,"AES"));
        }

        byte[] stream = Message.toStream(m);
        return new MessageBody(null ,0, 0, 0, encryptCipher.doFinal(stream));
    }

}

/*
    Subclass that represents plain unencrypted data.
 */
class PlainData extends MessageBody
{
    public PlainData(byte[] data) {
        super(null, 0, 0, 0, data);
    }
}

final class Response {
    public Response(MessageBody messageA, MessageBody messageB) {
        this.messageA = messageA;
        this.messageB = messageB;
    }

    final MessageBody messageA;
    final MessageBody messageB;

}

class Server {
    protected TreeMap<Integer, byte[]> keys = new TreeMap<Integer, byte[]>();
    SecureRandom random = new SecureRandom();

    public void addKey(int identity, byte[] key){
        keys.put(identity, key);
    }

    long getTime()
    {
        return System.currentTimeMillis();
    }

    public Client newClient()
    {
        int id = this.random.nextInt(100000);
        byte[] key = new byte[16];
        this.random.nextBytes(key);
        Client client = new Client(id, key);
        this.addKey(id, key);
        return client;
    }


    public Response request(int identityA, int identityB, int nonce) throws Exception
    {
        byte[] sessionKey = new byte[16];
        random.nextBytes(sessionKey);
        long time = getTime() + 100000;

        byte[] keyA = this.keys.get(identityA);
        byte[] keyB = this.keys.get(identityB);

        MessageBody messageA = new MessageBody(sessionKey, nonce,time, identityB, null);
        MessageBody messageB = new MessageBody(sessionKey, 0, time, identityA, null);

        return new Response(Message.encryptMessage(messageA, keyA), Message.encryptMessage(messageB, keyB));

    }
}

public class Kerberos {
    public static void main(String args[]) throws Exception
    {
        Server server = new Server();
        Client alice = server.newClient();
        Client bob = server.newClient();

        alice.initiateSessionWith(bob, server);
        Thread.sleep(100);
        alice.sendsDataTo(bob, new PlainData("test poraka".getBytes()));
        Thread.sleep(100);
        bob.sendsDataTo(alice, new PlainData("odgovor na porakata".getBytes()));


    }

}
