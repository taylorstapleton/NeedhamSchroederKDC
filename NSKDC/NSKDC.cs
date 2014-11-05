using System.Web;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace NSKDC
{
    class NSKDC
    {
        static void Main(string[] args)
        {
            bool useCBC = true;
            byte[] IV = new byte[] { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7 };
            byte[] key = new byte[] { 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7 };
            byte[] aliceKey = new byte[] {0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7 };

            string response = StartListening("asdf", IV, key, aliceKey, useCBC);
            Console.WriteLine("kdc recieves N1, \"Alice Wants Bob\", Kbob{Nb}");
            Console.WriteLine("kdc sends N1, \"Bob\", shared Key, and a ticket to Bob");
        }
        
        /// <summary>
        /// performs the socket communication. sends one message, recieves one message.
        /// </summary>
        /// <param name="toSend"></param>
        /// <returns></returns>
        public static string StartListening(string toSend, byte[] IV, byte[] key, byte[] keyAlice, bool useCBC)
        {

            string data = null;
            string toReturn = null;

            // Data buffer for incoming data.
            byte[] bytes = new Byte[1024];


            IPAddress addr = IPAddress.Loopback;

            IPEndPoint localEndPoint = new IPEndPoint(addr, 12000);

            // Create a TCP/IP socket.
            Socket listener = new Socket(AddressFamily.InterNetwork,
                SocketType.Stream, ProtocolType.Tcp);

            // Bind the socket to the local endpoint and 
            // listen for incoming connections.
            try
            {
                listener.Bind(localEndPoint);
                listener.Listen(10);

                // Program is suspended while waiting for an incoming connection.
                Socket handler = listener.Accept();
                data = null;

                // An incoming connection needs to be processed.
                while (true)
                {
                    bytes = new byte[1024];
                    int bytesRec = handler.Receive(bytes);
                    //data += Encoding.ASCII.GetString(bytes, 0, bytesRec);
                    data += getString(bytes);
                    if (data.IndexOf("<EOF>") > -1)
                    {
                        data = data.Substring(0, data.IndexOf("<EOF>"));
                        break;
                    }
                }

                string[] messageArray = data.Split(new string[]{"987654321"}, StringSplitOptions.None);

                toReturn = Decrypt(messageArray[1], key, IV, useCBC);

                string sharedKey = getSharedKey();

                // construct message to send
                string ticketMessage = sharedKey + "987654321" + toReturn;

                string ticket = encryptMessage(key, IV, getBytes(ticketMessage), useCBC);

                string firstPart = encryptMessage(keyAlice, IV, getBytes(messageArray[0] + "987654321" + sharedKey + "987654321" + ticket), useCBC);

                toSend = firstPart;

                //handler.Send(Encoding.ASCII.GetBytes(toSend + "<EOF>"));
                handler.Send(getBytes(toSend + "<EOF>"));
                handler.Shutdown(SocketShutdown.Both);
                handler.Close();


            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }

            return data;
        }


        public static string Decrypt(string cipherBlock, byte[] key, byte[] IV, bool useCBC)
        {
            byte[] toEncryptArray = getBytes(cipherBlock);

            // Set the secret key for the tripleDES algorithm
            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Key = key;
            tdes.IV = IV;
            tdes.Mode = CipherMode.CBC;
            tdes.Padding = PaddingMode.Zeros;

            ICryptoTransform cTransform = tdes.CreateDecryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
            tdes.Clear();

            // Return the Clear decrypted TEXT
            return getString(resultArray);
        }

        public static string getString(byte[] bytes)
        {
            char[] chars = new char[bytes.Length / sizeof(char)];
            System.Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
            return new string(chars);
            
        }

        public static byte[] getBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        public static string getSharedKey()
        {
            byte[] bytes = new byte[] {0x4, 0x3, 0x2, 0x1, 0x4, 0x3, 0x2, 0x1, 0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4};

            return getString(bytes);
        }

        public static string encryptMessage(byte[] key, byte[] IV, byte[] message, bool useCBC)
        {
            byte[] keyBytes = key; // UTF8Encoding.UTF8.GetBytes(key);
            byte[] messageBytes = message;   //UTF8Encoding.UTF8.GetBytes(message);
            byte[] ivBytes = IV; // UTF8Encoding.UTF8.GetBytes(IV);

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Key = keyBytes;
            tdes.IV = ivBytes;
            if (useCBC)
            {
                tdes.Mode = CipherMode.CBC;
            }
            else
            {
                tdes.Mode = CipherMode.ECB;
            }
            tdes.Padding = PaddingMode.Zeros;

            ICryptoTransform encryptor = tdes.CreateEncryptor();

            byte[] encResult = encryptor.TransformFinalBlock(messageBytes, 0, messageBytes.Length);

            tdes.Clear();

            string toReturn = getString(encResult);
            byte[] test = getBytes(toReturn);
            return toReturn;

        }
       


    }
}
