using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace cs432_project_server
{
    public partial class Form1 : Form
    {
        Socket serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        List<Socket> clientSockets = new List<Socket>();
        List<string> clientList = new List<string>();
        //List<string> clientPubKeys = new List<string>();
        //List<string> clientSessionKeys = new List<string>();

        bool terminating = false;
        bool listening = false;
        string location;
        string privateKey;
        //string username;

        public Form1()
        {
            Control.CheckForIllegalCrossThreadCalls = false;
            this.FormClosing += new FormClosingEventHandler(Form1_FormClosing);
            InitializeComponent();
        }

        private void Form1_FormClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            listening = false;
            terminating = true;
            Environment.Exit(0);
        }

        private void Accept()
        {
            while (listening)
            {
                try
                {
                    Socket newClient = serverSocket.Accept();
                    clientSockets.Add(newClient);
                    //logs.AppendText("A user connected!");

                    Thread nameCheckThread = new Thread(() => Connection(newClient));
                    nameCheckThread.Start();
                }
                catch
                {
                    if (terminating)
                    {
                        listening = false;
                    }
                    else
                    {
                        logs.AppendText("The socket stopped working.\n");
                    }
                }
            }
        }

        private void Connection(Socket thisClient)
        {
            string clientName = "";
            bool connected = true;

            // Waits for client to send username
            while (connected && !terminating && clientName == "")
            {
                Byte[] buffer = new Byte[64];
                thisClient.Receive(buffer);

                clientName = Encoding.Default.GetString(buffer);
                clientName = clientName.Substring(0, clientName.IndexOf("\0"));

                if (clientList.Contains(clientName)) // if username already exists
                {
                    Byte[] responseBuffer = new Byte[64]; // sends negative response
                    responseBuffer = Encoding.Default.GetBytes("Invalid Username");
                    logs.AppendText("A client tried to connect with an invalid username.\n");
                    thisClient.Send(responseBuffer);

                }

                else if (clientName != "") // if username does not exist (checks if empty or not)
                {
                    Byte[] responseBuffer = new Byte[64]; // sends positive response
                    responseBuffer = Encoding.Default.GetBytes("Valid Username");
                    thisClient.Send(responseBuffer);
                    /* Starts Listenning the Client */
                    logs.AppendText(clientName + " is connected.\n");
                    logs.AppendText("Current Client List:\n");
                    clientList.Add(clientName);
                    foreach (string user in clientList)
                    {
                        logs.AppendText("   "+ user + "\n");
                    }
                    

                    try
                    {
                        Authentication(thisClient, clientName);
                    }
                    catch
                    {
                        logs.AppendText("An Error Occured Druing Challenge-Response Protocol with client " + clientName + "!\n");
                        thisClient.Close();
                    }                   
                }
            }
        }

        private void Authentication(Socket thisClient, string clientName)
        {
            

            //sending random 128-bit nonce to user
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            byte[] random128num = new byte[16];
            rngCsp.GetBytes(random128num);
            thisClient.Send(random128num);
            string nonce = Encoding.Default.GetString(random128num);
            logs.AppendText("128-bit random value has been sent to client " + clientName + "\n");
            logs.AppendText(generateHexStringFromByteArray(random128num) + "\n" + "Number size: " + random128num.Length + "\n");

            //receiving signed nonce
            byte[] signed_nonce = new byte[512];
            thisClient.Receive(signed_nonce);
            //string signed_nonce_string = Encoding.Default.GetString(signed_nonce).Trim('\0');
            logs.AppendText("Signature of the client " + clientName + " over 128-bit random value has been received\n");
            logs.AppendText(generateHexStringFromByteArray(signed_nonce) + "\n" + "Signde Nonce size: " + signed_nonce.Length + "\n");

            //getting public key of that client
            string pubKeyClient;
            string pubPath = location + "\\" + clientName + "_pub.txt";
            using (System.IO.StreamReader fileReader =
            new System.IO.StreamReader(pubPath))
            {
                pubKeyClient = fileReader.ReadLine();
            }

            //adding public key of the client to pubkeys list
            //clientPubKeys.Add(pubKeyClient);
            byte[] pubKeyClient_byte = Encoding.Default.GetBytes(pubKeyClient);
            logs.AppendText("RSA public key of client " + clientName + "\n");
            logs.AppendText(generateHexStringFromByteArray(pubKeyClient_byte) + "\n" + "size: " + pubKeyClient_byte.Length + "\n");


            if (verifyWithRSA(nonce, 4096, pubKeyClient, signed_nonce))
            {
                logs.AppendText("Signature of the client " + clientName + " over the 128-bit random value has been verified\n");

                byte[] HMAC_Key = new byte[32];
                rngCsp.GetBytes(HMAC_Key);//random HMAC session key value set
                string hmac_key_string = Encoding.Default.GetString(HMAC_Key);
                //clientSessionKeys.Add(hmac_key_string);//adding the sesh key with the client to memory
                logs.AppendText("HMAC Session Key\n");
                logs.AppendText(generateHexStringFromByteArray(HMAC_Key) + "\n" + " HMAC Key size: " + HMAC_Key.Length + "\n");

                //encrypting the HMAC session key with the public key of the client
                byte[] encrypted_session_key_byte = encryptWithRSA(hmac_key_string, 4096, pubKeyClient);
                string encrypted_session_key_string = Encoding.Default.GetString(encrypted_session_key_byte);
                logs.AppendText("Encrypted HMAC Session Key\n");
                logs.AppendText(generateHexStringFromByteArray(encrypted_session_key_byte) + "\n" + "Encrypted HMAC Key size: " + encrypted_session_key_byte.Length + "\n");

                //appending the positive acknowledgement message to encypted HMAC session key
                string positive_ack = "POS_ACK";
                string message = encrypted_session_key_string + positive_ack;
                byte[] message_byte = Encoding.Default.GetBytes(message);


                //signature of the server over message
                string privateKey_string = privateKey;
                byte[] message_signed = signWithRSA(message, 4096, privateKey_string);

                //Sends encr(hmac_key) + ack
                thisClient.Send(message_byte);
                logs.AppendText("Sended encr(hmac_key) + ack to client " + clientName + "\n");
                logs.AppendText(generateHexStringFromByteArray(message_byte) + "\n" + "Encrypted HMAC Key + ACK size: " + message_byte.Length + "\n");

                //Sends signed(encr(hmac_key)+ack)
                thisClient.Send(message_signed);
                logs.AppendText("Sended signature over (encr(hmac_key) + ack) to client " + clientName + "\n");
                logs.AppendText(generateHexStringFromByteArray(message_signed) + "\n" + "Signature size: " + message_signed.Length + "\n");
                logs.AppendText("Client " + clientName + " has authanticated to the server\n");
                //Sends 
                Receive(thisClient, clientName, pubKeyClient, hmac_key_string);
            }
            else
            {
                //Sends ack
                string negative_ack = "NEG_ACK";
                byte[] message = Encoding.Default.GetBytes(negative_ack);
                thisClient.Send(message);

                //Sends sign(ack)
                string privateKey_string = privateKey;
                byte[] message_signature = signWithRSA(negative_ack, 4096, privateKey_string);
                thisClient.Send(message);

                logs.AppendText("Signature of the client " + clientName + " over the 128-bit random value could not verified\n");
                //thisClient.Close();

            }
        }
        private void Receive(Socket thisClient, string username, string pubKeyClient, string sessionKey)
        {
            bool connected = true;

            while (connected && !terminating)
            {
                string request_string;
                try
                {
                    // Receive the operation information
                    Byte[] receivedInfoHeader = new Byte[1];
                    thisClient.Receive(receivedInfoHeader);

                    if (receivedInfoHeader[0] == 0)
                    {
                        // Receive the incoming File's name and size
                        Byte[] fileProperties = new byte[256]; // First 128 Bytes are for Name, Last 128 for Size
                        thisClient.Receive(fileProperties); // Receive the Buffer

                        // Take the file name from the buffer
                        string fileName = Encoding.Default.GetString(fileProperties.Take(128).ToArray());

                        // Format the file name
                        fileName = fileName.Substring(0, fileName.IndexOf("\0"));
                        fileName = username + "_0"; // incremental seyi eklenecek
                        string fileName_basic = fileName;


                        // Read the LOGS.txt file to determine the final file name
                        int denemecount = 0;
                        bool deneme = false;
                        while (!deneme)
                        {
                            if (File.Exists(textBox_repository + "/" + fileName_basic))
                            {
                                denemecount++;
                                fileName_basic = fileName.Split('_')[0] + "_" + denemecount.ToString();
                            }
                            else
                            {
                                deneme = true;
                            }
                        }



                        // Take the file size from buffer
                        int fileSize = Int32.Parse(Encoding.Default.GetString(fileProperties.Skip(128).Take(128).ToArray()));


                        // Get the encrypted file 
                        Byte[] bufferEncrypted = new Byte[fileSize]; // The buffer size is allocated by the file size
                        thisClient.Receive(bufferEncrypted);
                        string enc_string = Encoding.Default.GetString(bufferEncrypted);
                        enc_string = enc_string.Substring(0, enc_string.IndexOf("\0"));

                        logs.AppendText("Recieved encrypted file is: \n");
                        logs.AppendText(enc_string + "\n");


                        // Get the HMAC 
                        Byte[] bufferHMAC = new Byte[fileSize]; // The buffer size is allocated by the file size
                        thisClient.Receive(bufferHMAC);
                        string hmac_string = Encoding.Default.GetString(bufferHMAC);
                        hmac_string = hmac_string.Substring(0, hmac_string.IndexOf("\0"));

                        logs.AppendText("Recieved HMAC is: \n");
                        logs.AppendText(hmac_string + "\n");

                        // Verify it using session authentication key for that client 
                        string key = sessionKey;
                        byte[] key_bytes = Encoding.ASCII.GetBytes(key);

                        logs.AppendText("Client session key is \n");
                        logs.AppendText(key + "\n");

                        byte[] hmac_toverify = applyHMACwithSHA256(enc_string, key_bytes);
                        string hmac_toverify_string = Encoding.Default.GetString(hmac_toverify);
                        hmac_toverify_string = hmac_toverify_string.Substring(0, hmac_toverify_string.IndexOf("\0"));



                        // If verified store the file //Client is informed with a signed message that contains new filename
                        if (hmac_toverify_string == hmac_string)
                        {

                            // Create the file and write into it
                            BinaryWriter bWrite = new BinaryWriter(File.Open // using system.I/O
                                    (textBox_repository + "/" + fileName_basic, FileMode.Append));
                            bWrite.Write(bufferEncrypted);
                            bWrite.Close();

                            // Write into LOGS ???


                            bufferEncrypted = null; // In order to prevent creating files over and over again


                        }

                        // If not verified inform the client with signed message 
                        else
                        {

                        }
                    }
                }
                catch
                {
                    if (!terminating)
                    {
                        logs.AppendText(username + " has disconnected\n");
                        try
                        {
                            clientList.Remove(username); //removes username if disconnected
                            // current clientlist will be printed here
                            logs.AppendText("Current Client List:\n");
                            foreach (string user in clientList)
                            {
                                logs.AppendText("   " + user + "\n");
                            }
                        }
                        catch (Exception e)
                        {
                            // do nothing if already removed & came here accidentally 
                        }
                    }
                    thisClient.Close();
                    clientSockets.Remove(thisClient);
                    connected = false;
                }
            }
        }

        private void button_serverStart_Click(object sender, EventArgs e)
        {
            int serverPort;

            if (Int32.TryParse(textBox_port.Text, out serverPort))
            {
                //creating the path for database file
                //DB_path = location + "\\server_DB.txt";

                IPEndPoint endPoint = new IPEndPoint(IPAddress.Any, serverPort);
                serverSocket.Bind(endPoint);
                serverSocket.Listen(3);

                listening = true;

                Thread acceptThread = new Thread(Accept);
                acceptThread.Start();

                logs.AppendText("Started listening on port: " + serverPort + "\n");

                button_serverStart.Enabled = false;
                button_fileExplorer.Enabled = false; //son gui eklemesi
                textBox_port.Enabled = false;


            }
            else
            {
                logs.AppendText("Please check port number \n");
            }
        }

        private void button_fileExplorer_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.ShowDialog();
            string filePath = openFileDialog.FileName;
            textBox_key.Text = filePath;

            if (File.Exists(filePath))
            {
                button_folderExplorer.Enabled = true;
                button_fileExplorer.Enabled = false;

                using (System.IO.StreamReader fileReader =
                new System.IO.StreamReader(filePath))
                {
                    privateKey = fileReader.ReadLine();
                    byte [] privateKey_byte = Encoding.Default.GetBytes(privateKey);
                    logs.AppendText("RSA private key:\n");
                    logs.AppendText(generateHexStringFromByteArray(privateKey_byte) + "\n" + "RSA private key size: " + privateKey.Length + "\n");
                }
                
            }
        }

        private void button_folderExplorer_Click(object sender, EventArgs e)
        {
            FolderBrowserDialog openFileDialog1 = new FolderBrowserDialog();
            openFileDialog1.ShowDialog();
            location = openFileDialog1.SelectedPath;
            textBox_repository.Text = location;

            if (Directory.Exists(location))
            {
                button_folderExplorer.Enabled = false;
                textBox_port.Enabled = true;
                button_serverStart.Enabled = true;
            }
        }


        // hash function: SHA-384
        private byte[] hashWithSHA384(string input)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create a hasher object from System.Security.Cryptography
            SHA384CryptoServiceProvider sha384Hasher = new SHA384CryptoServiceProvider();
            // hash and save the resulting byte array
            byte[] result = sha384Hasher.ComputeHash(byteInput);

            return result;
        }

        // helper functions
        private string generateHexStringFromByteArray(byte[] input)
        {
            string hexString = BitConverter.ToString(input);
            return hexString.Replace("-", "");
        }

        private static byte[] hexStringToByteArray(string hex)
        {
            int numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        // encryption with AES-256
        private byte[] decryptWithAES256(string input, byte[] key, byte[] IV)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);

            // create AES object from System.Security.Cryptography
            RijndaelManaged aesObject = new RijndaelManaged();
            // since we want to use AES-256
            aesObject.KeySize = 256;
            // block size of AES is 128 bits
            aesObject.BlockSize = 128;
            // mode -> CipherMode.*
            aesObject.Mode = CipherMode.CFB;
            // feedback size should be equal to block size
            aesObject.FeedbackSize = 128;
            // set the key
            aesObject.Key = key;
            // set the IV
            aesObject.IV = IV;
            // create an encryptor with the settings provided
            ICryptoTransform decryptor = aesObject.CreateDecryptor();
            byte[] result = null;

            try
            {
                result = decryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch (Exception e) // if encryption fails
            {
                //logs.AppendText(e.Message+"\n"); // display the cause
            }

            return result;
        }

        // RSA encryption with varying bit length
        static byte[] encryptWithRSA(string input, int algoLength, string xmlStringKey)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlStringKey);
            byte[] result = null;

            try
            {
                //true flag is set to perform direct RSA encryption using OAEP padding
                result = rsaObject.Encrypt(byteInput, true);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }

        // RSA decryption with varying bit length
        static byte[] decryptWithRSA(string input, int algoLength, string xmlStringKey)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlStringKey);
            byte[] result = null;

            try
            {
                result = rsaObject.Decrypt(byteInput, true);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }
        // signing with RSA
        static byte[] signWithRSA(string input, int algoLength, string xmlString)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlString);
            byte[] result = null;

            result = rsaObject.SignData(byteInput, "SHA512");

            return result;
        }

        // verifying with RSA
        static bool verifyWithRSA(string input, int algoLength, string xmlString, byte[] signature)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlString);
            bool result = false;

            result = rsaObject.VerifyData(byteInput, "SHA512", signature);

            return result;
        }

        // hash function: SHA-512
        static byte[] hashWithSHA512(string input)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create a hasher object from System.Security.Cryptography
            SHA512CryptoServiceProvider sha512Hasher = new SHA512CryptoServiceProvider();
            // hash and save the resulting byte array
            byte[] result = sha512Hasher.ComputeHash(byteInput);

            return result;
        }

        // HMAC with SHA-256
        static byte[] applyHMACwithSHA256(string input, byte[] key)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create HMAC applier object from System.Security.Cryptography
            HMACSHA256 hmacSHA256 = new HMACSHA256(key);
            // get the result of HMAC operation
            byte[] result = hmacSHA256.ComputeHash(byteInput);

            return result;
        }
    }
}
