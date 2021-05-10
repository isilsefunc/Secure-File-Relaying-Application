using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace client
{
    public partial class Form1 : Form
    {
        bool terminating = false;
        bool connected = false;
        byte[] privateKey;
        Socket clientSocket;
        string repository;
        byte[] sessionKey;

        public Form1()
        {
            Control.CheckForIllegalCrossThreadCalls = false;
            this.FormClosing += new FormClosingEventHandler(Form1_FormClosing);
            InitializeComponent();
        }

        private void Form1_FormClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            connected = false;
            terminating = true;
            Environment.Exit(0);
        }

        //Checks whether the username has underscore, returns false if it has an underscore.
        private bool NameValidity(string word)
        {
            if (word.Length == 0)
            {
                return false;
            }
            bool isMatch = true;
            for (int counter = 0; counter < word.Length && isMatch; counter++)
            {
                if (word.ElementAt<char>(counter) == '_')
                {
                    isMatch = false;
                }
            }
            return isMatch;
        }

        private byte[] passValidity(string pass)
        {
            byte[] sha384 = hashWithSHA384(pass);
            logs.AppendText("SHA384 result:\n");
            logs.AppendText(generateHexStringFromByteArray(sha384) + "\n" + "sha384.size: " + sha384.Length + "\n");

            byte[] encryptkey = new byte[32];

            byte[] myIV = new byte[16];

            Array.Copy(sha384, 0, encryptkey, 0, 32);
            Array.Copy(sha384, 32, myIV, 0, 16);

            logs.AppendText("AES256 Key:\n");
            logs.AppendText(generateHexStringFromByteArray(encryptkey) + "\n" + "Key.size: " + encryptkey.Length + "\n");

            logs.AppendText("AES256 IV:\n");
            logs.AppendText(generateHexStringFromByteArray(myIV) + "\n" + "IV.size: " + myIV.Length + "\n");

            string fileName = textBox_key.Text;

            string RSAxmlKey4096;
            using (System.IO.StreamReader fileReader =
            new System.IO.StreamReader(fileName))
            {
                RSAxmlKey4096 = fileReader.ReadLine();
            }
            byte[] encrypted_byte = hexStringToByteArray(RSAxmlKey4096);
            string encrypted_string = Encoding.Default.GetString(encrypted_byte);

            byte[] decryptedAES256 = decryptWithAES256(encrypted_string, encryptkey, myIV);
            return decryptedAES256;
        }

        private void Connection()
        {

            //Send Name
            Byte[] nameBuffer = new Byte[64];
            nameBuffer = Encoding.Default.GetBytes(textBox_username.Text);
            clientSocket.Send(nameBuffer);

            //Wait for Response
            bool responded = false;
            //bool response = false;
            while (!responded)
            {
                Byte[] buffer = new Byte[64];
                clientSocket.Receive(buffer);

                string incomingMessage = Encoding.Default.GetString(buffer);
                incomingMessage = incomingMessage.Substring(0, incomingMessage.IndexOf("\0"));

                if (incomingMessage == "Valid Username")
                {
                    responded = true;
                    //Authentication();
                    //response = true;
                    textBox_pass.Enabled = true;
                    authenticate_button.Enabled = true;

                }
                else if (incomingMessage == "Invalid Username")
                {
                    logs.AppendText("Invalid Username\n");
                    logs.AppendText("Disconnected\n");
                    clientSocket.Close();
                    responded = true;
                    //response = false;
                }
            }

        }

        void Authentication()
        {
            try
            {
                //receiving nonce from the server
                byte[] nonce = new byte[16];
                clientSocket.Receive(nonce);
                logs.AppendText("Nonce has been received from the server\n");
                logs.AppendText(generateHexStringFromByteArray(nonce) + "\n" + "Nonce size: " + nonce.Length + "\n");


                string nonce_string = Encoding.Default.GetString(nonce);
                //nonce_string = nonce_string.Substring(0, nonce_string.IndexOf("\0"));


                //signing the nonce
                string privateKey_string = Encoding.Default.GetString(privateKey);
                byte[] signed_nonce = signWithRSA(nonce_string, 4096, privateKey_string);

                //sending the signed  nonce
                clientSocket.Send(signed_nonce);
                logs.AppendText("Signature over nonce has been sent to server\n");
                logs.AppendText(generateHexStringFromByteArray(signed_nonce) + "\n" + "Signed Nonce size: " + signed_nonce.Length + "\n");

                //receiving encrypted hmac + ack message
                byte[] hmac = new byte[519];
                clientSocket.Receive(hmac);
                logs.AppendText("Received encr(hmac_key) + ack\n");
                logs.AppendText(generateHexStringFromByteArray(hmac) + "\n" + "Hmac + ack size: " + hmac.Length + "\n");

                //receiving signature of the server over (encrypted hmac + ack message)
                byte[] signed_hmac = new byte[512];
                clientSocket.Receive(signed_hmac);
                logs.AppendText("Received signature(encr(hmac_key) + ack)\n");
                logs.AppendText(generateHexStringFromByteArray(signed_hmac) + "\n" + "Signature over (Hmac + ack) size: " + signed_hmac.Length + "\n");

                //getting the public key of the server
                string serverPubKey;
                using (System.IO.StreamReader fileReader =
                new System.IO.StreamReader(repository + "\\server_pub.txt"))
                {
                    serverPubKey = fileReader.ReadLine();
                }
                byte[] serverPubKey_byte = Encoding.Default.GetBytes(serverPubKey);
                logs.AppendText("Server's public key:\n");
                logs.AppendText(generateHexStringFromByteArray(serverPubKey_byte) + "\n" + "Server Public key size: " + serverPubKey_byte.Length + "\n");

                string hmac_string = Encoding.Default.GetString(hmac);
                hmac_string = hmac_string.Substring(0, hmac_string.IndexOf("\0"));

                if (hmac_string == "NEG_ACK")
                {
                    logs.AppendText("Negative ack has been received\n");
                    if (verifyWithRSA(hmac_string, 4096, serverPubKey, signed_hmac))
                    {
                        logs.AppendText("Signature of the negative ack message is verified\n");
                        clientSocket.Close();
                    }
                    else
                    {
                        logs.AppendText("Signature of the negative ack message could not be verified!\n");
                        clientSocket.Close();
                    }
                }
                else
                {
                    logs.AppendText("Positive ack has been received\n");
                    if (verifyWithRSA(hmac_string, 4096, serverPubKey, signed_hmac))
                    {
                        logs.AppendText("Signature of the server has been verified\n");
                        logs.AppendText("Server has authanticated itself!\n");
                        string encrypted_hmac = hmac_string.Substring(0, hmac_string.IndexOf("POS_ACK"));

                        sessionKey = decryptWithRSA(encrypted_hmac, 4096, privateKey_string);
                        logs.AppendText("Session Key:\n");
                        logs.AppendText(generateHexStringFromByteArray(sessionKey) + "\n" + "Session key size: " + sessionKey.Length + "\n");

                        logs.AppendText("Protocol has been completed and you are authanticated to the server!\n");
                        button_disconnect.Enabled = true;
                        button_connect.Enabled = false;
                        Receive();
                    }
                    else
                    {
                        logs.AppendText("Could not verify the signature of the hmac + ack message\n");
                        logs.AppendText("Check your private key file, password or username and try again!\n");
                        clientSocket.Close();
                    }
                }

            }
            catch
            {
                logs.AppendText("An Error Occured During Challenge-Response Protocol!\n");
                logs.AppendText("Check your private key file, password or username and try again!\n");
                logs.AppendText("Disconnect!\n");
                //
                clientSocket.Close();
                
            }
        }


        private void Receive()
        {
            while (connected)
            {
                string request_string;
                try
                {
                    Byte[] request_buffer = new Byte[4];
                    clientSocket.Receive(request_buffer);
                    request_string = Encoding.Default.GetString(request_buffer);
                    request_string = request_string.Substring(0, request_string.IndexOf("\0"));
                }
                catch
                {
                    if (!terminating)
                    {
                        logs.AppendText("The server has disconnected\n");
                    }
                    clientSocket.Close();
                    connected = false;
                }
            }
        }

        private void button_connect_Click(object sender, EventArgs e)
        {

            if (!NameValidity(textBox_username.Text))
            {
                logs.AppendText("Username is invalid, please try again.\n");
            }

            else
            {



                clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                string IP = textBox_ip.Text;
                int portNum;
                if (Int32.TryParse(textBox_port.Text, out portNum))
                {
                    try
                    {
                        Byte[] buffer1 = new Byte[64];

                        clientSocket.Connect(IP, portNum);
                        connected = true;
                        logs.AppendText("Connected to the server!\n");
                        button_connect.Enabled = false;
                        button_disconnect.Enabled = true;
                        Thread receiveThread = new Thread(Connection);
                        receiveThread.Start();
                    }
                    catch
                    {
                        logs.AppendText("Could not connect to the server!\n");
                    }
                }
                else
                {
                    logs.AppendText("Check the port\n");
                }
            }
        }

        private void button_disconnect_Click(object sender, EventArgs e)
        {
            logs.AppendText("Disconnecting from the server...\n");
            clientSocket.Close();
            connected = false;
            terminating = true;

            button_disconnect.Enabled = false;
            button_connect.Enabled = false;
            textBox_ip.Enabled = true;
            textBox_port.Enabled = true;
            textBox_username.Enabled = true;
            button_fileExplorer.Enabled = true;
            privateKey = null;
            sessionKey = null;
            repository = "";

        }

        private void button_fileExplorer_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.ShowDialog();
            textBox_key.Text = openFileDialog.FileName;

            if (File.Exists(textBox_key.Text))
            {
                button_folderExplorer.Enabled = true;
                button_fileExplorer.Enabled = false;
            }
        }

        private void button_folderExplorer_Click(object sender, EventArgs e)
        {
            FolderBrowserDialog openFileDialog1 = new FolderBrowserDialog();
            openFileDialog1.ShowDialog();
            repository = openFileDialog1.SelectedPath;
            textBox_repository.Text = repository;

            if (Directory.Exists(repository))
            {
                textBox_ip.Enabled = true;
                textBox_port.Enabled = true;
                textBox_username.Enabled = true;
                textBox_pass.Enabled = true;

                button_folderExplorer.Enabled = false;
                button_connect.Enabled = true;
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
        static byte[] encryptWithAES256(string input, byte[] key, byte[] IV)
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
            // RijndaelManaged Mode property doesn't support CFB and OFB modes. 
            //If you want to use one of those modes, you should use RijndaelManaged library instead of RijndaelManaged.
            aesObject.Mode = CipherMode.CFB;
            // feedback size should be equal to block size
            aesObject.FeedbackSize = 128;
            // set the key
            aesObject.Key = key;
            // set the IV
            aesObject.IV = IV;
            // create an encryptor with the settings provided
            ICryptoTransform encryptor = aesObject.CreateEncryptor();
            byte[] result = null;

            result = encryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);

            return result;
        }

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

        private void upload_button_Click(object sender, EventArgs e)
        {
            // Uploading a file to the Server
            try
            {
                // Select the file
                OpenFileDialog dialog = new OpenFileDialog();
                dialog.Filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*"; // Taken directly from docs


                // If the file is selected
                if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                {


                    // Send the 1 byte to inform the server that the client is sending a file
                    Byte[] infoHeader = new Byte[1];
                    infoHeader[0] = 0;
                    clientSocket.Send(infoHeader);

                    // client generates random two numbers 256 bit AES key and 128 bit IV
                    RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
                    byte[] AESkey = new byte[32];
                    rngCsp.GetBytes(AESkey);
                    logs.AppendText("256 bit AES key:\n");
                    logs.AppendText(generateHexStringFromByteArray(AESkey) + "\n");


                    RNGCryptoServiceProvider rngCsp2 = new RNGCryptoServiceProvider();
                    byte[] IV = new byte[16];
                    rngCsp2.GetBytes(IV);
                    logs.AppendText("128 bit IV:\n");
                    logs.AppendText(generateHexStringFromByteArray(IV) + "\n");




                    // Copy the data into generalBuffer
                    Byte[] generalBuffer = new Byte[File.ReadAllBytes(dialog.FileName).Length];
                    generalBuffer = File.ReadAllBytes(dialog.FileName);
                    string plaintext = Encoding.Default.GetString(generalBuffer);


                    // Files will be enrypted in CBC mode using AES key and IV
                    byte[] encryptedWithAES256 = encryptWithAES256(plaintext, AESkey, IV);
                    logs.AppendText("AES256 Encryption:");
                    logs.AppendText(generateHexStringFromByteArray(encryptedWithAES256) + "\n");
                    string s_encryptedWithAES256 = Encoding.Default.GetString(encryptedWithAES256);



                    // Client generates the HMAC value of the encrypted file
                    byte[] hmac_value = applyHMACwithSHA256(s_encryptedWithAES256, sessionKey);
                    logs.AppendText("HMAC Value of the Encrypted File:");
                    logs.AppendText(generateHexStringFromByteArray(hmac_value) + "\n");
                    string s_hmac_value = Encoding.Default.GetString(hmac_value);


                    //Send file name file size to the server 
                    int fileProperties = 256; // FileName + The Data's Length
                    int fileNameLength = 128; // FileName
                    string fileLength = File.ReadAllBytes(dialog.FileName).Length.ToString(); // The Data's Length is turned into string 
                                                                                              // to put into a Byte Array with the FileName
                    Byte[] filePropertiesBuffer = new Byte[fileProperties]; // Allocate space for FileName and The Data's Length
                    // Copy the FileName and The Data's Length into the filePropertiesBuffer
                    Array.Copy(Encoding.Default.GetBytes(dialog.SafeFileName), filePropertiesBuffer, dialog.SafeFileName.Length);
                    Array.Copy(Encoding.ASCII.GetBytes(fileLength), 0, filePropertiesBuffer, fileNameLength, fileLength.Length);
                    // Send the filePropertiesBuffer to the Server
                    clientSocket.Send(filePropertiesBuffer);



                    // Encrypted file and HMAC value and sent to server
                    //string message = s_hmac_value + s_encryptedWithAES256;
                    byte[] hmac = Encoding.Default.GetBytes(s_hmac_value);
                    byte[] enc_file = Encoding.Default.GetBytes(s_encryptedWithAES256);
                    clientSocket.Send(enc_file);
                    clientSocket.Send(hmac);

                    //Recieve acknowledgement 


                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }

        }

        private void authenticate_button_Click(object sender, EventArgs e)
        {
            try
            {

                privateKey = passValidity(textBox_pass.Text);
                logs.AppendText("RSA private key:\n");
                logs.AppendText(generateHexStringFromByteArray(privateKey) + "\n" + "RSA private key size: " + privateKey.Length + "\n");

                if (privateKey == null)
                {
                    logs.AppendText("Problem with the password or private key\n");

                }
                else
                {
                    Thread authenticateThread = new Thread(Authentication);
                    authenticateThread.Start();
                }
            }
            catch
            {
                logs.AppendText("Problem with the password or private key\n");
            }
        }
    }
}
