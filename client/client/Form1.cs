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
        string serverPubKey;
        string LOGS_Path;
        OpenFileDialog dialog;
        int permission = 2;

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
            try
            {
                //Send Name
                Byte[] nameBuffer = new Byte[64];
                nameBuffer = Encoding.Default.GetBytes(textBox_username.Text);
                clientSocket.Send(nameBuffer);

                //Wait for Response
                Byte[] buffer = new Byte[64];
                clientSocket.Receive(buffer);

                string usernameValidity = Encoding.Default.GetString(buffer);
                usernameValidity = usernameValidity.Substring(0, usernameValidity.IndexOf("\0"));

                if (usernameValidity == "Valid Username")
                {
                    //Authentication();
                    textBox_pass.Enabled = true;
                    button_authenticate.Enabled = true;
                }
                else if (usernameValidity == "Invalid Username")
                {
                    logs.AppendText("Invalid Username, disconnecting...\n");
                    button_disconnect.Enabled = false;
                    button_connect.Enabled = true;
                    clientSocket.Close();
                }
            }
            catch
            {
                logs.AppendText("Server has disconnected during connection phase");
            }
        }

        void Authentication()
        {
            try
            {
                clientSocket.Send(Encoding.Default.GetBytes("OK"));
                //receiving nonce from the server
                byte[] nonce = new byte[16];
                clientSocket.Receive(nonce);
                logs.AppendText("Nonce has been received from the server\n");
                logs.AppendText(generateHexStringFromByteArray(nonce) + "\n" + "Nonce size: " + nonce.Length + "\n");

                string nonce_string = Encoding.Default.GetString(nonce);

                //signing the nonce
                string privateKey_string = Encoding.Default.GetString(privateKey);
                byte[] signed_nonce = signWithRSA(nonce_string, 4096, privateKey_string);

                //sending the signed  nonce
                clientSocket.Send(signed_nonce);
                logs.AppendText("Signature over nonce has been sent to server\n");
                logs.AppendText(generateHexStringFromByteArray(signed_nonce) + "\n" + "Signed Nonce size: " + signed_nonce.Length + "\n");

                //getting the public key of the server
                
                using (System.IO.StreamReader fileReader =
                new System.IO.StreamReader(repository + "\\server_pub.txt"))
                {
                    serverPubKey = fileReader.ReadLine();
                }
                byte[] serverPubKey_byte = Encoding.Default.GetBytes(serverPubKey);
                logs.AppendText("Server's public key:\n");
                logs.AppendText(generateHexStringFromByteArray(serverPubKey_byte) + "\n" + "Server Public key size: " + serverPubKey_byte.Length + "\n");

                //receiving response from server
                byte[] response = new byte[519];
                clientSocket.Receive(response);
                string response_string = Encoding.Default.GetString(response);
                //string not_trimmed_response = response_string;
                response_string = response_string.Substring(0, response_string.IndexOf("\0"));

                //receiving signed response from server
                byte[] signed_response = new byte[512];
                clientSocket.Receive(signed_response);

                string ack = response_string.Substring(0, 7);

                if (ack == "NEG_ACK") //server sent negative acknowledgement
                {
                    logs.AppendText("Negative ack has been received\n");
                    if (verifyWithRSA(response_string, 4096, serverPubKey, signed_response))
                    {
                        logs.AppendText("Signature of the negative ack message is verified\n");
                        clientSocket.Close();
                        button_fileExplorer.Enabled = true;
                        button_disconnect.Enabled = false;
                        button_authenticate.Enabled = false;
                        textBox_pass.Enabled = false;
                    }
                    else
                    {
                        logs.AppendText("Signature of the negative ack message could not be verified!\n");
                        clientSocket.Close();
                        button_fileExplorer.Enabled = true;
                        button_disconnect.Enabled = false;
                        button_authenticate.Enabled = false;
                        textBox_pass.Enabled = false;
                    }
                }
                else if (ack == "POS_ACK") //server sent positive acknowledgement
                {
                    logs.AppendText("Positive ack has been received\n");
                    logs.AppendText("Received encr(hmac_key) + ack\n");
                    logs.AppendText(generateHexStringFromByteArray(response) + "\n" + "Hmac + ack size: " + response.Length + "\n");

                    logs.AppendText("Received signature(encr(hmac_key) + ack)\n");
                    logs.AppendText(generateHexStringFromByteArray(signed_response) + "\n" + "Signature over (Hmac + ack) size: " + signed_response.Length + "\n");

                    byte[] encrypted_hmac_byte = new byte[512];
                    Array.Copy(response, 7, encrypted_hmac_byte, 0, 512);
                    string encrypted_hmac_string = Encoding.Default.GetString(encrypted_hmac_byte);

                    logs.AppendText("Encrypted hmac:\n" + generateHexStringFromByteArray(encrypted_hmac_byte) + "\n");
                    if (verifyWithRSA(response_string, 4096, serverPubKey, signed_response))
                    {
                        logs.AppendText("Signature of the server has been verified\n");
                        logs.AppendText("Server has authanticated itself!\n");

                        sessionKey = decryptWithRSA(encrypted_hmac_string, 4096, privateKey_string);
                        logs.AppendText("Session key: " + generateHexStringFromByteArray(sessionKey) + "\n" + "Session key size: " + sessionKey.Length + "\n");

                        
                        clientSocket.Send(Encoding.Default.GetBytes("OKBRUH"));
                        logs.AppendText("Protocol has been completed and you are authanticated to the server!\n");
                        button_authenticate.Enabled = false;
                        textBox_pass.Enabled = false;
                        upload_button.Enabled = true;
                        download_button.Enabled = true;
                        textBox1.Enabled = true;
                        Receive();
                    }
                    else
                    {
                        clientSocket.Send(Encoding.Default.GetBytes("NOBRUH"));
                        logs.AppendText("Could not verify the signature of the hmac + ack message\n");
                        logs.AppendText("Check your private key file, password or username and try again!\n");
                        clientSocket.Close();
                        button_fileExplorer.Enabled = true;
                        button_disconnect.Enabled = false;
                        button_authenticate.Enabled = false;
                        textBox_pass.Enabled = false;
                    }
                }
                else
                {
                    logs.AppendText("No ack was found in the message\n");
                    clientSocket.Close();
                    button_fileExplorer.Enabled = true;
                    button_connect.Enabled = true;
                    button_disconnect.Enabled = false;
                    button_authenticate.Enabled = false;
                    textBox_pass.Enabled = false;
                }
            }
            catch
            {
                logs.AppendText("An Error Occured During Challenge-Response Protocol!\n");
                logs.AppendText("Check your private key file, password or username and try again!\n");
                logs.AppendText("Disconnecting...\n");
                try
                {
                    clientSocket.Close();
                }
                catch
                {
                    logs.AppendText("Server has already disconnected\n");
                }
                button_fileExplorer.Enabled = true;
                button_connect.Enabled = true;
                button_disconnect.Enabled = false;
                button_authenticate.Enabled = false;
                textBox_pass.Enabled = false;
            }
        }

        private void Receive()
        {
            while (connected && !terminating)
            {
                try
                {
                    Byte[] header_buffer = new Byte[6];
                    clientSocket.Receive(header_buffer);
                    string header_string = Encoding.Default.GetString(header_buffer);
                    logs.AppendText("Received Header: " + header_string + "\n");

                    if (header_string == "UPLOAD") //Upload
                    {
                        // Uploading a file to the Server
                        try
                        {
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
                            logs.AppendText("AES256 Encrypted file:");
                            logs.AppendText(generateHexStringFromByteArray(encryptedWithAES256) + "\n");
                            string s_encryptedWithAES256 = Encoding.Default.GetString(encryptedWithAES256);



                            // Client generates the HMAC value of the encrypted file
                            byte[] hmac_value = applyHMACwithSHA512(s_encryptedWithAES256, sessionKey);
                            logs.AppendText("HMAC Value of the Encrypted File: ");
                            logs.AppendText(generateHexStringFromByteArray(hmac_value) + "\n");
                            string s_hmac_value = Encoding.Default.GetString(hmac_value);


                            //Send file name file size to the server 
                            int fileProperties = 256; // FileName + The Data's Length
                            int fileNameLength = 128; // FileName
                            string fileLength = s_encryptedWithAES256.Length.ToString(); // The Data's Length is turned into string 
                                                                                            // to put into a Byte Array with the FileName
                            Byte[] filePropertiesBuffer = new Byte[fileProperties]; // Allocate space for FileName and The Data's Length
                                                                                    // Copy the FileName and The Data's Length into the filePropertiesBuffer
                            string original_filename = dialog.SafeFileName;
                            Array.Copy(Encoding.Default.GetBytes(dialog.SafeFileName), filePropertiesBuffer, dialog.SafeFileName.Length);
                            Array.Copy(Encoding.Default.GetBytes(fileLength), 0, filePropertiesBuffer, fileNameLength, fileLength.Length);
                            // Send the filePropertiesBuffer to the Server
                            clientSocket.Send(filePropertiesBuffer);



                            // Encrypted file and HMAC value and sent to server
                            //byte[] enc_file = Encoding.Default.GetBytes(s_encryptedWithAES256);
                            clientSocket.Send(encryptedWithAES256);
                            clientSocket.Send(hmac_value);

                            //Recieve acknowledgement
                            Byte[] bufferAck = new Byte[64];
                            clientSocket.Receive(bufferAck);
                            string sAcknowledgement = Encoding.Default.GetString(bufferAck).Trim('\0');
                            logs.AppendText("Received ack is : ");
                            logs.AppendText(generateHexStringFromByteArray(bufferAck) + "\n");
                            logs.AppendText(sAcknowledgement + "\n");

                            //Recieve signed acknowledgement 
                            Byte[] bufferAckSigned = new Byte[512];
                            clientSocket.Receive(bufferAckSigned);
                            logs.AppendText("Recieved signed ack is : ");
                            logs.AppendText(generateHexStringFromByteArray(bufferAckSigned) + "\n");



                            //Verify the signature
                            if (verifyWithRSA(sAcknowledgement, 4096, serverPubKey, bufferAckSigned))
                            {
                                logs.AppendText("Signature of the ack message is verified\n");

                                if (sAcknowledgement == "neg_ack")
                                {
                                    logs.AppendText("Returned ack equals to ");
                                    logs.AppendText(sAcknowledgement + "\n");
                                    logs.AppendText("File sent could not uploaded since HMAC is not verified");


                                }
                                else
                                {
                                    //returns the file name to the client 
                                    string formatted_filename = sAcknowledgement;
                                    logs.AppendText("Formatted filename equals to ");
                                    logs.AppendText(sAcknowledgement + "\n");

                                    //Store the file name, AES key, IV and formatted filename safely

                                    // Write into LOGS.txt                          
                                    BinaryWriter bWriteLog = new BinaryWriter(File.Open(LOGS_Path, FileMode.Append));
                                    string AESkey_string = Encoding.Default.GetString(AESkey);
                                    string IV_string = Encoding.Default.GetString(IV);
                                    string privateKey_string = Encoding.Default.GetString(privateKey);
                                    byte[] encrypted_AES = encryptWithRSA(AESkey_string, 4096, privateKey_string);
                                    byte[] encrypted_IV = encryptWithRSA(IV_string, 4096, privateKey_string);
                                    Byte[] logBuffer = Encoding.Default.GetBytes(original_filename + "\t" + formatted_filename + "\t"
                                        + generateHexStringFromByteArray(encrypted_AES) + "\t" + generateHexStringFromByteArray(encrypted_IV) + "\n");
                                    bWriteLog.Write(logBuffer.ToArray());
                                    bWriteLog.Close();
                                }
                            }
                            else
                            {
                                logs.AppendText("Signature of the ack message could not be verified!\n");

                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine(ex);
                        }
                    }
                    else if(header_string == "DOLOAD") //Download mode where the client requests own file
                    {
                        try
                        {
                            string filename_string = textBox1.Text;

                            //Sending requested file's name to the server
                            byte[] filename = Encoding.Default.GetBytes(filename_string);
                            clientSocket.Send(filename);

                            //Sending signature over filename
                            string privatekey_string = Encoding.Default.GetString(privateKey);
                            byte[] signature_filename = signWithRSA(filename_string, 4096, privatekey_string);
                            clientSocket.Send(signature_filename);
                            logs.AppendText("Signature: " + generateHexStringFromByteArray(signature_filename) + "\n" + "signature size: " + signature_filename.Length+"\n");
                            logs.AppendText("Requested filename and signature has been sent to server!\n");

                            Byte[] download_mode = new Byte[1];
                            clientSocket.Receive(download_mode);
                            logs.AppendText("Download mode: " + download_mode[0] + "\n");

                            if (download_mode[0] == 10)//if it is your file that will be downloaded
                            {
                                //Receiving encrypted file
                                byte[] file_byte = new byte[64];
                                clientSocket.Receive(file_byte);

                                string ciphertext = Encoding.Default.GetString(file_byte);
                                ciphertext = ciphertext.Substring(0, ciphertext.IndexOf("\0"));


                                byte[] ciphertext_byte = Encoding.Default.GetBytes(ciphertext);
                                string enc_file = generateHexStringFromByteArray(ciphertext_byte);

                                logs.AppendText("Encrypted file has been downloaded:\n");
                                logs.AppendText("Hex content: " + enc_file + "\n");

                                //Receiving signature over  encrypted file
                                byte[] sig_enc_file = new byte[512];
                                clientSocket.Receive(sig_enc_file);
                                logs.AppendText("Signature of the received encrypted file: " + generateHexStringFromByteArray(sig_enc_file) + "\n");

                                if (verifyWithRSA(enc_file, 4096, serverPubKey, sig_enc_file))
                                {
                                    logs.AppendText("Signature of the server's response to download has been verified!\n");

                                    //Now we will search LOGS.txt for the corresponding AES key and IV for decryption of the file downloaded
                                    StreamReader logReader = new StreamReader(LOGS_Path);
                                    string hex_enc_AESkey = "";
                                    string hex_enc_IV = "";
                                    string line = "";
                                    bool rowfound = false;
                                    while ((line = logReader.ReadLine()) != null)//read each line
                                    {
                                        if (line.Split('\t')[1] == filename_string)//if you find the correct file
                                        {
                                            hex_enc_AESkey = line.Split('\t')[2];//take aes and IV
                                            hex_enc_IV = line.Split('\t')[3];
                                            rowfound = true;
                                            break;
                                        }
                                        else
                                        {
                                            continue;
                                        }
                                    }
                                    logReader.Close();

                                    if (rowfound)
                                    {
                                        //extracting plaintext AESkey and IV
                                        string enc_AESkey = Encoding.Default.GetString(hexStringToByteArray(hex_enc_AESkey));
                                        string enc_IV = Encoding.Default.GetString(hexStringToByteArray(hex_enc_IV));
                                        byte[] AESkey_byte = decryptWithRSA(enc_AESkey, 4096, privatekey_string);
                                        byte[] IV_byte = decryptWithRSA(enc_IV, 4096, privatekey_string);

                                        logs.AppendText("AES_KEY: " + generateHexStringFromByteArray(AESkey_byte) + "\n");
                                        logs.AppendText("IV: " + generateHexStringFromByteArray(IV_byte) + "\n");

                                        //encryption of the downloaded by the file
                                        byte[] byte_file = decryptWithAES256(ciphertext, AESkey_byte, IV_byte);

                                        //string downlaoded_file = Encoding.Default.GetString(byte_file);

                                        File.WriteAllBytes(repository + "/" + filename_string, byte_file);
                                        // Create the file and write into it 
                                        /*BinaryWriter bWrite = new BinaryWriter(File.Open(repository + "/" + file, FileMode.Append));
                                        bWrite.Write(downlaoded_file);
                                        bWrite.Close();
                                        downlaoded_file = null; // In order to prevent creating files over and over again*/

                                    }
                                    else
                                    {
                                        logs.AppendText("Error occured bro!\n");
                                    }

                                }
                                else
                                {
                                    logs.AppendText("Signature of the server's response to download couldnt be verified!\n");
                                }
                            }
                            else if (download_mode[0] == 11)//the file will be downloaded from another client
                            {
                                byte[] packet_size_byte = new byte[128];
                                clientSocket.Receive(packet_size_byte);
                                int packet_size = Int32.Parse(Encoding.Default.GetString(packet_size_byte).Trim('\0'));

                                byte[] file_size_byte = new byte[128];
                                clientSocket.Receive(file_size_byte);
                                int file_size = Int32.Parse(Encoding.Default.GetString(file_size_byte).Trim('\0'));

                                byte[] packet = new byte[packet_size];
                                clientSocket.Receive(packet);
                                logs.AppendText("Hex-string of the entire packet: " + generateHexStringFromByteArray(packet) + "\n");
                                
                                byte[] packet_contents = packet.Take(packet.Length - 512).ToArray();
                                logs.AppendText("Hex-string of the encrypted packet content: " + generateHexStringFromByteArray(packet_contents) + "\n");

                                byte[] packet_contents_signature = packet.Skip(packet.Length - 512).Take(512).ToArray();
                                logs.AppendText("Hex-string of the signature: " + generateHexStringFromByteArray(packet_contents_signature) + "\n");

                                //verifies the packet
                                if(verifyWithRSA(Encoding.Default.GetString(packet_contents), 4096, serverPubKey, packet_contents_signature))
                                {
                                    byte[] enc_aes_parameters = packet_contents.Take(packet_contents.Length - file_size).ToArray();
                                    byte[] cipthertext = packet_contents.Skip(packet_contents.Length - file_size).Take(file_size).ToArray();

                                    byte[] aes_parameters = decryptWithRSA(Encoding.Default.GetString(enc_aes_parameters), 4096, privatekey_string);
                                    logs.AppendText("Hex-string of decrypted packet content: " + generateHexStringFromByteArray(aes_parameters) + "\n");

                                    byte[] aes_key = aes_parameters.Take(32).ToArray();
                                    logs.AppendText("Hex-string of aes_key: " + generateHexStringFromByteArray(aes_key) + "\n");

                                    byte[] IV = aes_parameters.Skip(32).Take(16).ToArray();
                                    logs.AppendText("Hex-string of IV: " + generateHexStringFromByteArray(IV) + "\n");

                                    byte[] original_filename = aes_parameters.Skip(48).Take(aes_parameters.Length - 48).ToArray();
                                    string original_filename_string = Encoding.Default.GetString(original_filename);
                                    logs.AppendText("Original file_name: " + Encoding.Default.GetString(original_filename) + "\n");

                                    byte[] plaintext = decryptWithAES256(Encoding.Default.GetString(cipthertext), aes_key, IV);
                                    File.WriteAllBytes(repository + "/" + original_filename_string, plaintext);
                                    logs.AppendText("File was succesfully downloaded!\n");
                                }
                                else
                                {
                                    logs.AppendText("The server's signature was NOT verified\n");
                                }

                            }
                            else if (download_mode[0] == 12)//there is a problem occured
                            {
                                byte[] message = new byte[256];
                                clientSocket.Receive(message);
                                string message_string = Encoding.Default.GetString(message).Trim('\0');
                                logs.AppendText("Your download request FAILED!\n");
                                logs.AppendText("Server: " + message_string + "\n");
                            }
                            else
                            {
                                logs.AppendText("Sektin");
                            }
                        }
                        catch
                        {
                            logs.AppendText("Sıçtın moruk catche girdin!\n");
                        }
                    }
                    else if(header_string == "REQUST") //Request mode where the client requests some other client's file
                    {
                        byte[] request = new byte[256 + 64 + serverPubKey.Length];
                        clientSocket.Receive(request);

                        logs.AppendText("File download request has been received!\n");

                        //taking filename
                        string fileName = Encoding.Default.GetString(request.Take(128).ToArray());                   
                        fileName = fileName.Trim('\0');
                        logs.AppendText("Filename requested to be downloaded : " + fileName +"\n");

                        // Take username from buffer
                        string username = Encoding.Default.GetString(request.Skip(128).Take(128).ToArray());
                        username = username.Trim('\0');
                        logs.AppendText("Username : " + username + "\n");

                        // Take pubkey of the requester client from buffer
                        string pubkeyRequester = Encoding.Default.GetString(request.Skip(256).Take(serverPubKey.Length).ToArray());
                        logs.AppendText("Public key of the requestor : " + generateHexStringFromByteArray(Encoding.Default.GetBytes(pubkeyRequester)) + "\n");

                        // Take pubkey of the requester client from buffer
                        string hmac_request_string = Encoding.Default.GetString(request.Skip(256+ serverPubKey.Length).Take(64).ToArray());                       
                        logs.AppendText("HMAC of the request : " + generateHexStringFromByteArray(Encoding.Default.GetBytes(hmac_request_string)) + "\n");


                        //generate HMAC with sessionkey
                        byte[] hmac_request_genereated = applyHMACwithSHA512(fileName+username+pubkeyRequester,sessionKey);
                        logs.AppendText("Generated HMAC : " + generateHexStringFromByteArray(hmac_request_genereated) + "\n");
                        string hmac_request_generated_string = Encoding.Default.GetString(hmac_request_genereated);

                        if(hmac_request_string == hmac_request_generated_string)
                        {
                            logs.AppendText("HMAC of the Download request relay message from server has been verified!\n");

                            button_yes.Enabled = true;
                            button_no.Enabled = true;

                            while(permission == 2) { }//busy waiting on permissons (initial value is 2)


                            if (permission == 1)// if permission granted
                            {
                                //Now we will search LOGS.txt for the corresponding AES key and IV for decryption of the file downloaded
                                StreamReader logReader = new StreamReader(LOGS_Path);
                                string hex_enc_AESkey = "";
                                string hex_enc_IV = "";
                                string line = "";
                                string original_filename = "";
                                bool rowfound = false;
                                while ((line = logReader.ReadLine()) != null)//read each line
                                {
                                    if (line.Split('\t')[1] == fileName)//if you find the correct file
                                    {
                                        hex_enc_AESkey = line.Split('\t')[2];//take aes and IV
                                        hex_enc_IV = line.Split('\t')[3];
                                        original_filename = line.Split('\t')[0];
                                        rowfound = true;
                                        break;
                                    }
                                    else
                                    {
                                        continue;
                                    }
                                }
                                logReader.Close();

                                if (rowfound)
                                {
                                    //extracting plaintext AESkey and IV
                                    string privatekey_string = Encoding.Default.GetString(privateKey);
                                    string enc_AESkey = Encoding.Default.GetString(hexStringToByteArray(hex_enc_AESkey));
                                    string enc_IV = Encoding.Default.GetString(hexStringToByteArray(hex_enc_IV));
                                    byte[] AESkey_byte = decryptWithRSA(enc_AESkey, 4096, privatekey_string);
                                    byte[] IV_byte = decryptWithRSA(enc_IV, 4096, privatekey_string);

                                    logs.AppendText("AES_KEY that will be sent: " + generateHexStringFromByteArray(AESkey_byte) + "\n");
                                    logs.AppendText("IV that will be sent: " + generateHexStringFromByteArray(IV_byte) + "\n");
                                    logs.AppendText("Original filename will be sent :" + original_filename + "\n");
                                    
                                    byte [] concat = new byte[32 + 16 + original_filename.Length];
                                    Array.Copy(AESkey_byte, 0, concat, 0, 32);
                                    Array.Copy(IV_byte, 0, concat, 32, 16);
                                    Array.Copy(Encoding.Default.GetBytes(original_filename), 0, concat, 48, original_filename.Length);
                                    byte [] enc_request_response = encryptWithRSA(Encoding.Default.GetString(concat),4096,pubkeyRequester);
                                    logs.AppendText("Encrypted IV + AES + original_filename: "+ generateHexStringFromByteArray(enc_request_response) + "Size :"+ enc_request_response.Length+"\n");

                                    byte [] ack_message = Encoding.Default.GetBytes("OK!");
                                    byte[] ack_plus_response = new byte[enc_request_response.Length + 3];
                                    
                                    Array.Copy(ack_message,0, ack_plus_response, 0, 3);
                                    Array.Copy(enc_request_response, 0, ack_plus_response, 3, enc_request_response.Length);

                                    byte[] HMAC_server = applyHMACwithSHA512(Encoding.Default.GetString(ack_plus_response),sessionKey);
                                    logs.AppendText("HMAC that will be sent: " + generateHexStringFromByteArray(HMAC_server) + "\n Size: " + HMAC_server.Length + "\n");

                                    byte[] all_response = new byte[enc_request_response.Length + 3 + HMAC_server.Length];
                                    logs.AppendText("Response size: "+ all_response.Length+"\n");
                                    Array.Copy(ack_plus_response, 0, all_response, 0, enc_request_response.Length + 3);
                                    Array.Copy(HMAC_server,0,all_response, enc_request_response.Length + 3, HMAC_server.Length);

                                    //byte[] response_size = Encoding.Default.GetBytes(all_response.Length.ToString());
                                    //clientSocket.Send(response_size);
                                    clientSocket.Send(Encoding.Default.GetBytes(2.ToString()));

                                    clientSocket.Send(all_response);


                                }
                                else
                                {
                                    logs.AppendText("Error occured bro!\n");
                                }
                            }
                            else if (permission == 0)// if permission rejected
                            {
                                byte[] neg_ack_message = Encoding.Default.GetBytes("NOO");
                                byte[] HMAC_server = applyHMACwithSHA512("NOO", sessionKey);
                                logs.AppendText("HMAC that will be sent to server with response: "+ generateHexStringFromByteArray(HMAC_server) +"\n");

                                byte[] concat = new byte[neg_ack_message.Length + HMAC_server.Length];
                                Array.Copy(neg_ack_message, concat, neg_ack_message.Length);
                                Array.Copy(HMAC_server, 0, concat, neg_ack_message.Length, HMAC_server.Length);

                                clientSocket.Send(Encoding.Default.GetBytes(2.ToString()));

                                clientSocket.Send(concat);
                            }
                            permission = 2;//reinitializing the permission variable
                        }
                        else
                        {
                            logs.AppendText("HMAC of the Download request relay message from server is NOT verified!\n");
                        }

                    }
                }
                catch
                {
                    if (!terminating)
                    {
                        logs.AppendText("The server has disconnected\n");
                    }
                    clientSocket.Close();
                    connected = false;
                    terminating = true;
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
            button_authenticate.Enabled = false;
            textBox_pass.Enabled = false;
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

                button_folderExplorer.Enabled = false;
                button_connect.Enabled = true;

                string lgp = repository.Substring(0, repository.LastIndexOf('\\')) + "\\LOGS.txt";
                StreamWriter w = File.AppendText(lgp); // "CREATE IF LOGS TXT DOES NOT EXIST
                w.Close();
                LOGS_Path = lgp.Replace(@"\", "/");
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
        static byte[] applyHMACwithSHA512(string input, byte[] key)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create HMAC applier object from System.Security.Cryptography
            HMACSHA512 hmacSHA512 = new HMACSHA512(key);
            // get the result of HMAC operation
            byte[] result = hmacSHA512.ComputeHash(byteInput);

            return result;
        }

        private void upload_button_Click(object sender, EventArgs e)
        {
            // Uploading a file to the Server
            try
            {
                // Select the file
                dialog = new OpenFileDialog();
                dialog.Filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*"; // Taken directly from docs

                // If the file is selected
                if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                {
                    // Send the 1 byte to inform the server that the client is sending a file
                    Byte[] infoHeader = new Byte[1];
                    infoHeader[0] = 0;
                    clientSocket.Send(infoHeader);
                }
            }
            catch (Exception ex)
            {
                logs.AppendText(ex.Message);
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

        private void download_button_Click(object sender, EventArgs e)
        {
            try
            {
                //Send option indicator as 1, means Request/Download option
                Byte[] infoHeader = new Byte[1];
                infoHeader[0] = 1;
                clientSocket.Send(infoHeader);
            }
            catch
            {
                logs.AppendText("Couldn't send to the server");
            }
        }

        private void button_yes_Click(object sender, EventArgs e)
        {
            permission = 1;
            button_yes.Enabled = false;
            button_no.Enabled = false;
        }

        private void button_no_Click(object sender, EventArgs e)
        {
            permission = 0;
            button_yes.Enabled = false;
            button_no.Enabled = false;
        }
    }
}