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
        List<string> clientSessionKeys = new List<string>();

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
                else // if username does not exist (checks if empty or not)
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
                        logs.AppendText("--"+user + "\n");
                    }

                    try
                    {
                        Authentication(thisClient, clientName);
                    }
                    catch
                    {
                        logs.AppendText("An Error Occured During Challenge-Response Protocol with client " + clientName + "!\n");
                        logs.AppendText(clientName + " disconnected.\n");
                        clientList.Remove(clientName);
                        logs.AppendText("Current Client List:\n");
                        foreach (string user in clientList)
                        {
                            logs.AppendText("--" + user + "\n");
                        }
                        thisClient.Close();
                    }
                }
            }
        }

        private void Authentication(Socket thisClient, string clientName)
        {
            byte[] initial_message = new byte[2];
            thisClient.Receive(initial_message);
            string initial_string = Encoding.Default.GetString(initial_message);
            if(initial_string != "OK")
            {
                logs.AppendText("Error in the authentication protocol initiation phase!\n");
                return;
            }

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
            logs.AppendText("Signature of the client " + clientName + " over 128-bit random value has been received\n");
            logs.AppendText(generateHexStringFromByteArray(signed_nonce) + "\n" + "Signed Nonce size: " + signed_nonce.Length + "\n");

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
                
                logs.AppendText("HMAC Session Key\n");
                logs.AppendText(generateHexStringFromByteArray(HMAC_Key) + "\n" + " HMAC Key size: " + HMAC_Key.Length + "\n");

                logs.AppendText("HMAC Session Key String\n");
                logs.AppendText(hmac_key_string + "\n" + " HMAC Key size: " + HMAC_Key.Length + "\n");

                //encrypting the HMAC session key with the public key of the client
                byte[] encrypted_session_key_byte = encryptWithRSA(hmac_key_string, 4096, pubKeyClient);
                string encrypted_session_key_string = Encoding.Default.GetString(encrypted_session_key_byte);
                encrypted_session_key_string = encrypted_session_key_string.Substring(0, encrypted_session_key_string.IndexOf("\0"));
                logs.AppendText("Encrypted HMAC Session Key\n");
                logs.AppendText(generateHexStringFromByteArray(encrypted_session_key_byte) + "\n" + "Encrypted HMAC Key size: " + encrypted_session_key_byte.Length + "\n");

                //appending the positive acknowledgement message to encypted HMAC session key
                string positive_ack_string  = "POS_ACK";
                byte[] positive_ack_byte = Encoding.Default.GetBytes(positive_ack_string);

                byte[] message_byte = new byte[519];

                Array.Copy(positive_ack_byte, 0, message_byte, 0, 7);
                Array.Copy(encrypted_session_key_byte, 0, message_byte, 7, 512);
                string message = Encoding.Default.GetString(message_byte);
                message = message.Substring(0, message.IndexOf("\0"));

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

                byte[] last = new byte[6];
                thisClient.Receive(last);
                string last_message = Encoding.Default.GetString(last);

                if (last_message == "OKBRUH")
                {
                    logs.AppendText("Client " + clientName + " has authanticated to the server, protocol completed!\n");
                    //Starts listening to the client
                    clientSessionKeys.Add(hmac_key_string);//adding the sesh key with the client to memory
                    Receive(thisClient, clientName, pubKeyClient, hmac_key_string);
                }
                else if (last_message == "NOBRUH")
                {
                    logs.AppendText("Client " + clientName + " had problem in the last step of the protocol, could not connect!\n");
                }
                else
                    logs.AppendText("Generic error!\n");
                
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
                thisClient.Send(message_signature);

                logs.AppendText("Signature of the client " + clientName + " over the 128-bit random value could not verified\n");
                logs.AppendText(clientName + " disconnected.\n");
                clientList.Remove(clientName);
                logs.AppendText("Current Client List:\n");
                foreach (string user in clientList)
                {
                    logs.AppendText("--" + user + "\n");
                }
                //thisClient.Close();
            }
        }
        private void Receive(Socket thisClient, string username, string pubKeyClient, string sessionKey)
        {
            bool connected = true;
            byte[] sessionkeybytes = Encoding.Default.GetBytes(sessionKey);
            logs.AppendText("Client session key is \n");
            logs.AppendText(generateHexStringFromByteArray(sessionkeybytes) + "\n");

            while (connected && !terminating)
            {

                try
                {
                    // Receive the operation information
                    Byte[] receivedInfoHeader = new Byte[1];
                    thisClient.Receive(receivedInfoHeader);


                    if (receivedInfoHeader[0] == 0) //Upload
                    {
                        Byte[] upload_header = new Byte[6];
                        upload_header = Encoding.Default.GetBytes("UPLOAD");
                        thisClient.Send(upload_header);

                        // Receive the incoming File's name and size
                        Byte[] fileProperties = new Byte[256]; // First 128 Bytes are for Name, Last 128 for Size
                        thisClient.Receive(fileProperties); // Receive the Buffer


                        // Take the file name from the buffer
                        string fileName = Encoding.Default.GetString(fileProperties.Take(128).ToArray());


                        // Format the file name
                        fileName = fileName.Substring(0, fileName.IndexOf("\0"));
                        fileName = username + "_0"; // incremental seyi eklenecek
                        string fileName_basic = fileName;



                        // Read filenames to determine the final file name
                        int filecount = 0;
                        bool terminate = false;
                        while (!terminate)
                        {
                            if (File.Exists(textBox_database_path.Text + "/" + fileName_basic + ".txt"))
                            {
                                filecount++;
                                fileName_basic = fileName.Split('_')[0] + "_" + filecount.ToString();
                            }
                            else
                            {
                                terminate = true;
                            }
                        }
                        fileName_basic = fileName_basic + ".txt";


                        // Take the file size from buffer
                        int fileSize = Int32.Parse(Encoding.Default.GetString(fileProperties.Skip(128).Take(128).ToArray()));

                        // Get the encrypted file 
                        Byte[] bufferEncrypted = new Byte[fileSize]; // The buffer size is allocated by the file size
                        thisClient.Receive(bufferEncrypted);
                        string enc_string = Encoding.Default.GetString(bufferEncrypted);


                        logs.AppendText("Recieved encrypted file is: \n");
                        logs.AppendText(generateHexStringFromByteArray(bufferEncrypted) + "\n\n");




                        // Verify it using session authentication key for that client 
                        string key = sessionKey;
                        byte[] key_bytes = Encoding.Default.GetBytes(key);

                        logs.AppendText("Client session key is \n");
                        logs.AppendText(generateHexStringFromByteArray(key_bytes) + "\n\n");


                        byte[] hmac_toverify = applyHMACwithSHA512(enc_string, key_bytes);
                        string hmac_toverify_string = Encoding.Default.GetString(hmac_toverify);

                        logs.AppendText("Generated HMAC  \n");
                        logs.AppendText(generateHexStringFromByteArray(hmac_toverify) + "\n\n");

                        // Get the HMAC 
                        Byte[] bufferHMAC = new Byte[hmac_toverify_string.Length]; // The buffer size is allocated by the file size
                        thisClient.Receive(bufferHMAC);
                        string hmac_string = Encoding.Default.GetString(bufferHMAC);
                        //hmac_string = hmac_string.Substring(0, hmac_string.IndexOf("\0"));

                        logs.AppendText("Recieved HMAC is: \n");
                        logs.AppendText(generateHexStringFromByteArray(bufferHMAC) + "\n\n");


                        // If verified store the file //Client is informed with a signed message that contains new filename
                        if (hmac_toverify_string == hmac_string)
                        {

                            // Create the file and write into it 
                            /*BinaryWriter bWrite = new BinaryWriter(File.Open (textBox_database_path.Text + "/" + fileName_basic, FileMode.Append));
                            bWrite.Write(generateHexStringFromByteArray(bufferEncrypted));
                            bWrite.Close();
                            bufferEncrypted = null; // In order to prevent creating files over and over again*/
                            //string hex_bufferEncrypted = generateHexStringFromByteArray(bufferEncrypted);
                            //byte[] byte_hex_bufferEncrypted = Encoding.Default.GetBytes(hex_bufferEncrypted);

                            //string hex_bufferEncrypted = generateHexStringFromByteArray(bufferEncrypted);
                            File.WriteAllBytes(textBox_database_path.Text + "/" + fileName_basic, bufferEncrypted);

                            //Send  message to the client
                            byte[] filenameByte = Encoding.Default.GetBytes(fileName_basic);
                            logs.AppendText("Filename hex is : ");
                            logs.AppendText(generateHexStringFromByteArray(filenameByte) + "\n");
                            thisClient.Send(filenameByte);
                            logs.AppendText("Sent filename to the client is " + fileName_basic + "\n");

                            //Sign the filenameme
                            byte[] signed_filename = signWithRSA(fileName_basic, 4096, privateKey);

                            //Send signed message to the client
                            thisClient.Send(signed_filename);
                            logs.AppendText("Signed file name is : ");
                            logs.AppendText(generateHexStringFromByteArray(signed_filename) + "\n");

                        }

                        // If not verified inform the client with signed message 
                        else
                        {
                            //Send  message to the client
                            thisClient.Send(Encoding.Default.GetBytes("neg_ack"));
                            logs.AppendText("Negative ack is :");
                            logs.AppendText(Encoding.Default.GetBytes("neg_ack") + "\n");


                            //Sign the negative ack
                            byte[] signed_ack = signWithRSA("neg_ack", 4096, privateKey);


                            //Send signed message to the client
                            thisClient.Send(signed_ack);
                            logs.AppendText("Signed negative ack is :");
                            logs.AppendText(generateHexStringFromByteArray(signed_ack) + "\n");


                        }
                    }
                    else if (receivedInfoHeader[0] == 1)// request/download
                    {
                        //sends the header for the download operation
                        Byte[] download_header = new Byte[6];
                        download_header = Encoding.Default.GetBytes("DOLOAD");
                        thisClient.Send(download_header);

                        //receiving filename from client
                        Byte[] filename = new Byte[64];
                        thisClient.Receive(filename);
                        string filename_string = Encoding.Default.GetString(filename).Trim('\0');
                        logs.AppendText("File: "+ filename_string + " is requested to be downloaded by the client "+ username + "\n");

                        //receiving signature
                        byte[] filename_signature = new byte[512];
                        thisClient.Receive(filename_signature);

                        if(verifyWithRSA(filename_string, 4096, pubKeyClient, filename_signature))
                        {
                            logs.AppendText("Signature of the filename has been verified\n");
                            //check whether given file exists,
                            string fileOwner = filename_string.Split('_')[0];
                            if (File.Exists(textBox_database_path.Text + "/" + filename_string))
                            {
                                if (clientList.Exists(x => x == fileOwner))//file owner of the client is online at the moment
                                {
                                    if (username == fileOwner)// given file belongs to the client
                                    {
                                        // Create the file and write into it 
                                        //BinaryReader reader = new BinaryReader(File.Open(textBox_database_path.Text + "/" + filename_string, FileMode.Open));
                                        //string enc_file;
                                        //enc_file = reader.ReadString();
                                        //reader.Close();
                                        byte[] enc_file = File.ReadAllBytes(textBox_database_path.Text + "/" + filename_string);
                                        string enc_file_string = generateHexStringFromByteArray(enc_file);
                                        //enc_file = enc_file.Substring(0, enc_file.IndexOf("\0"));

                                        logs.AppendText("File: " + filename_string + " will be sent to client: "+ username + "!\n");
                                        logs.AppendText("Hex Content: "+ enc_file_string + "\n");

                                        Byte[] download_mode = new Byte[1];
                                        download_mode[0] = 10;
                                        thisClient.Send(download_mode);

                                        //send encrypted file
                                        //byte[] file_buffer = hexStringToByteArray(enc_file_string);
                                        thisClient.Send(enc_file);

                                        //send signature over encrypted file
                                        byte[] sig_enc_file = signWithRSA(enc_file_string, 4096, privateKey);
                                        thisClient.Send(sig_enc_file);
                                        logs.AppendText("Signature of the encrypted file has sent: " + generateHexStringFromByteArray(sig_enc_file) + "\n");
                                    }
                                    else//file will be requested from other client
                                    {
                                        //TO DO: request protocol to other client will be implemented here
                                        int clientIndex = 0;
                                        bool checker = false;
                                        for (int i = 0; i < clientList.Count && !checker; i++)
                                        {
                                            if(clientList[i] == fileOwner)
                                            {
                                                clientIndex = i;
                                                checker = true;
                                            }
                                        }
                                        //gets the clientSocket for the owner of the file
                                        Socket fileOwnerClient = clientSockets[clientIndex];
                                        string fileowner_sesskey = clientSessionKeys[clientIndex];

                                        //sends request header to fileOwnerClient
                                        Byte[] header = new Byte[6];
                                        header = Encoding.Default.GetBytes("REQUST");
                                        fileOwnerClient.Send(header);

                                        Byte[] reqPropertiesBuffer = new Byte[128+128+pubKeyClient.Length+64];
                                        Array.Copy(Encoding.Default.GetBytes(filename_string), reqPropertiesBuffer, filename_string.Length);
                                        Array.Copy(Encoding.Default.GetBytes(username), 0, reqPropertiesBuffer, 128, username.Length);
                                        Array.Copy(Encoding.Default.GetBytes(pubKeyClient), 0, reqPropertiesBuffer, 256, pubKeyClient.Length);
                                        byte[] hmac_request = applyHMACwithSHA512(filename_string + username + pubKeyClient, Encoding.Default.GetBytes(fileowner_sesskey));
                                        Array.Copy(hmac_request, 0, reqPropertiesBuffer, 256 + pubKeyClient.Length, hmac_request.Length);


                                        logs.AppendText("File downlaod request will be sent:\n");
                                        logs.AppendText("File owner: "+ fileOwner+ "\n");
                                        logs.AppendText("Requestor: " + username + "\n");
                                        logs.AppendText("File requested: " + filename_string + "\n");
                                        logs.AppendText("Public Key of the requester: " + generateHexStringFromByteArray(Encoding.Default.GetBytes(pubKeyClient))+ "\nLength: "+pubKeyClient.Length+"\n");
                                        logs.AppendText("HMAC appended to the message: " + generateHexStringFromByteArray(hmac_request) + "\n");

                                        // Send the filePropertiesBuffer to the Server
                                        fileOwnerClient.Send(reqPropertiesBuffer);                                       

                                        byte[] reqResponse = new byte[579];                                                                              
                                        fileOwnerClient.Receive(reqResponse);
                                        reqResponse = Encoding.Default.GetBytes(Encoding.Default.GetString(reqResponse).Trim('\0'));
                                        int length = reqResponse.Length;

                                        string response = Encoding.Default.GetString(reqResponse.Take(length-64).ToArray());
                                        string HMAC_response = Encoding.Default.GetString(reqResponse.Skip(length - 64).Take(64).ToArray());
                                        logs.AppendText("HMAC received from the fileOwners response: " + generateHexStringFromByteArray(Encoding.Default.GetBytes(HMAC_response)) + "\n");

                                        byte [] HMAC_response_generated_byte = applyHMACwithSHA512(response,Encoding.Default.GetBytes(fileowner_sesskey));
                                        logs.AppendText("HMAC generated from the fileOwners response: " + generateHexStringFromByteArray(HMAC_response_generated_byte) + "\n");
                                        string HMAC_response_generated = Encoding.Default.GetString(HMAC_response_generated_byte);


                                        if (HMAC_response_generated == HMAC_response)
                                        {
                                            logs.AppendText("Signature of the fileowner's response has been verified!\n");

                                            string response_ack = Encoding.Default.GetString(reqResponse.Take(3).ToArray());
                                            if (response_ack == "NOO")
                                            {
                                                string message_string = "Permission denied by " + fileOwner + " to download the file: " + filename_string + "\nRequester: " + username + "\n";

                                                message_print_and_send(message_string, thisClient);

                                            }
                                            else if (response_ack == "OK!")
                                            {                                              
                                                logs.AppendText("Permission granted\n");

                                                byte[] enc_file = File.ReadAllBytes(textBox_database_path.Text + "/" + filename_string);
                                                string enc_file_string = generateHexStringFromByteArray(enc_file);
                                                //enc_file = enc_file.Substring(0, enc_file.IndexOf("\0"));

                                                logs.AppendText("File: " + filename_string + " will be sent to client: " + username + "!\n");
                                                logs.AppendText("Hex Content: " + enc_file_string + "\n");

                                                byte[] enc_file_and_items = new byte[length - (64 + 3) + enc_file.Length];
                                                byte[] aes_parameters = reqResponse.Skip(3).Take(length - (64 + 3)).ToArray();
                                                Array.Copy(aes_parameters, 0, enc_file_and_items, 0, aes_parameters.Length);
                                                Array.Copy(enc_file, 0, enc_file_and_items, aes_parameters.Length, enc_file.Length);

                                                byte[] HMAC_enc_file_and_items = signWithRSA(Encoding.Default.GetString(enc_file_and_items), 4096, privateKey);
                                                logs.AppendText("HMAC of enc(aes_parameters)|encypted_file: " + generateHexStringFromByteArray(HMAC_enc_file_and_items) + "\n");

                                                byte[] file_everything = new byte[enc_file_and_items.Length + HMAC_enc_file_and_items.Length];
                                                Array.Copy(enc_file_and_items, 0, file_everything, 0, enc_file_and_items.Length);
                                                Array.Copy(HMAC_enc_file_and_items, 0, file_everything, enc_file_and_items.Length, HMAC_enc_file_and_items.Length);
                                                logs.AppendText("Total packet size: " + (enc_file_and_items.Length + HMAC_enc_file_and_items.Length) + "\n");

                                                //Sends the mode for the download
                                                byte[] download_mode = new byte[1];
                                                download_mode[0] = 11;
                                                thisClient.Send(download_mode);

                                                //Sends the packet size
                                                byte[] packet_size = Encoding.Default.GetBytes(file_everything.Length.ToString());
                                                logs.AppendText("Size of the packet: " + file_everything.Length + "\n");
                                                thisClient.Send(packet_size);

                                                byte[] file_size = Encoding.Default.GetBytes(enc_file.Length.ToString());
                                                logs.AppendText("Size of the packet: " + enc_file.Length + "\n");
                                                thisClient.Send(file_size);

                                                //Sends the packet
                                                logs.AppendText("Hex content of the packet: " + generateHexStringFromByteArray(file_everything) + "\n");
                                                thisClient.Send(file_everything);
                                            }
                                        }
                                        else
                                        {
                                            string message_string = "Signature of the fileOwners response is NOT verified!\n";

                                            message_print_and_send(message_string,thisClient);
                                        }                                       
                                    }
                                }
                                else
                                {
                                    string message_string = "File owner (" + filename_string + ") is not online at the moment, try again later to get download request!\n";
                                    message_print_and_send(message_string,thisClient);                                  

                                }

                            }
                            else
                            {
                                string message_string = "There is no such file exists: " + filename_string + "!\n";
                                message_print_and_send(message_string,thisClient);
                                
                            }
                        }
                        else
                        {
                            string message_string = "Signature over sended filename for download request is not verified for client " + username + "!\n";
                            message_print_and_send(message_string,thisClient);                           
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
                            clientList.Remove(username);//removes username if disconnected
                            int index = clientList.IndexOf(username);
                            clientSessionKeys.Remove(clientSessionKeys[index]);
                            // current clientlist will be printed here
                            logs.AppendText("Current Client List:\n");
                            foreach (string user in clientList)
                            {
                                logs.AppendText("--" + user + "\n");
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
                button_fileExplorer.Enabled = false;
                button_database_explorer.Enabled = true;
                //textBox_port.Enabled = true;
                //button_serverStart.Enabled = true;
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

        // HMAC with SHA-512
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

        private void button_database_explorer_Click(object sender, EventArgs e)
        {
            FolderBrowserDialog dialog = new FolderBrowserDialog();
            dialog.ShowDialog();
            string db_location = dialog.SelectedPath;
            textBox_database_path.Text = db_location;

            if (Directory.Exists(db_location))
            {
                button_folderExplorer.Enabled = false;
                textBox_port.Enabled = true;
                button_serverStart.Enabled = true;
            }
        }

        private void message_print_and_send(string message_string, Socket thisClient)
        {
            byte[] message = new byte[256];
            message = Encoding.Default.GetBytes(message_string);
            logs.AppendText(message_string);

            byte[] download_mode = new byte[1];
            download_mode[0] = 12;
            thisClient.Send(download_mode);
            thisClient.Send(message);
        }
    }
}
