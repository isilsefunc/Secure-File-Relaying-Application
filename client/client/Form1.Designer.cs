﻿namespace client
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.textBox_ip = new System.Windows.Forms.TextBox();
            this.textBox_port = new System.Windows.Forms.TextBox();
            this.textBox_username = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.logs = new System.Windows.Forms.RichTextBox();
            this.button_connect = new System.Windows.Forms.Button();
            this.button_disconnect = new System.Windows.Forms.Button();
            this.textBox_pass = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.button_fileExplorer = new System.Windows.Forms.Button();
            this.label5 = new System.Windows.Forms.Label();
            this.textBox_key = new System.Windows.Forms.TextBox();
            this.button_folderExplorer = new System.Windows.Forms.Button();
            this.label6 = new System.Windows.Forms.Label();
            this.textBox_repository = new System.Windows.Forms.TextBox();
            this.upload_button = new System.Windows.Forms.Button();
            this.download_button = new System.Windows.Forms.Button();
            this.textBox1 = new System.Windows.Forms.TextBox();
            this.authenticate_button = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // textBox_ip
            // 
            this.textBox_ip.Enabled = false;
            this.textBox_ip.Location = new System.Drawing.Point(244, 84);
            this.textBox_ip.Margin = new System.Windows.Forms.Padding(6);
            this.textBox_ip.Name = "textBox_ip";
            this.textBox_ip.Size = new System.Drawing.Size(278, 31);
            this.textBox_ip.TabIndex = 0;
            // 
            // textBox_port
            // 
            this.textBox_port.Enabled = false;
            this.textBox_port.Location = new System.Drawing.Point(244, 156);
            this.textBox_port.Margin = new System.Windows.Forms.Padding(6);
            this.textBox_port.Name = "textBox_port";
            this.textBox_port.Size = new System.Drawing.Size(278, 31);
            this.textBox_port.TabIndex = 1;
            // 
            // textBox_username
            // 
            this.textBox_username.Enabled = false;
            this.textBox_username.Location = new System.Drawing.Point(244, 233);
            this.textBox_username.Margin = new System.Windows.Forms.Padding(6);
            this.textBox_username.Name = "textBox_username";
            this.textBox_username.Size = new System.Drawing.Size(278, 31);
            this.textBox_username.TabIndex = 2;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(40, 91);
            this.label1.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(37, 25);
            this.label1.TabIndex = 3;
            this.label1.Text = "IP:";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(40, 161);
            this.label2.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(57, 25);
            this.label2.TabIndex = 4;
            this.label2.Text = "Port:";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(40, 239);
            this.label3.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(116, 25);
            this.label3.TabIndex = 5;
            this.label3.Text = "Username:";
            // 
            // logs
            // 
            this.logs.Location = new System.Drawing.Point(640, 84);
            this.logs.Margin = new System.Windows.Forms.Padding(6);
            this.logs.Name = "logs";
            this.logs.ReadOnly = true;
            this.logs.Size = new System.Drawing.Size(772, 531);
            this.logs.TabIndex = 6;
            this.logs.Text = "";
            // 
            // button_connect
            // 
            this.button_connect.Enabled = false;
            this.button_connect.Location = new System.Drawing.Point(244, 287);
            this.button_connect.Margin = new System.Windows.Forms.Padding(6);
            this.button_connect.Name = "button_connect";
            this.button_connect.Size = new System.Drawing.Size(278, 44);
            this.button_connect.TabIndex = 7;
            this.button_connect.Text = "Connect";
            this.button_connect.UseVisualStyleBackColor = true;
            this.button_connect.Click += new System.EventHandler(this.button_connect_Click);
            // 
            // button_disconnect
            // 
            this.button_disconnect.Enabled = false;
            this.button_disconnect.Location = new System.Drawing.Point(244, 343);
            this.button_disconnect.Margin = new System.Windows.Forms.Padding(6);
            this.button_disconnect.Name = "button_disconnect";
            this.button_disconnect.Size = new System.Drawing.Size(274, 44);
            this.button_disconnect.TabIndex = 8;
            this.button_disconnect.Text = "Disconnect";
            this.button_disconnect.UseVisualStyleBackColor = true;
            this.button_disconnect.Click += new System.EventHandler(this.button_disconnect_Click);
            // 
            // textBox_pass
            // 
            this.textBox_pass.Enabled = false;
            this.textBox_pass.Location = new System.Drawing.Point(244, 471);
            this.textBox_pass.Margin = new System.Windows.Forms.Padding(6);
            this.textBox_pass.Name = "textBox_pass";
            this.textBox_pass.Size = new System.Drawing.Size(278, 31);
            this.textBox_pass.TabIndex = 9;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(40, 477);
            this.label4.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(112, 25);
            this.label4.TabIndex = 10;
            this.label4.Text = "Password:";
            // 
            // button_fileExplorer
            // 
            this.button_fileExplorer.Location = new System.Drawing.Point(244, 667);
            this.button_fileExplorer.Margin = new System.Windows.Forms.Padding(6);
            this.button_fileExplorer.Name = "button_fileExplorer";
            this.button_fileExplorer.Size = new System.Drawing.Size(278, 44);
            this.button_fileExplorer.TabIndex = 14;
            this.button_fileExplorer.Text = "File Explorer";
            this.button_fileExplorer.UseVisualStyleBackColor = true;
            this.button_fileExplorer.Click += new System.EventHandler(this.button_fileExplorer_Click);
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(36, 624);
            this.label5.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(143, 25);
            this.label5.TabIndex = 13;
            this.label5.Text = "Key Location:";
            // 
            // textBox_key
            // 
            this.textBox_key.Enabled = false;
            this.textBox_key.Location = new System.Drawing.Point(244, 617);
            this.textBox_key.Margin = new System.Windows.Forms.Padding(6);
            this.textBox_key.Name = "textBox_key";
            this.textBox_key.Size = new System.Drawing.Size(274, 31);
            this.textBox_key.TabIndex = 12;
            // 
            // button_folderExplorer
            // 
            this.button_folderExplorer.Enabled = false;
            this.button_folderExplorer.Location = new System.Drawing.Point(244, 822);
            this.button_folderExplorer.Margin = new System.Windows.Forms.Padding(6);
            this.button_folderExplorer.Name = "button_folderExplorer";
            this.button_folderExplorer.Size = new System.Drawing.Size(278, 44);
            this.button_folderExplorer.TabIndex = 17;
            this.button_folderExplorer.Text = "Folder Explorer";
            this.button_folderExplorer.UseVisualStyleBackColor = true;
            this.button_folderExplorer.Click += new System.EventHandler(this.button_folderExplorer_Click);
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(40, 778);
            this.label6.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(121, 25);
            this.label6.TabIndex = 16;
            this.label6.Text = "Repository:";
            // 
            // textBox_repository
            // 
            this.textBox_repository.Enabled = false;
            this.textBox_repository.Location = new System.Drawing.Point(244, 772);
            this.textBox_repository.Margin = new System.Windows.Forms.Padding(6);
            this.textBox_repository.Name = "textBox_repository";
            this.textBox_repository.Size = new System.Drawing.Size(278, 31);
            this.textBox_repository.TabIndex = 15;
            // 
            // upload_button
            // 
            this.upload_button.Location = new System.Drawing.Point(640, 914);
            this.upload_button.Name = "upload_button";
            this.upload_button.Size = new System.Drawing.Size(271, 44);
            this.upload_button.TabIndex = 18;
            this.upload_button.Text = "Upload";
            this.upload_button.UseVisualStyleBackColor = true;
            this.upload_button.Click += new System.EventHandler(this.upload_button_Click);
            // 
            // download_button
            // 
            this.download_button.Location = new System.Drawing.Point(977, 914);
            this.download_button.Name = "download_button";
            this.download_button.Size = new System.Drawing.Size(263, 43);
            this.download_button.TabIndex = 19;
            this.download_button.Text = "Download Request";
            this.download_button.UseVisualStyleBackColor = true;
            // 
            // textBox1
            // 
            this.textBox1.Location = new System.Drawing.Point(977, 858);
            this.textBox1.Name = "textBox1";
            this.textBox1.Size = new System.Drawing.Size(263, 31);
            this.textBox1.TabIndex = 20;
            // 
            // authenticate_button
            // 
            this.authenticate_button.Enabled = false;
            this.authenticate_button.Location = new System.Drawing.Point(244, 523);
            this.authenticate_button.Name = "authenticate_button";
            this.authenticate_button.Size = new System.Drawing.Size(278, 44);
            this.authenticate_button.TabIndex = 21;
            this.authenticate_button.Text = "Authenticate";
            this.authenticate_button.UseVisualStyleBackColor = true;
            this.authenticate_button.Click += new System.EventHandler(this.authenticate_button_Click);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(12F, 25F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1472, 1072);
            this.Controls.Add(this.authenticate_button);
            this.Controls.Add(this.textBox1);
            this.Controls.Add(this.download_button);
            this.Controls.Add(this.upload_button);
            this.Controls.Add(this.button_folderExplorer);
            this.Controls.Add(this.label6);
            this.Controls.Add(this.textBox_repository);
            this.Controls.Add(this.button_fileExplorer);
            this.Controls.Add(this.label5);
            this.Controls.Add(this.textBox_key);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.textBox_pass);
            this.Controls.Add(this.button_disconnect);
            this.Controls.Add(this.button_connect);
            this.Controls.Add(this.logs);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.textBox_username);
            this.Controls.Add(this.textBox_port);
            this.Controls.Add(this.textBox_ip);
            this.Margin = new System.Windows.Forms.Padding(6);
            this.Name = "Form1";
            this.Text = "Form1";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TextBox textBox_ip;
        private System.Windows.Forms.TextBox textBox_port;
        private System.Windows.Forms.TextBox textBox_username;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.RichTextBox logs;
        private System.Windows.Forms.Button button_connect;
        private System.Windows.Forms.Button button_disconnect;
        private System.Windows.Forms.TextBox textBox_pass;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.Button button_fileExplorer;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.TextBox textBox_key;
        private System.Windows.Forms.Button button_folderExplorer;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.TextBox textBox_repository;
        private System.Windows.Forms.Button upload_button;
        private System.Windows.Forms.Button download_button;
        private System.Windows.Forms.TextBox textBox1;
        private System.Windows.Forms.Button authenticate_button;
    }
}
