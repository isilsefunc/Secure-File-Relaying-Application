namespace cs432_project_server
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
            this.textBox_key = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.textBox_port = new System.Windows.Forms.TextBox();
            this.logs = new System.Windows.Forms.RichTextBox();
            this.button_fileExplorer = new System.Windows.Forms.Button();
            this.button_serverStart = new System.Windows.Forms.Button();
            this.button_folderExplorer = new System.Windows.Forms.Button();
            this.label3 = new System.Windows.Forms.Label();
            this.textBox_repository = new System.Windows.Forms.TextBox();
            this.button_database_explorer = new System.Windows.Forms.Button();
            this.textBox_database_path = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // textBox_key
            // 
            this.textBox_key.Enabled = false;
            this.textBox_key.Location = new System.Drawing.Point(238, 86);
            this.textBox_key.Margin = new System.Windows.Forms.Padding(6);
            this.textBox_key.Name = "textBox_key";
            this.textBox_key.Size = new System.Drawing.Size(196, 31);
            this.textBox_key.TabIndex = 0;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(50, 92);
            this.label1.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(143, 25);
            this.label1.TabIndex = 1;
            this.label1.Text = "Key Location:";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(50, 568);
            this.label2.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(138, 25);
            this.label2.TabIndex = 3;
            this.label2.Text = "Port Number:";
            // 
            // textBox_port
            // 
            this.textBox_port.Enabled = false;
            this.textBox_port.Location = new System.Drawing.Point(238, 562);
            this.textBox_port.Margin = new System.Windows.Forms.Padding(6);
            this.textBox_port.Name = "textBox_port";
            this.textBox_port.Size = new System.Drawing.Size(196, 31);
            this.textBox_port.TabIndex = 2;
            // 
            // logs
            // 
            this.logs.Location = new System.Drawing.Point(522, 86);
            this.logs.Margin = new System.Windows.Forms.Padding(6);
            this.logs.Name = "logs";
            this.logs.ReadOnly = true;
            this.logs.Size = new System.Drawing.Size(660, 518);
            this.logs.TabIndex = 4;
            this.logs.Text = "";
            // 
            // button_fileExplorer
            // 
            this.button_fileExplorer.Location = new System.Drawing.Point(238, 136);
            this.button_fileExplorer.Margin = new System.Windows.Forms.Padding(6);
            this.button_fileExplorer.Name = "button_fileExplorer";
            this.button_fileExplorer.Size = new System.Drawing.Size(200, 44);
            this.button_fileExplorer.TabIndex = 5;
            this.button_fileExplorer.Text = "File Explorer";
            this.button_fileExplorer.UseVisualStyleBackColor = true;
            this.button_fileExplorer.Click += new System.EventHandler(this.button_fileExplorer_Click);
            // 
            // button_serverStart
            // 
            this.button_serverStart.Enabled = false;
            this.button_serverStart.Location = new System.Drawing.Point(238, 612);
            this.button_serverStart.Margin = new System.Windows.Forms.Padding(6);
            this.button_serverStart.Name = "button_serverStart";
            this.button_serverStart.Size = new System.Drawing.Size(200, 44);
            this.button_serverStart.TabIndex = 6;
            this.button_serverStart.Text = "Start Server";
            this.button_serverStart.UseVisualStyleBackColor = true;
            this.button_serverStart.Click += new System.EventHandler(this.button_serverStart_Click);
            // 
            // button_folderExplorer
            // 
            this.button_folderExplorer.Enabled = false;
            this.button_folderExplorer.Location = new System.Drawing.Point(238, 317);
            this.button_folderExplorer.Margin = new System.Windows.Forms.Padding(6);
            this.button_folderExplorer.Name = "button_folderExplorer";
            this.button_folderExplorer.Size = new System.Drawing.Size(200, 44);
            this.button_folderExplorer.TabIndex = 9;
            this.button_folderExplorer.Text = "Folder Explorer";
            this.button_folderExplorer.UseVisualStyleBackColor = true;
            this.button_folderExplorer.Click += new System.EventHandler(this.button_folderExplorer_Click);
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(50, 273);
            this.label3.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(121, 25);
            this.label3.TabIndex = 8;
            this.label3.Text = "Repository:";
            // 
            // textBox_repository
            // 
            this.textBox_repository.Enabled = false;
            this.textBox_repository.Location = new System.Drawing.Point(238, 267);
            this.textBox_repository.Margin = new System.Windows.Forms.Padding(6);
            this.textBox_repository.Name = "textBox_repository";
            this.textBox_repository.Size = new System.Drawing.Size(196, 31);
            this.textBox_repository.TabIndex = 7;
            // 
            // button_database_explorer
            // 
            this.button_database_explorer.Enabled = false;
            this.button_database_explorer.Location = new System.Drawing.Point(238, 465);
            this.button_database_explorer.Name = "button_database_explorer";
            this.button_database_explorer.Size = new System.Drawing.Size(196, 47);
            this.button_database_explorer.TabIndex = 10;
            this.button_database_explorer.Text = "Folder Explorer";
            this.button_database_explorer.UseVisualStyleBackColor = true;
            this.button_database_explorer.Click += new System.EventHandler(this.button_database_explorer_Click);
            // 
            // textBox_database_path
            // 
            this.textBox_database_path.Location = new System.Drawing.Point(238, 412);
            this.textBox_database_path.Name = "textBox_database_path";
            this.textBox_database_path.Size = new System.Drawing.Size(196, 31);
            this.textBox_database_path.TabIndex = 11;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(50, 412);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(154, 25);
            this.label4.TabIndex = 12;
            this.label4.Text = "Database Path";
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(12F, 25F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1354, 767);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.textBox_database_path);
            this.Controls.Add(this.button_database_explorer);
            this.Controls.Add(this.button_folderExplorer);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.textBox_repository);
            this.Controls.Add(this.button_serverStart);
            this.Controls.Add(this.button_fileExplorer);
            this.Controls.Add(this.logs);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.textBox_port);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.textBox_key);
            this.Margin = new System.Windows.Forms.Padding(6);
            this.Name = "Form1";
            this.Text = "Form1";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TextBox textBox_key;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox textBox_port;
        private System.Windows.Forms.RichTextBox logs;
        private System.Windows.Forms.Button button_fileExplorer;
        private System.Windows.Forms.Button button_serverStart;
        private System.Windows.Forms.Button button_folderExplorer;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.TextBox textBox_repository;
        private System.Windows.Forms.Button button_database_explorer;
        private System.Windows.Forms.TextBox textBox_database_path;
        private System.Windows.Forms.Label label4;
    }
}

