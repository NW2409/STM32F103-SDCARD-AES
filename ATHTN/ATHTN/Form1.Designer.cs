namespace ATHTN
{
    partial class Form1
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            this.tabControl1 = new System.Windows.Forms.TabControl();
            this.tabLogin = new System.Windows.Forms.TabPage();
            this.label2 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.txtUsername = new System.Windows.Forms.TextBox();
            this.txtPassword = new System.Windows.Forms.TextBox();
            this.btnLogin = new System.Windows.Forms.Button();
            this.tabMain = new System.Windows.Forms.TabPage();
            this.btnSelectFile = new System.Windows.Forms.Button();
            this.btnEncryptSend = new System.Windows.Forms.Button();
            this.btnGetList = new System.Windows.Forms.Button();
            this.btnDecryptFile = new System.Windows.Forms.Button();
            this.lstFiles = new System.Windows.Forms.ListBox();
            this.txtContent = new System.Windows.Forms.TextBox();
            this.tabControl1.SuspendLayout();
            this.tabLogin.SuspendLayout();
            this.tabMain.SuspendLayout();
            this.SuspendLayout();
            // 
            // tabControl1
            // 
            this.tabControl1.Controls.Add(this.tabLogin);
            this.tabControl1.Controls.Add(this.tabMain);
            this.tabControl1.Location = new System.Drawing.Point(0, 0);
            this.tabControl1.Margin = new System.Windows.Forms.Padding(4);
            this.tabControl1.Name = "tabControl1";
            this.tabControl1.SelectedIndex = 0;
            this.tabControl1.Size = new System.Drawing.Size(800, 600);
            this.tabControl1.TabIndex = 0;
            // 
            // tabLogin
            // 
            this.tabLogin.BackColor = System.Drawing.Color.LightGray;
            this.tabLogin.Controls.Add(this.label2);
            this.tabLogin.Controls.Add(this.label1);
            this.tabLogin.Controls.Add(this.txtUsername);
            this.tabLogin.Controls.Add(this.txtPassword);
            this.tabLogin.Controls.Add(this.btnLogin);
            this.tabLogin.Location = new System.Drawing.Point(4, 29);
            this.tabLogin.Margin = new System.Windows.Forms.Padding(4);
            this.tabLogin.Name = "tabLogin";
            this.tabLogin.Size = new System.Drawing.Size(792, 567);
            this.tabLogin.TabIndex = 0;
            this.tabLogin.Text = "Login";
            // 
            // label2
            // 
            this.label2.BackColor = System.Drawing.Color.Linen;
            this.label2.Location = new System.Drawing.Point(80, 180);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(115, 42);
            this.label2.TabIndex = 4;
            this.label2.Text = "Password";
            // 
            // label1
            // 
            this.label1.BackColor = System.Drawing.Color.Linen;
            this.label1.ForeColor = System.Drawing.Color.Black;
            this.label1.Location = new System.Drawing.Point(82, 111);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(113, 34);
            this.label1.TabIndex = 3;
            this.label1.Text = "Username";
            // 
            // txtUsername
            // 
            this.txtUsername.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.txtUsername.Location = new System.Drawing.Point(260, 111);
            this.txtUsername.Margin = new System.Windows.Forms.Padding(4);
            this.txtUsername.Name = "txtUsername";
            this.txtUsername.Size = new System.Drawing.Size(300, 34);
            this.txtUsername.TabIndex = 0;
            // 
            // txtPassword
            // 
            this.txtPassword.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.txtPassword.Location = new System.Drawing.Point(260, 180);
            this.txtPassword.Margin = new System.Windows.Forms.Padding(4);
            this.txtPassword.Name = "txtPassword";
            this.txtPassword.PasswordChar = '*';
            this.txtPassword.Size = new System.Drawing.Size(300, 34);
            this.txtPassword.TabIndex = 1;
            // 
            // btnLogin
            // 
            this.btnLogin.Font = new System.Drawing.Font("Segoe UI", 10F, System.Drawing.FontStyle.Bold);
            this.btnLogin.Location = new System.Drawing.Point(283, 287);
            this.btnLogin.Margin = new System.Windows.Forms.Padding(4);
            this.btnLogin.Name = "btnLogin";
            this.btnLogin.Size = new System.Drawing.Size(171, 62);
            this.btnLogin.TabIndex = 2;
            this.btnLogin.Text = "Login";
            this.btnLogin.UseVisualStyleBackColor = true;
            this.btnLogin.Click += new System.EventHandler(this.btnLogin_Click);
            // 
            // tabMain
            // 
            this.tabMain.Controls.Add(this.btnSelectFile);
            this.tabMain.Controls.Add(this.btnEncryptSend);
            this.tabMain.Controls.Add(this.btnGetList);
            this.tabMain.Controls.Add(this.btnDecryptFile);
            this.tabMain.Controls.Add(this.lstFiles);
            this.tabMain.Controls.Add(this.txtContent);
            this.tabMain.Enabled = false;
            this.tabMain.Location = new System.Drawing.Point(4, 29);
            this.tabMain.Margin = new System.Windows.Forms.Padding(4);
            this.tabMain.Name = "tabMain";
            this.tabMain.Size = new System.Drawing.Size(792, 567);
            this.tabMain.TabIndex = 1;
            this.tabMain.Text = "Main";
            this.tabMain.UseVisualStyleBackColor = true;
            // 
            // btnSelectFile
            // 
            this.btnSelectFile.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.btnSelectFile.Location = new System.Drawing.Point(30, 30);
            this.btnSelectFile.Margin = new System.Windows.Forms.Padding(4);
            this.btnSelectFile.Name = "btnSelectFile";
            this.btnSelectFile.Size = new System.Drawing.Size(150, 40);
            this.btnSelectFile.TabIndex = 0;
            this.btnSelectFile.Text = "Select File";
            this.btnSelectFile.UseVisualStyleBackColor = true;
            this.btnSelectFile.Click += new System.EventHandler(this.btnSelectFile_Click);
            // 
            // btnEncryptSend
            // 
            this.btnEncryptSend.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.btnEncryptSend.Location = new System.Drawing.Point(188, 30);
            this.btnEncryptSend.Margin = new System.Windows.Forms.Padding(4);
            this.btnEncryptSend.Name = "btnEncryptSend";
            this.btnEncryptSend.Size = new System.Drawing.Size(192, 40);
            this.btnEncryptSend.TabIndex = 1;
            this.btnEncryptSend.Text = "Encrypt And Send";
            this.btnEncryptSend.UseVisualStyleBackColor = true;
            this.btnEncryptSend.Click += new System.EventHandler(this.btnEncryptSend_Click);
            // 
            // btnGetList
            // 
            this.btnGetList.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.btnGetList.Location = new System.Drawing.Point(380, 30);
            this.btnGetList.Margin = new System.Windows.Forms.Padding(4);
            this.btnGetList.Name = "btnGetList";
            this.btnGetList.Size = new System.Drawing.Size(150, 40);
            this.btnGetList.TabIndex = 2;
            this.btnGetList.Text = "Get File List";
            this.btnGetList.UseVisualStyleBackColor = true;
            this.btnGetList.Click += new System.EventHandler(this.btnGetList_Click);
            // 
            // btnDecryptFile
            // 
            this.btnDecryptFile.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.btnDecryptFile.Location = new System.Drawing.Point(540, 30);
            this.btnDecryptFile.Margin = new System.Windows.Forms.Padding(4);
            this.btnDecryptFile.Name = "btnDecryptFile";
            this.btnDecryptFile.Size = new System.Drawing.Size(150, 40);
            this.btnDecryptFile.TabIndex = 3;
            this.btnDecryptFile.Text = "Decrypt File";
            this.btnDecryptFile.UseVisualStyleBackColor = true;
            this.btnDecryptFile.Click += new System.EventHandler(this.btnDecryptFile_Click);
            // 
            // lstFiles
            // 
            this.lstFiles.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.lstFiles.ItemHeight = 28;
            this.lstFiles.Location = new System.Drawing.Point(30, 80);
            this.lstFiles.Margin = new System.Windows.Forms.Padding(4);
            this.lstFiles.Name = "lstFiles";
            this.lstFiles.Size = new System.Drawing.Size(730, 144);
            this.lstFiles.TabIndex = 4;
            this.lstFiles.DoubleClick += new System.EventHandler(this.lstFiles_DoubleClick);
            // 
            // txtContent
            // 
            this.txtContent.Font = new System.Drawing.Font("Consolas", 11F);
            this.txtContent.Location = new System.Drawing.Point(30, 232);
            this.txtContent.Margin = new System.Windows.Forms.Padding(4);
            this.txtContent.Multiline = true;
            this.txtContent.Name = "txtContent";
            this.txtContent.ReadOnly = true;
            this.txtContent.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.txtContent.Size = new System.Drawing.Size(730, 308);
            this.txtContent.TabIndex = 5;
            this.txtContent.WordWrap = false;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 600);
            this.Controls.Add(this.tabControl1);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Margin = new System.Windows.Forms.Padding(4);
            this.Name = "Form1";
            this.Text = "STM32 File Encryption";
            this.tabControl1.ResumeLayout(false);
            this.tabLogin.ResumeLayout(false);
            this.tabLogin.PerformLayout();
            this.tabMain.ResumeLayout(false);
            this.tabMain.PerformLayout();
            this.ResumeLayout(false);

        }

        private System.Windows.Forms.TabControl tabControl1;
        private System.Windows.Forms.TabPage tabLogin;
        private System.Windows.Forms.TextBox txtUsername;
        private System.Windows.Forms.TextBox txtPassword;
        private System.Windows.Forms.Button btnLogin;
        private System.Windows.Forms.TabPage tabMain;
        private System.Windows.Forms.Button btnSelectFile;
        private System.Windows.Forms.Button btnEncryptSend;
        private System.Windows.Forms.Button btnGetList;
        private System.Windows.Forms.Button btnDecryptFile;
        private System.Windows.Forms.ListBox lstFiles;
        private System.Windows.Forms.TextBox txtContent;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label1;
    }
}