using System;
using System.IO;
using System.IO.Ports;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using System.Collections.Generic;
using System.Threading;
using System.Linq;

namespace ATHTN
{
    public partial class Form1 : Form
    {
        private SerialPort serialPort;
        private string derivedKeyHex;
        private string selectedFile = "";
        private const int CHUNK_SIZE = 16;
        private const int TIMEOUT_MS = 5000;
        private const int MAX_RETRIES = 3;
        private bool isLoggedIn = false;

        public Form1()
        {
            InitializeComponent();
            tabControl1.SelectedIndex = 0;
            tabControl1.TabPages[1].Enabled = false;

            txtContent.Multiline = true;
            txtContent.ScrollBars = ScrollBars.Vertical;
            txtContent.WordWrap = true;
            txtContent.ReadOnly = true;
            txtContent.Height = 200;

            tabControl1.Selecting += TabControl1_Selecting;
        }

        private void TabControl1_Selecting(object sender, TabControlCancelEventArgs e)
        {
            if (e.TabPageIndex == 1 && !isLoggedIn)
            {
                e.Cancel = true;
                MessageBox.Show("Vui lòng đăng nhập trước để truy cập tab Main.");
            }
        }

        private string ComputeSHA256Hex(string input)
        {
            using (var sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hash)
                    sb.AppendFormat("{0:x2}", b);
                return sb.ToString();
            }
        }

        // Hàm tính SHA256 cho khối dữ liệu (thêm mới)
        private string ComputeSHA256Hex(byte[] input)
        {
            using (var sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(input);
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hash)
                    sb.AppendFormat("{0:x2}", b);
                return sb.ToString();
            }
        }

        private void btnLogin_Click(object sender, EventArgs e)
        {
            try
            {
                serialPort = new SerialPort("COM5", 115200)
                {
                    Encoding = Encoding.UTF8,
                    NewLine = "\r\n"
                };
                serialPort.Open();

                string username = txtUsername.Text.Trim();
                string password = txtPassword.Text.Trim();

                // Kiểm tra hợp lệ
                if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
                {
                    MessageBox.Show("Vui lòng nhập tài khoản và mật khẩu.", "Lỗi đăng nhập");
                    txtContent.AppendText("❌ Thiếu tài khoản hoặc mật khẩu.\r\n");
                    serialPort.Close();
                    return;
                }

                // Kiểm tra username phải là "admin"
                if (username.ToLower() != "admin")
                {
                    MessageBox.Show("Tài khoản hoặc mật khẩu không hợp lệ");
                   // txtContent.AppendText("❌ Sai tài khoản (chỉ chấp nhận 'admin').\r\n");
                    serialPort.Close();
                    return;
                }

                // Tính SHA256 của mật khẩu
                string hashHex = ComputeSHA256Hex(password);
               txtContent.AppendText($"🔐 Băm mật khẩu (hex): {hashHex}\r\n");

              

  
                // Tạo và gửi lệnh LOGIN
                string loginCommand = $"LOGIN:{hashHex}";
                serialPort.WriteLine(loginCommand);
                txtContent.AppendText($"🔐 Đã gửi: {loginCommand}\r\n");
                MessageBox.Show(loginCommand);

                // Đọc phản hồi từ STM32
                string response = ReadResponse(TIMEOUT_MS);
              //  txtContent.AppendText($"📥 Phản hồi: {response}\r\n");
                serialPort.Close();

                // Xử lý phản hồi
                if (string.IsNullOrEmpty(response))
                {
                    MessageBox.Show("LỖI  ");
                   // txtContent.AppendText("❌ Không nhận được phản hồi từ STM32.\r\n");
                    return;
                }

                response = response.Trim();
                if (response == "LOGIN_OK")
                {
                    isLoggedIn = true;
                    tabControl1.SelectedIndex = 1;
                    derivedKeyHex = DeriveKeyHex(password);
                    tabControl1.TabPages[0].Enabled = false;
                    tabControl1.TabPages[1].Enabled = true;
                    txtContent.AppendText("✅ Đăng nhập thành công.\r\n");
                }
                else if (response == "LOGIN_FAIL")
                {
                    MessageBox.Show("Sai mật khẩu hoặ tài khoản ", "Lỗi đăng nhập");
                    txtContent.AppendText("❌ Sai mật khẩu.\r\n");
                }
                else
                {
                    MessageBox.Show("Không nhận được phản hồi hợp lệ từ STM32.");
                    txtContent.AppendText($"❌ Phản hồi không hợp lệ: {response}\r\n");
                }
            }
            catch (Exception ex)
            {
                if (serialPort != null && serialPort.IsOpen)
                    serialPort.Close();
                MessageBox.Show($"Lỗi khi đăng nhập: {ex.Message}");
                txtContent.AppendText($"❌ Lỗi đăng nhập: {ex.Message}\r\n");
            }
        }
    
        private string DeriveKeyHex(string password)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, Encoding.UTF8.GetBytes("salt1234"), 1000, HashAlgorithmName.SHA256))
            {
                var key = pbkdf2.GetBytes(16);
                return BitConverter.ToString(key).Replace("-", "").ToLower();
            }
        }

        private void btnSelectFile_Click(object sender, EventArgs e)
        {
            using (var openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*";
                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    selectedFile = openFileDialog.FileName;
                    txtContent.Text = $"Đã chọn: {Path.GetFileName(selectedFile)}\r\n";
                }
            }
        }

        private string ToHex(byte[] data)
        {
            StringBuilder sb = new StringBuilder(data.Length * 2);
            foreach (byte b in data)
                sb.AppendFormat("{0:x2}", b);
            return sb.ToString();
        }

        private string ReadResponse(int timeoutMs)
        {
            StringBuilder response = new StringBuilder();
            DateTime startTime = DateTime.Now;

            while ((DateTime.Now - startTime).TotalMilliseconds < timeoutMs)
            {
                if (serialPort != null && serialPort.IsOpen && serialPort.BytesToRead > 0)
                {
                    string line = serialPort.ReadLine().Trim();
                    response.AppendLine(line);
                    if (line.Contains("OK") || line.Contains("ERROR"))
                        break;
                }
                Thread.Sleep(10);
            }

            return response.ToString().Trim();
        }

        private byte[] HexToBytes(string hex)
        {
            if (string.IsNullOrEmpty(hex) || hex.Length % 2 != 0)
                return new byte[0];
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }
/*
        private byte[] EncryptAESECB(string data, byte[] key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.PKCS7;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(data);
                        cs.Write(plainBytes, 0, plainBytes.Length);
                        cs.FlushFinalBlock();
                    }
                    return ms.ToArray();
                }
            }
        }
        */
        private byte[] EncryptAES(byte[] data, byte[] key, out byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.GenerateIV();
                iv = aes.IV;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var encryptor = aes.CreateEncryptor())
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                        cs.FlushFinalBlock();
                    }
                    return ms.ToArray();
                }
            }
        }

        private byte[] DecryptAES(byte[] encryptedData, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var decryptor = aes.CreateDecryptor())
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedData, 0, encryptedData.Length);
                        cs.FlushFinalBlock();
                    }
                    return ms.ToArray();
                }
            }
        }

        private string ReadFileContent(int timeoutMs = 20000)
        {
            List<byte> receivedBytes = new List<byte>();
            StringBuilder statusMessages = new StringBuilder();
            DateTime startTime = DateTime.Now;
            bool completed = false;
            string ivHex = null;

            while ((DateTime.Now - startTime).TotalMilliseconds < timeoutMs)
            {
                if (serialPort != null && serialPort.IsOpen && serialPort.BytesToRead > 0)
                {
                    string line = serialPort.ReadLine().Trim();
                    if (line.StartsWith("IV:"))
                    {
                        ivHex = line.Substring(3);
                        statusMessages.AppendLine($"Phản hồi STM32 (IV): {line}");
                        continue;
                    }
                    if (line.Contains("OK:"))
                    {
                        statusMessages.AppendLine($"Phản hồi STM32: {line}");
                        completed = true;
                        break;
                    }
                    if (line.Contains("ERROR"))
                    {
                        statusMessages.AppendLine($"Lỗi từ STM32: {line}");
                        completed = true;
                        break;
                    }

                    byte[] chunkBytes = HexToBytes(line);
                    if (chunkBytes.Length > 0)
                    {
                        receivedBytes.AddRange(chunkBytes);
                    }
                }
                Thread.Sleep(1);
            }

            txtContent.AppendText(statusMessages.ToString());

            if (!completed)
            {
                string partialHex = BitConverter.ToString(receivedBytes.ToArray()).Replace("-", "");
                txtContent.AppendText($"DEBUG: Timeout sau {timeoutMs}ms, nhận được {receivedBytes.Count} byte\r\n");
                txtContent.AppendText($"Dữ liệu HEX: {partialHex}\r\n");
                throw new Exception($"Timeout: Did not receive 'OK' or 'ERROR', received {receivedBytes.Count} bytes");
            }

            if (string.IsNullOrEmpty(ivHex))
            {
                throw new Exception("Không nhận được IV từ STM32.");
            }

            return $"{ivHex}\r\n{BitConverter.ToString(receivedBytes.ToArray()).Replace("-", "")}";
        }

        private void btnEncryptSend_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(selectedFile))
            {
                MessageBox.Show("Lỗi: Vui lòng chọn một tệp.");
                return;
            }

            try
            {
                var fileBytes = File.ReadAllBytes(selectedFile);
                var fileName = Path.GetFileName(selectedFile);
                var keyBytes = HexToBytes(derivedKeyHex);

                byte[] iv;
                byte[] encryptedBytes = EncryptAES(fileBytes, keyBytes, out iv);
                int fileSize = encryptedBytes.Length;

                serialPort = new SerialPort("COM5", 115200)
                {
                    Encoding = Encoding.UTF8,
                    NewLine = "\r\n"
                };
                serialPort.Open();

                string ivHex = ToHex(iv);
                string header = $"SEND_START:{fileName}:{fileSize}:{ivHex}";
                serialPort.WriteLine(header);
                txtContent.AppendText($"Đã gửi: {header}\r\n");

                string response = ReadResponse(TIMEOUT_MS);
                if (!response.Contains("OK: Ready to receive file chunks"))
                {
                    throw new Exception($"Lỗi STM32: {response}");
                }

                int sentBytes = 0;
                while (sentBytes < fileSize)
                {
                    int chunkLength = Math.Min(CHUNK_SIZE, fileSize - sentBytes);
                    byte[] block = new byte[CHUNK_SIZE];
                    Array.Clear(block, 0, CHUNK_SIZE);
                    Array.Copy(encryptedBytes, sentBytes, block, 0, chunkLength);

                    // Tính SHA256 cho khối dữ liệu
                    string sha256Hex = ComputeSHA256Hex(block);

                    // Chuyển khối dữ liệu thành hex
                    string hexChunk = ToHex(block);

                    // Gửi lệnh SEND_CHUNK với SHA256
                    string chunkCommand = $"SEND_CHUNK:{hexChunk}:{sha256Hex}";
                    serialPort.WriteLine(chunkCommand);
                    txtContent.AppendText($"Gửi chunk ({sentBytes}/{fileSize}): {hexChunk} (SHA256: {sha256Hex})\r\n");

                    response = ReadResponse(TIMEOUT_MS);
                    if (!response.Contains("OK: Chunk written"))
                    {
                        throw new Exception($"Lỗi STM32: {response}");
                    }

                    sentBytes += chunkLength;
                }

                serialPort.WriteLine("SEND_END");
                response = ReadResponse(TIMEOUT_MS);
                serialPort.Close();

                if (response.Contains("OK: File saved"))
                {
                    txtContent.AppendText($"✅ Tệp đã được mã hóa và gửi thành công tới STM32. ({fileSize}/{fileSize})\r\n");
                }
                else
                {
                    throw new Exception($"Lỗi STM32: {response}");
                }
            }
            catch (Exception ex)
            {
                if (serialPort != null && serialPort.IsOpen)
                    serialPort.Close();
                MessageBox.Show($"❌ Lỗi gửi tệp: {ex.Message}");
                txtContent.AppendText($"❌ Lỗi: {ex.Message}\r\n");
            }
        }

        private void btnGetList_Click(object sender, EventArgs e)
        {
            lstFiles.Items.Clear();
            try
            {
                serialPort = new SerialPort("COM5", 115200)
                {
                    Encoding = Encoding.UTF8,
                    NewLine = "\r\n"
                };
                serialPort.Open();
                serialPort.WriteLine("LIST");
                string response = ReadResponse(2000);
                serialPort.Close();

                var files = response.Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var file in files)
                {
                    if (!file.Contains("ERROR") && !file.Contains("DEBUG"))
                        lstFiles.Items.Add(file);
                }
                txtContent.AppendText($"✅ Danh sách tệp: {files.Length} tệp.\r\n");
            }
            catch (Exception ex)
            {
                if (serialPort != null && serialPort.IsOpen)
                    serialPort.Close();
                MessageBox.Show($"Lỗi khi lấy danh sách tệp: {ex.Message}");
                txtContent.AppendText($"❌ Lỗi lấy danh sách: {ex.Message}\r\n");
            }
        }

        private void btnDecryptFile_Click(object sender, EventArgs e)
        {
            if (lstFiles.SelectedItem == null)
            {
                MessageBox.Show("Lỗi: Vui lòng chọn một tệp.");
                return;
            }

            var fileName = lstFiles.SelectedItem.ToString();
            try
            {
                serialPort = new SerialPort("COM5", 115200)
                {
                    Encoding = Encoding.UTF8,
                    NewLine = "\r\n"
                };
                serialPort.Open();

                string command = $"READ:{fileName}";
                serialPort.WriteLine(command);
                txtContent.AppendText($"Đã gửi: {command}\r\n");

                string response = ReadFileContent(10000);
                serialPort.Close();

                var parts = response.Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2)
                {
                    throw new Exception("Dữ liệu nhận được không đầy đủ (thiếu IV hoặc dữ liệu).");
                }

                string ivHex = parts[0];
                string dataHex = parts[1];
                byte[] iv = HexToBytes(ivHex);
                byte[] encryptedData = HexToBytes(dataHex);
                byte[] keyBytes = HexToBytes(derivedKeyHex);

                byte[] decryptedData = DecryptAES(encryptedData, keyBytes, iv);
                string decryptedText = Encoding.UTF8.GetString(decryptedData);

                txtContent.AppendText($"Nội dung giải mã (Text):\r\n{decryptedText}\r\n");
               // txtContent.AppendText($"\r\nKích thước nhận được: {decryptedData.Length} byte\r\n");
            }
            catch (Exception ex)
            {
                if (serialPort != null && serialPort.IsOpen)
                    serialPort.Close();
                MessageBox.Show($"Lỗi giải mã tệp: {ex.Message}");
                txtContent.AppendText($"❌ Lỗi giải mã: {ex.Message}\r\n");
            }
        }
       
        private void lstFiles_DoubleClick(object sender, EventArgs e)
        {
            if (lstFiles.SelectedItem == null) return;

            var fileName = lstFiles.SelectedItem.ToString();
            try
            {
                serialPort = new SerialPort("COM5", 115200)
                {
                    Encoding = Encoding.UTF8,
                    NewLine = "\r\n"
                };
                serialPort.Open();
                serialPort.WriteLine($"READ:{fileName}");
                string response = ReadFileContent(20000);
                serialPort.Close();

                var parts = response.Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2)
                {
                    txtContent.Text = $"Nội dung tệp (RAW):\r\n{response}\r\n";
                    return;
                }

                string ivHex = parts[0];
                string dataHex = parts[1];

                txtContent.Text = $"Nội dung tệp (mã hóa):\r\nIV: {ivHex}\r\nDữ liệu mã hóa (hex): {dataHex}\r\n";
            }
            catch (Exception ex)
            {
                if (serialPort != null && serialPort.IsOpen)
                    serialPort.Close();
                MessageBox.Show($"Lỗi đọc tệp: {ex.Message}");
                txtContent.AppendText($"❌ Lỗi đọc tệp: {ex.Message}\r\n");
            }
        }
    }
       
        

    public static class ListExtensions
    {
        public static int LastIndexOf(this List<byte> list, byte value)
        {
            for (int i = list.Count - 1; i >= 0; i--)
                if (list[i] == value)
                    return i;
            return -1;
        }
    }
}