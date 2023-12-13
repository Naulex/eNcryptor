using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Threading;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net;
using System.Drawing;

namespace eNcryptorByAlexanderN
{
    public partial class eNcryptorByAlexanderN : Form
    {
        string FilePath;
        bool alive = false;
        UdpClient client;

        static CancellationTokenSource CancelAnyTask = new CancellationTokenSource();

        private void CancelButton_Click(object sender, EventArgs e)
        {
            CancelAnyTask.Cancel();
            StatusLabel.Text = "Операция отменена...";
        }

        private string GetMacAddress()
        {
            try
            {
                string macAddresses = "";
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus == OperationalStatus.Up)
                    {
                        macAddresses += nic.GetPhysicalAddress().ToString();
                        break;
                    }
                }
                return macAddresses;
            }
            catch
            { return "Сетевой интерфейс не обнаружен"; }
        }

        public eNcryptorByAlexanderN()
        {
            InitializeComponent();
            this.Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            CheckForIllegalCrossThreadCalls = false;
            MacLabel.Text = Convert.ToString(GetMacAddress());

        }

        private void AboutAlgButton_Click(object sender, EventArgs e)
        {

            MessageBox.Show("Введите незашифрованный текст в поле \"Исходный текст\", или загрузите его из файла при помощи соответствующей кнопки, создайте пару ключей, установите последовательность шифраций и нажмите кнопку \"Зашифровать\". Поддерживаются только TXT файлы в кодировке UTF!\r\n\r\nИли введите зашифрованный текст (рекомендуется использовать встроенный интерфейс приема и передачи!), последовательность шифраций, шифрованный пароль, закрытый ключ, и нажмите кнопку \"Расшифровать\".\r\n\r\n\r\n\r\n\r\n\r\nNaulex\r\n073797@gmail.com\r\n2020.", "Информация | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Information);

        }

        private async void EncryptButton_Click(object sender, EventArgs e)
        {
            ReadTextFromFileButton.Enabled = false;
            EncryptButton.Enabled = false;
            DecryptButton.Enabled = false;
            DelAlg.Enabled = false;
            AddXOR.Enabled = false;
            AddVigenere.Enabled = false;
            AddScytale.Enabled = false;
            SaveOrSendGroup.Enabled = false;
            GeneratePass.Enabled = false;
            CleanAll.Enabled = false;

            CancellationToken Cancel = CancelAnyTask.Token;
            try
            {
                if (AlgTextBox.Text.Length != 0 && PublicKeyTextBox.Text.Length != 0 && PrivateKeyTextBox.Text.Length != 0 && NormalTextBox.Text.Length != 0)
                {
                    MainProgressBar.Style = ProgressBarStyle.Blocks;
                    MainProgressBar.Value = 0;
                    StatusLabel.Text = "Начато шифрование текста...";
                    EncryptedTextBox.Clear();
                    string encString = NormalTextBox.Text;
                    String[] Settings = AlgTextBox.Text.Split(new char[] { '+' }, StringSplitOptions.RemoveEmptyEntries);
                    string fullPass = "";

                    for (int i = 0; i < AlgTextBox.Text.Length / 2; i++)
                    {
                        MainProgressBar.Maximum = (AlgTextBox.Text.Length / 2) + 1;

                        if (Settings[i] == "X")
                        {
                            StatusLabel.Text = "Шифрование текста методом XOR...";
                            string pass = "";
                            if (GeneratePass.Checked == true)
                            { pass = eNcMethods.GenerateRandomString(); }
                            if (GeneratePass.Checked == false)
                            {
                                try
                                {
                                    pass = Microsoft.VisualBasic.Interaction.InputBox("Введите пароль для шифрования текста методом XOR. Запоминать его не нужно, он будет дополнительно зашифрован открытым ключом.", "Создание пароля | eNcryptor");
                                }
                                catch
                                {
                                    MessageBox.Show("Ошибка преобразования пароля!\r\n\r\n\r\nБудет сгенерирован стандартный пароль!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                                    pass = eNcMethods.GenerateRandomString();
                                }
                            }

                            fullPass = fullPass + pass + "/S/";
                            try
                            {
                                await Task.Run(() => encString = eNcMethods.XOR.Encrypt(encString, pass, Cancel));
                            }
                            catch
                            {
                                MessageBox.Show("Ошибка шифрования!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            }
                            MainProgressBar.Value++;
                        }

                        if (Settings[i] == "V")

                        {
                            StatusLabel.Text = "Шифрование текста методом Vigenere...";
                            string pass = "";
                            if (GeneratePass.Checked == true)
                            { pass = eNcMethods.GenerateRandomString(); }
                            if (GeneratePass.Checked == false)
                            {
                                try
                                {
                                    pass = Microsoft.VisualBasic.Interaction.InputBox("Введите пароль для шифрования текста методом Vigenere. Запоминать его не нужно, он будет дополнительно зашифрован открытым ключом.", "Создание пароля | eNcryptor");
                                }
                                catch
                                {
                                    MessageBox.Show("Ошибка преобразования пароля!\r\n\r\n\r\nБудет сгенерирован стандартный пароль!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                                    pass = eNcMethods.GenerateRandomString();
                                }
                            }
                            fullPass = fullPass + pass + "/S/";

                            try
                            {
                                await Task.Run(() => encString = eNcMethods.Vigenere.Encrypt(encString, pass, Cancel));
                            }
                            catch
                            {
                                MessageBox.Show("Ошибка шифрования!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            }
                            MainProgressBar.Value++;
                        }

                        if (Settings[i] == "S")

                        {
                            StatusLabel.Text = "Шифрование текста методом Scytale...";
                            int pass = 0;
                            if (GeneratePass.Checked == true)
                            { pass = eNcMethods.GenerateRandomEasyString(NormalTextBox.Text.Length); }
                            if (GeneratePass.Checked == false)
                            {
                                try
                                {
                                    string strpass = Microsoft.VisualBasic.Interaction.InputBox("Введите ЧИСЛОВОЙ пароль для шифрования текста методом Vigenere. Запоминать его не нужно, он будет дополнительно зашифрован открытым ключом.", "Создание пароля | eNcryptor");
                                    pass = Convert.ToInt32(strpass);
                                }
                                catch
                                {
                                    MessageBox.Show("Ошибка преобразования пароля!\r\n\r\n\r\nБудет сгенерирован стандартный пароль!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                                    pass = eNcMethods.GenerateRandomEasyString(NormalTextBox.Text.Length);

                                }
                            }


                            fullPass = fullPass + Convert.ToString(pass) + "/S/";
                            try
                            {
                                await Task.Run(() => encString = eNcMethods.Scytale.Encrypt(encString, pass, Cancel));
                            }
                            catch
                            {
                                MessageBox.Show("Ошибка шифрования!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            }
                            MainProgressBar.Value++;
                        }
                    }

                    StatusLabel.Text = "Шифрование ключа методом RSA...";
                    String[] PublicKey = PublicKeyTextBox.Text.Split(new char[] { '+' }, StringSplitOptions.RemoveEmptyEntries);
                    String[] PrivateKey = PrivateKeyTextBox.Text.Split(new char[] { '+' }, StringSplitOptions.RemoveEmptyEntries);
                    EncryptedTextBox.Text += encString;

                    try
                    {
                        await Task.Run(() => SymmPassTextBox.Text = eNcMethods.Base64.ToBase64N(Encoding.UTF8.GetBytes(eNcMethods.RSA.Encrypt(Convert.ToInt32(PublicKey[0]), Convert.ToInt32(PublicKey[1]), fullPass, Convert.ToInt32(PrivateKey[0]), Convert.ToInt32(PrivateKey[1]), Cancel))));
                    }
                    catch
                    { MessageBox.Show("Внутренняя ошибка асимметричного шифрования!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error); }
                    MainProgressBar.Value++;
                    StatusLabel.Text = "Шифрование текста завершено!";
                }

                else
                {
                    MessageBox.Show("Не заполнено одно или несколько обязательных полей!\r\n\r\n\r\n(Открытый ключ, закрытый ключ, последовательность шифраций, текст для преобразования)", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            catch
            {
                MessageBox.Show("Внутренняя ошибка шифрования строки. Повторите попытку шифрования, создайте новую пару ключей.", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

            EncryptButton.Enabled = true;
            DecryptButton.Enabled = true;
            DelAlg.Enabled = true;
            AddXOR.Enabled = true;
            AddVigenere.Enabled = true;
            AddScytale.Enabled = true;
            SaveOrSendGroup.Enabled = true;
            GeneratePass.Enabled = true;
            ReadTextFromFileButton.Enabled = true;
            CleanAll.Enabled = true;
            Console.Beep(200, 100);
            Console.Beep(300, 100);
            Console.Beep(400, 100);
        }

        private async void DecryptButton_Click(object sender, EventArgs e)
        {
            CancellationToken Cancel = CancelAnyTask.Token;

            ReadTextFromFileButton.Enabled = false;
            EncryptButton.Enabled = false;
            DecryptButton.Enabled = false;
            DelAlg.Enabled = false;
            AddXOR.Enabled = false;
            AddVigenere.Enabled = false;
            AddScytale.Enabled = false;
            SaveOrSendGroup.Enabled = false;
            GeneratePass.Enabled = false;
            CleanAll.Enabled = false;
            try
            {
                if (AlgTextBox.Text.Length != 0 && PrivateKeyTextBox.Text.Length != 0 && EncryptedTextBox.Text.Length != 0 && SymmPassTextBox.Text.Length != 0)
                {


                    MainProgressBar.Style = ProgressBarStyle.Blocks;
                    MainProgressBar.Value = 0;


                    NormalTextBox.Clear();
                    string unEncString = EncryptedTextBox.Text;
                    string ReversedAlgString = new string(AlgTextBox.Text.ToCharArray().Reverse().ToArray());

                    MainProgressBar.Maximum = (AlgTextBox.Text.Length / 2) + 1;
                    MainProgressBar.Value++;
                    StatusLabel.Text = "Расшифровка ключа методом RSA...";
                    String[] PrivateKey = PrivateKeyTextBox.Text.Split(new char[] { '+' }, StringSplitOptions.RemoveEmptyEntries);
                    string pass = "";
                    try
                    {
                        pass = await Task.Run(() => eNcMethods.RSA.Decrypt(Convert.ToInt32(PrivateKey[0]), Convert.ToInt32(PrivateKey[1]), Encoding.UTF8.GetString(eNcMethods.Base64.FromBase64N(SymmPassTextBox.Text)), Cancel));
                    }
                    catch
                    {
                        MessageBox.Show("Ошибка преобразования ключа!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }

                    String[] passsplit = pass.Split(new string[] { "/S/" }, StringSplitOptions.RemoveEmptyEntries);
                    Array.Reverse(passsplit);
                    String[] Settings = ReversedAlgString.Split(new char[] { '+' }, StringSplitOptions.RemoveEmptyEntries);



                    for (int i = 0; i < ReversedAlgString.Length / 2; i++)
                    {
                        if (Settings[i] == "X")
                        {
                            StatusLabel.Text = "Расшифровка текста методом XOR...";
                            try
                            {
                                await Task.Run(() => unEncString = eNcMethods.XOR.Decrypt(unEncString, passsplit[i], Cancel));
                            }
                            catch
                            {
                                MessageBox.Show("Ошибка расшифровки!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            }
                            MainProgressBar.Value++;
                        }

                        if (Settings[i] == "V")
                        {
                            StatusLabel.Text = "Расшифровка текста методом Vigenere...";
                            try
                            {
                                await Task.Run(() => unEncString = eNcMethods.Vigenere.Decrypt(unEncString, passsplit[i], Cancel));
                            }
                            catch
                            {
                                MessageBox.Show("Ошибка расшифровки!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            }
                            MainProgressBar.Value++;
                        }

                        if (Settings[i] == "S")
                        {
                            StatusLabel.Text = "Расшифровка текста методом Scytale...";
                            try
                            {
                                await Task.Run(() => unEncString = eNcMethods.Scytale.Decrypt(unEncString, Convert.ToInt32(passsplit[i]), Cancel));
                            }
                            catch
                            {
                                MessageBox.Show("Ошибка расшифровки!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            }
                            MainProgressBar.Value++;
                        }


                    }

                    NormalTextBox.Text += unEncString;
                    StatusLabel.Text = "Расшифровка текста завершена!";
                }
                else
                {
                    MessageBox.Show("Не заполнено одно или несколько обязательных полей!\r\n\r\n\r\n(Последовательность шифраций, Закрытый ключ, Зашифрованный пароль, Зашифрованный текст)", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            catch
            {
                MessageBox.Show("Внутренняя ошибка расшифровки строки. Повторите попытку расшифровки, убедитесь в правильности введенных данных.", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            ReadTextFromFileButton.Enabled = true;
            EncryptButton.Enabled = true;
            DecryptButton.Enabled = true;
            DelAlg.Enabled = true;
            AddXOR.Enabled = true;
            AddVigenere.Enabled = true;
            AddScytale.Enabled = true;
            SaveOrSendGroup.Enabled = true;
            GeneratePass.Enabled = true;
            CleanAll.Enabled = true;
            Console.Beep(200, 100);
            Console.Beep(300, 100);
            Console.Beep(400, 100);
        }

        private void GenerateKeysButton_Click(object sender, EventArgs e)
        {
            try
            {
                Random rnd = new Random();
                long a = 0;
                long b = 0;
                do
                {
                    a = eNcMethods.PrimeFinder(rnd.Next(50, 300));
                    b = eNcMethods.PrimeFinder(rnd.Next(50, 300));
                }
                while (a == b);
                PublicKeyTextBox.Text = a + "+" + b;

                eNcMethods.RSA.GenerateKeyPair.GetDN(a, b, out long c, out long d);
                PrivateKeyTextBox.Text = c + "+" + d;
                StatusLabel.Text = "Генерация пары ключей завершена...";
            }
            catch
            {
                MessageBox.Show("Ошибка генерации ключей. Повторите попытку.", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void SaveToBufferButton_Click(object sender, EventArgs e)
        {
            if (EncryptedCheck.Checked == false && PrivateCheck.Checked == false && AlgCheck.Checked == false && PassCheck.Checked == false && DecryptedCheck.Checked == false && PublicCheck.Checked == false)
            {
                MessageBox.Show("Выберите хотя бы одно поле для сохранения!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);

            }
            else
            {
                try
                {
                    Thread thread = new Thread(() =>
                    {
                        string stringToSave = CreateFullExportString(false);
                        if (stringToSave.Length > 8192)
                        {
                            DialogResult result = MessageBox.Show("Размер датаграмы превышает 8 КБ, передача такой длинной строки может вызвать неудобства. Настоятельно рекомендуется сохранить строку в файл. \r\n\r\nНастаиваете на продолжении?", "Превышен рекомендуемый размер | eNcryptor", MessageBoxButtons.YesNo, MessageBoxIcon.Question);

                            if (result == DialogResult.No)
                            {
                                StatusLabel.Text = "Данные не сохранены...";
                                return;
                            }
                            else
                            {
                                Clipboard.SetText(stringToSave);
                                StatusLabel.Text = "Данные сохранены в буфер...";
                            }
                        }
                        else
                        {

                            Clipboard.SetText(stringToSave);
                            StatusLabel.Text = "Данные сохранены в буфер...";


                        }

                    });
                    thread.SetApartmentState(ApartmentState.STA);
                    thread.Start();
                    thread.Join();

                }
                catch
                {
                    MessageBox.Show("Ошибка сохранения в буфер. Повторите попытку.", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }

        }
        private string CreateFullExportString(bool isNeedToHideMac)
        {
            try
            {
                string MetaData = "";
                string Export = "";
                if (EncryptedCheck.Checked == true)
                {
                    Export += EncryptedTextBox.Text + "/N/";
                    MetaData += "Зашифрованное сообщение\r\n";
                }
                else Export += " /N/";

                if (DecryptedCheck.Checked == true)
                {
                    Export += NormalTextBox.Text + "/N/";
                    MetaData += "Расшифрованное сообщение\r\n";
                }
                else Export += " /N/";

                if (PassCheck.Checked == true)
                {
                    Export += SymmPassTextBox.Text + "/N/";
                    MetaData += "Зашифрованный пароль\r\n";
                }
                else Export += " /N/";

                if (AlgCheck.Checked == true)
                {
                    Export += AlgTextBox.Text + "/N/";
                    MetaData += "Алгоритм шифрования\r\n";
                }
                else Export += " /N/";

                if (PrivateCheck.Checked == true)
                {
                    Export += PrivateKeyTextBox.Text + "/N/";
                    MetaData += "Закрытый ключ\r\n";
                }
                else Export += " /N/";

                if (PublicCheck.Checked == true)
                {
                    Export += PublicKeyTextBox.Text + "/N/";
                    MetaData += "Открытый ключ\n";
                }
                else Export += " /N/";

                if (MetaData == "")
                { MetaData = " /N/"; }

                Export += GetMacAddress() + "/N/";



                Export = eNcMethods.Base64.ToBase64N(Encoding.UTF8.GetBytes(Export));

                MetaData = eNcMethods.Base64.ToBase64N(Encoding.UTF8.GetBytes(MetaData));

                string MacSender;
                if (!isNeedToHideMac)
                { MacSender = eNcMethods.Base64.ToBase64N(Encoding.UTF8.GetBytes("Локальный пользователь")); }
                else
                { MacSender = eNcMethods.Base64.ToBase64N(Encoding.UTF8.GetBytes(GetMacAddress())); }

                return "=====eNcryptorExportData=====/N/" + Export + "/N/" + MetaData + "/N/" + MacSender;
            }
            catch
            {
                MessageBox.Show("Ошибка генерации сохраняемой строки. Повторите попытку.", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return null;
            }
        }

        private void ReadFromBufferButton_Click(object sender, EventArgs e)
        {
            try
            {
                string ClipboardText = "";
                if (Clipboard.ContainsText() == true)
                {
                    try
                    {
                        ClipboardText = Clipboard.GetText();
                        GetDatagram(ClipboardText);
                        StatusLabel.Text = "Чтение данных из буфера...";

                    }
                    catch
                    {
                        MessageBox.Show("Данные имеют неверный формат.\n\nУбедитесь, что копируемый текст имеет строку\n\n=====eNcryptorExportData=====/N/\n\nв начале.", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
            catch
            {
                MessageBox.Show("Ошибка чтения буфера. Повторите попытку.", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void SelectAll_Click(object sender, EventArgs e)
        {
            EncryptedCheck.Checked = true;
            PrivateCheck.Checked = true;
            AlgCheck.Checked = true;
            PassCheck.Checked = true;
            DecryptedCheck.Checked = true;
            PublicCheck.Checked = true;
        }

        private void SaveToFileButton_Click(object sender, EventArgs e)
        {
            if (EncryptedCheck.Checked == false && PrivateCheck.Checked == false && AlgCheck.Checked == false && PassCheck.Checked == false && DecryptedCheck.Checked == false && PublicCheck.Checked == false)
            {
                MessageBox.Show("Выберите хотя бы одно поле для сохранения!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            else
            {
                if (OpenFileToRead.FileName != "")
                {
                    SaveDatagram.FileName = OpenFileToRead.FileName + ".eNc";
                }
                if (SaveDatagram.ShowDialog() == DialogResult.Cancel)
                    return;
                else
                {
                    try
                    {
                        StreamWriter writefl;
                        string filename = SaveDatagram.FileName;
                        writefl = File.CreateText(filename);
                        writefl.Write(CreateFullExportString(false));
                        writefl.Close();
                        StatusLabel.Text = "Данные сохранены в файл...";
                    }
                    catch
                    {
                        MessageBox.Show("Ошибка сохранения в файл!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }

                }
            }
        }

        private void ReadFromFileButton_Click(object sender, EventArgs e)
        {
            if (OpenDatagram.ShowDialog() == DialogResult.Cancel)
                return;
            else
            {
                try
                {
                    StatusLabel.Text = "Чтение датаграмы... ЖДИТЕ!";
                    string ReadData = "";
                    ReadData = File.ReadAllText(OpenDatagram.FileName);
                    GetDatagram(ReadData);
                }
                catch
                {
                    MessageBox.Show("Ошибка чтения из файла!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private async void GetDatagram(string ReadData)
        {
            try
            {
                MainProgressBar.Style = ProgressBarStyle.Marquee;
                MainProgressBar.MarqueeAnimationSpeed = 30;

                String[] Head = ReadData.Split(new string[] { "/N/" }, StringSplitOptions.RemoveEmptyEntries);
                if (Head[0] == "=====eNcryptorExportData=====")
                {
                    string mac = "";
                    await Task.Run(() => mac = Encoding.UTF8.GetString(eNcMethods.Base64.FromBase64N(Head[3])));

                    if (GetMacAddress() == mac)
                    { return; }

                    string Include = "";
                    await Task.Run(() => Include = Encoding.UTF8.GetString(eNcMethods.Base64.FromBase64N(Head[2])));

                    DialogResult result = MessageBox.Show("Желаете загрузить датаграму от " + mac + " со следующим содержимым?\r\n\r\n" + Include, "Обнаружена датаграма | eNcryptor", MessageBoxButtons.YesNo, MessageBoxIcon.Question);

                    if (result == DialogResult.No)
                    {
                        return;
                    }
                    await Task.Run(() => Head[1] = Encoding.UTF8.GetString(eNcMethods.Base64.FromBase64N(Head[1])));
                    String[] Settings = Head[1].Split(new string[] { "/N/" }, StringSplitOptions.RemoveEmptyEntries);
                    if (Settings[0] != " ")
                    {
                        EncryptedTextBox.Text = Settings[0];

                    }
                    if (Settings[1] != " ")
                    {
                        NormalTextBox.Text = Settings[1];

                    }
                    if (Settings[2] != " ")
                    {
                        SymmPassTextBox.Text = Settings[2];

                    }
                    if (Settings[3] != " ")
                    {
                        AlgTextBox.Text = Settings[3];

                    }
                    if (Settings[4] != " ")
                    {
                        PrivateKeyTextBox.Text = Settings[4];

                    }
                    if (Settings[5] != " ")
                    {
                        PublicKeyTextBox.Text = Settings[5];

                    }
                }
                else
                {
                    MessageBox.Show("Данные имеют неверный формат.\n\nУбедитесь, что копируемый текст имеет строку\n\n=====eNcryptorExportData=====/N/\n\nв начале.", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                MainProgressBar.Style = ProgressBarStyle.Continuous;
                MainProgressBar.Increment(100);
                MainProgressBar.MarqueeAnimationSpeed = 0;
                StatusLabel.Text = "Чтение датаграмы завершено!";
            }
            catch
            {
                MessageBox.Show("Ошибка преобразования датаграмы!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void NetStartButton_Click(object sender, EventArgs e)
        {
            try
            {
                client = new UdpClient(Convert.ToInt32(PortTextBox.Value));
                client.JoinMulticastGroup(IPAddress.Parse(SendAddressTextBox.Text), 20);
                Task receiveTask = new Task(ReceiveMessages);
                receiveTask.Start();
                StatusLabel.Text = "Начато прослушивание канала...";
                NetTimer.Enabled = true;
                SendAddressTextBox.Enabled = false;
                PortTextBox.Enabled = false;
                NetStartButton.Enabled = false;
                NetStopButton.Enabled = true;
                DatagramSendButton.Enabled = true;
            }
            catch
            {
                MessageBox.Show("Ошибка подключения к каналу!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ReceiveMessages()
        {
            alive = true;
            try
            {
                while (alive)
                {

                    IPEndPoint remoteIp = null;
                    byte[] data = client.Receive(ref remoteIp);
                    string message = Encoding.UTF8.GetString(data);
                    {
                        Invoke(new MethodInvoker(() =>
                        {
                            GetDatagram(message);
                        }));
                    }

                }

            }
            catch (ObjectDisposedException)
            {
                if (!alive)
                    return;
                throw;
            }
            catch
            {
                alive = false;
            }
        }

        private void DatagramSendButton_Click(object sender, EventArgs e)
        {
            try
            {
                if (EncryptedCheck.Checked == false && PrivateCheck.Checked == false && AlgCheck.Checked == false && PassCheck.Checked == false && DecryptedCheck.Checked == false && PublicCheck.Checked == false)
                {
                    MessageBox.Show("Выберите хотя бы одно поле для передачи!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                else
                {
                    StatusLabel.Text = "Передача датаграмы...";
                    byte[] data = Encoding.UTF8.GetBytes(CreateFullExportString(true));
                    if (data.Length >= 8192)
                    {
                        MessageBox.Show("Размер датаграмы превышает максимально допустимый (8кб). Сетевая передача невозможна.", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                    client.Send(data, data.Length, SendAddressTextBox.Text, Convert.ToInt32(PortTextBox.Value));

                }
            }
            catch
            {
                MessageBox.Show("Ошибка передачи датаграмы!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }


        private void NetStopButton_Click(object sender, EventArgs e)
        {
            try
            {
                alive = false;
                client.Close();
                StatusLabel.Text = "Прослушивание канала прекращено...";
                NetTimer.Enabled = false;
                TimerText.Text = "30";
                SendAddressTextBox.Enabled = true;
                PortTextBox.Enabled = true;
                NetStartButton.Enabled = true;
                NetStopButton.Enabled = false;
                DatagramSendButton.Enabled = false;
                MainProgressBar.Style = ProgressBarStyle.Blocks;
                MainProgressBar.Value = 0;
                MainProgressBar.MarqueeAnimationSpeed = 0;
            }
            catch
            {
                MessageBox.Show("Ошибка остановки прослушивания!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void AddXOR_Click(object sender, EventArgs e)
        {
            AlgTextBox.Text += "X+";
            StatusLabel.Text = "Добавлена шифрация...";
        }

        private void AddVigenere_Click(object sender, EventArgs e)
        {
            AlgTextBox.Text += "V+";
            StatusLabel.Text = "Добавлена шифрация...";
        }

        private void AddScytale_Click(object sender, EventArgs e)
        {
            AlgTextBox.Text += "S+";
            StatusLabel.Text = "Добавлена шифрация...";
        }

        private void DelAlg_Click(object sender, EventArgs e)
        {
            try
            {

                AlgTextBox.Text = AlgTextBox.Text.Remove(AlgTextBox.Text.Length - 2);
                StatusLabel.Text = "Удалена шифрация...";
            }
            catch
            {
                MessageBox.Show("Должен присутствовать хотя бы один алгоритм!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private async void ReadTextFromFileButton_Click(object sender, EventArgs e)
        {
            try
            {
                CancellationToken Cancel = CancelAnyTask.Token;

                if (OpenFileToRead.ShowDialog() == DialogResult.Cancel)
                    return;
                FilePath = OpenFileToRead.FileName;
                FileInfo ChoosedFileInfo = new FileInfo(FilePath);
                FileInfoTextBox.Text = "ИНФОРМАЦИЯ О ФАЙЛЕ:" + "\r\n\r\n\r\nИМЯ ФАЙЛА: " + ChoosedFileInfo.Name + "\r\n\r\nРАСШИРЕНИЕ: " + ChoosedFileInfo.Extension + "\r\n\r\nРАСПОЛОЖЕНИЕ ФАЙЛА: " + ChoosedFileInfo.DirectoryName + "\r\n\r\nСОЗДАН: " + ChoosedFileInfo.CreationTime + "\r\n\r\nОТКРЫТ: " + ChoosedFileInfo.LastAccessTime + "\r\n\r\nСОХРАНЕН: " + ChoosedFileInfo.LastWriteTime + "\r\n\r\nРАЗМЕР: " + ChoosedFileInfo.Length + " байт" + "\r\n\r\nАТРИБУТЫ: " + ChoosedFileInfo.Attributes + "\r\n\r\nТОЛЬКО ДЛЯ ЧТЕНИЯ: " + ChoosedFileInfo.IsReadOnly;
                using (StreamReader sr = new StreamReader(OpenFileToRead.FileName))
                {
                    if (Cancel.IsCancellationRequested)
                        return;
                    NormalTextBox.Text = (await sr.ReadToEndAsync());
                }
            }
            catch
            {
                MessageBox.Show("Ошибка чтения текста!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

        }

        private void ChooseFileButton_Click_1(object sender, EventArgs e)
        {
            try
            {
                if (OpenDataFile.ShowDialog() == DialogResult.Cancel)
                    return;
                FilePath = OpenDataFile.FileName;
                FileInfo ChoosedFileInfo = new FileInfo(FilePath);
                FileInfoTextBox.Text = "ИНФОРМАЦИЯ О ФАЙЛЕ:" + "\r\n\r\n\r\nИМЯ ФАЙЛА: " + ChoosedFileInfo.Name + "\r\n\r\nРАСШИРЕНИЕ: " + ChoosedFileInfo.Extension + "\r\n\r\nРАСПОЛОЖЕНИЕ ФАЙЛА: " + ChoosedFileInfo.DirectoryName + "\r\n\r\nСОЗДАН: " + ChoosedFileInfo.CreationTime + "\r\n\r\nОТКРЫТ: " + ChoosedFileInfo.LastAccessTime + "\r\n\r\nСОХРАНЕН: " + ChoosedFileInfo.LastWriteTime + "\r\n\r\nРАЗМЕР: " + ChoosedFileInfo.Length + " байт" + "\r\n\r\nАТРИБУТЫ: " + ChoosedFileInfo.Attributes + "\r\n\r\nТОЛЬКО ДЛЯ ЧТЕНИЯ: " + ChoosedFileInfo.IsReadOnly;
            }
            catch
            {
                MessageBox.Show("Ошибка открытия файла!", "Ошибка | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void NetTimer_Tick(object sender, EventArgs e)
        {
            int time = Convert.ToInt32(TimerText.Text);
            time--;
            TimerText.Text = Convert.ToString(time);
            if (time == 0)
            {
                NetTimer.Enabled = false;
                alive = false;
                client.Close();
                StatusLabel.Text = "Прослушивание канала прекращено...";
                TimerText.Text = "30";
                SendAddressTextBox.Enabled = true;
                PortTextBox.Enabled = true;
                NetStartButton.Enabled = true;
                NetStopButton.Enabled = false;
                DatagramSendButton.Enabled = false;
                MainProgressBar.Style = ProgressBarStyle.Blocks;
                MainProgressBar.Value = 0;
                MainProgressBar.MarqueeAnimationSpeed = 0;
            }


        }

        private void ShowPass_CheckedChanged(object sender, EventArgs e)
        {
            if (ShowPass.Checked == true)
            {
                PrivateKeyTextBox.UseSystemPasswordChar = false;
                SymmPassTextBox.UseSystemPasswordChar = false;
            }
            else
            {
                PrivateKeyTextBox.UseSystemPasswordChar = true;
                SymmPassTextBox.UseSystemPasswordChar = true;
            }
        }

        private void CleanAll_Click(object sender, EventArgs e)
        {
            NormalTextBox.Text = "";
            EncryptedTextBox.Text = "";
            SymmPassTextBox.Text = "";
            PublicKeyTextBox.Text = "";
            PrivateKeyTextBox.Text = "";
            AlgTextBox.Text = "X+";
            StatusLabel.Text = "Поля очищены...";
        }

        private void TopMost_CheckedChanged(object sender, EventArgs e)
        {
            if (UpAll.Checked == true)
                TopMost = true;
            else
                TopMost = false;
        }

        private void Info2_Click(object sender, EventArgs e)
        {

            MessageBox.Show("Основной особенностью программы является возможность ручной установки последовательности и количества проводимых шифраций. Нажимайте соответствующие кнопки чтобы создать уникальную последовательность. Весь текст будет зашифрован согласно установленному алгоритму, при этом, Вы можете отключить генерацию стандартных паролей и вводить их вручную. В конце концов набор паролей для каждой последовательности будет асимметрично зашифрован при помощи пары открытого и закрытого ключей.", "Информация | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Information);

        }

        private void Info3_Click(object sender, EventArgs e)
        {

            MessageBox.Show("Настоятельно рекомендуется использовать встроенный интерфейс передачи и сохранения данных вместо классических \"Копировать\" и \"Вставить\". Вы можете сохранить все или некоторые данные в буфер обмена или специальный файл, а так же передать их по локальной сети в другую такую же программу.\r\n\r\nДля сетевой передачи данных нажмите кнопку \"Старт\" в обоих программах, затем в одной из них нажмите \"Передать\". Для передачи данных используется механизм многоадресной рассылки UDP. В поле 'Адрес рассылки и порт' можно ввести любой адрес категории D для частных мультикаст-доменов (239.0.0.0-239.255.255.255). Эти адреса используются для многоадресной рассылки и должны быть одинаковыми во всех программах, между которыми будет производиться передача данных. Если системный администратор заблокировал порт по умолчанию или пакеты по каким-то причинам теряются, все участники должны использовать другой свободный порт и/или адрес.", "Информация | eNcryptor", MessageBoxButtons.OK, MessageBoxIcon.Information);

        }
    }
}







