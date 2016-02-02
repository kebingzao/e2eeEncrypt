//des ���ܽ��ܺ���
(function () {
	// aes �ӽ��ܷ�����
	window.aesUtil = {
		// aes ���ܵ�iv �������Ҫ���ͻ���Լ���ã�
		_aes_iv : "1122334405060708",
		// ��ʼ��aes helper
		// password --> aes �Ľ���key
		// encrypt --> �Ǽ��ܻ��ǽ���
		helper: function(password, encrypt) {
			var cipher = new System.Security.Cryptography.RijndaelManaged();
			var key = System.Text.Encoding.ASCII.GetBytes(password);
			var iv = System.Text.Encoding.ASCII.GetBytes(this._aes_iv);
			var cryptor = null;
			if (encrypt) {
				cryptor = cipher.CreateEncryptor(key, iv);
			} else {
				cryptor = cipher.CreateDecryptor(key, iv);
			}
			return cryptor;
		},
		// aes �ӽ��ܵļ������
		cipherStreamWrite:function(cryptor, input){
			var inputBuffer = new System.Byte(input.length);
			// Copy data bytes to input buffer.
			System.Buffer.BlockCopy(input, 0, inputBuffer, 0, inputBuffer.length);
			// Create a MemoryStream to hold the output bytes.
			var stream = new System.IO.MemoryStream();
			// Create a CryptoStream through which we are going to be processing our data.
			var mode = System.Security.Cryptography.CryptoStreamMode.Write;
			var cryptoStream = new System.Security.Cryptography.CryptoStream(stream, cryptor, mode);
			// Start the crypting process.
			cryptoStream.Write(inputBuffer, 0, inputBuffer.length);
			// Finish crypting.
			cryptoStream.FlushFinalBlock();
			// Convert data from a memoryStream into a byte array.
			var outputBuffer = stream.ToArray();
			// Close both streams.
			stream.Close();
			cryptoStream.Close();
			return outputBuffer;
		},
		// ����16λ���AES��Կ
		createAESKey: function(){
			return hex_md5("hehe@#$%^" + new Date().getTime()).substr(0,16);
		},
		// aes ���ܲ���base64 ���
		encryptToBase64: function(password, s) {
			// Turn input strings into a byte array.
			var bytes = System.Text.Encoding.UTF8.GetBytes(s);
			// Get encrypted bytes.
			var encryptedBytes = this.encrypt(password, bytes);
			// Convert encrypted data into a base64-encoded string.
			var base64String = System.Convert.ToBase64String(encryptedBytes);
			// Return encrypted string.
			return base64String;
		},
		// aes ����
		encrypt: function(password, bytes) {
			// Create an instance of the Rihndael class.
			// Create a encryptor.
			var encryptor = this.helper(password, true);
			// Return encrypted bytes.
			return this.cipherStreamWrite(encryptor, bytes);
		},
		// aes ���ܲ���base64���
		decryptFromBase64: function(password, base64String) {
			// Convert Base64 string into a byte array.
			var encryptedBytes = System.Convert.FromBase64String(base64String);
			var bytes = this.decrypt(password, encryptedBytes);
			// Convert decrypted data into a string.
			var s = System.Text.Encoding.UTF8.GetString(bytes);
			// Return decrypted string.
			return s;
		},
		// aes ����
		decrypt: function(password, bytes) {
			// Create an instance of the Rihndael class.
			// Create a encryptor.
			var decryptor = this.helper(password, false);
			// Return encrypted bytes.
			return this.cipherStreamWrite(decryptor, bytes);
		}
	};

	// rsa �ӽ��ܷ�����
	window.rsaUtil = {
		// rsa ��λ��
		_keySize: 1024,
		// rsa ��key, ��˽Կ�����й�Կ��ʵ��˽Կ��һ���ֶ��ѣ���xml���ַ�����ʽ���ڣ����Դ��ڴ��϶�ȡ
		_rsaKeyStr: '',
		// aes ��Կ������һ���Ƚϸ��ӵľ�̬��ֵ(16λ)����ȡ���Զ�̬��ȡ��
		_rsaSaveAesPwd: '987654321*&^%$#@',
		// ��ȡ�µ�rsa provider
		getNewRsaProvider: function (dwKeySize) {
			// Create a new instance of RSACryptoServiceProvider.
			if (!dwKeySize) dwKeySize = this._keySize;
			return new System.Security.Cryptography.RSACryptoServiceProvider(dwKeySize);
		},
		// ���������µ�rsa��key������˽Կ��ֵ���ڱ��ش洢
		setNewRsaKey: function(){
			var rsa = this.getNewRsaProvider();
			this._rsaKeyStr = rsa.ToXmlString(true);
			return this._rsaKeyStr;
		},
		// ��ȡrsa key
		getRsaKey: function (includePrivateParameters, rsaKeyStr) {
			var rsa = this.getNewRsaProvider();
			// Import parameters from xml.
			rsa.FromXmlString(rsaKeyStr);
			// Export RSA key to RSAParameters and include:
			//    false - Only public key required for encryption.
			//    true  - Private key required for decryption.
			return rsa.ExportParameters(includePrivateParameters);
		},
		// ����rsa����
		encrypt: function(bytes, publishKey){
			var doOaepPadding = false;
			publishKey = publishKey || this._rsaKeyStr;
			var rsa = this.getNewRsaProvider();
			// Import the RSA Key information.
			rsa.ImportParameters(this.getRsaKey(false,publishKey));
			// Encrypt the passed byte array and specify OAEP padding.
			return rsa.Encrypt(bytes, doOaepPadding);
		},
		// ����rsa���ܲ�ת��Ϊbase64���
		encryptToBase64: function(data,publishKey){
			var bytes = System.Text.Encoding.UTF8.GetBytes(data);
			var encryptedBytes = this.encrypt(bytes,publishKey);
			return System.Convert.ToBase64String(encryptedBytes);
		},
		// rsa ����
		decrypt: function(bytes){
			var doOaepPadding = false;
			var rsa = this.getNewRsaProvider();
			// Import the RSA Key information.
			rsa.ImportParameters(this.getRsaKey(true,this._rsaKeyStr));
			// Decrypt the passed byte array and specify OAEP padding.
			return rsa.Decrypt(bytes, doOaepPadding);
		},
		// ����rsa���ܲ�ת��Ϊbase64���
		decryptToBase64: function(data){
			var encryptedBytes = System.Convert.FromBase64String(data);
			var decryptedBytes = this.decrypt(encryptedBytes);
			return System.Text.Encoding.UTF8.GetString(decryptedBytes);
		},
		// ��ȡ��Կ
		getPublishKey: function(){
			return this._rsaKeyStr.replace(/(<\/Exponent>)(\S+)(<\/RSAKeyValue>)/gm,'$1$3');
		},
		// ����key
		setRsaKeyValue: function(str){
			this._rsaKeyStr = str;
		}
	};
	// �����e2ee�ļ��ܷ�ʽ
	window.e2eeUtil = {
		// ��ȡe2ee�Ĺ�Կ
		getPublishKey: function(){
			return rsaUtil.getPublishKey();
		},
		// e2ee ����
		encrypt: function(data,publishKey, aesKey){
			// ��Ҫ��Ϊ4����ƴ��
			// ���Ĳ���-��������
			var aesKey = aesUtil.createAESKey();
			var data_4 = aesUtil.encryptToBase64(aesKey,data);
			// ��������- AES��Կ,��rsa�㷨����
			var data_3 = rsaUtil.encryptToBase64(aesKey,publishKey);
			// �ڶ�����-�������ֳ��� ��ת��Ϊbase64�պ���8���ַ���
			var data_2 = System.Convert.ToBase64String(System.BitConverter.GetBytes(data_3.length));
			// ��һ����- ���Ĳ��ֳ��� ��ת��Ϊbase64�պ���8���ַ���
			var data_1 = System.Convert.ToBase64String(System.BitConverter.GetBytes(data_4.length));
			var result = data_1 + data_2 +data_3 +data_4;
			console.log("���͵�e2ee����Ϊ��" + result);
			return result;
		},
		// e2ee ����
		decrypt: function(data){
			console.log("���յ����͹�����e2ee����Ϊ:", data);
			// ��ʼ��
			var data_1 = data.substr(0,8);
			var data_2 = data.substr(8,8);
			// ��ȡ�������ֵĳ���, ��rsa���ܹ���AES��Կ
			var data_3_len = System.BitConverter.ToInt32(System.Convert.FromBase64String(data_2), 0);
			// ��ȡ���Ĳ��ֵĳ��ȣ�����������
			var data_4_len = System.BitConverter.ToInt32(System.Convert.FromBase64String(data_1), 0);
			// ��������ȡ�������ֵ�AES����Կ��Ҫ��rsa������
			var data_3 = data.substr(16, data_3_len).trim();
			var keyForAES = rsaUtil.decryptToBase64(data_3);
			// ��������AES��key��������
			var data_4 = data.substr(16 + data_3_len, data_4_len).trim();
			var decrypted = aesUtil.decryptFromBase64(keyForAES, data_4);
			console.log("���ܺ�ı���Ϊ��", decrypted);
			return decrypted;
		}
	};
})();