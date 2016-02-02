//des 加密解密函数
(function () {
	// aes 加解密方法集
	window.aesUtil = {
		// aes 加密的iv （这个需要跟客户端约定好）
		_aes_iv : "1122334405060708",
		// 初始化aes helper
		// password --> aes 的解密key
		// encrypt --> 是加密还是解密
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
		// aes 加解密的计算过程
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
		// 生成16位随机AES密钥
		createAESKey: function(){
			return hex_md5("hehe@#$%^" + new Date().getTime()).substr(0,16);
		},
		// aes 加密并用base64 输出
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
		// aes 加密
		encrypt: function(password, bytes) {
			// Create an instance of the Rihndael class.
			// Create a encryptor.
			var encryptor = this.helper(password, true);
			// Return encrypted bytes.
			return this.cipherStreamWrite(encryptor, bytes);
		},
		// aes 解密并用base64输出
		decryptFromBase64: function(password, base64String) {
			// Convert Base64 string into a byte array.
			var encryptedBytes = System.Convert.FromBase64String(base64String);
			var bytes = this.decrypt(password, encryptedBytes);
			// Convert decrypted data into a string.
			var s = System.Text.Encoding.UTF8.GetString(bytes);
			// Return decrypted string.
			return s;
		},
		// aes 解密
		decrypt: function(password, bytes) {
			// Create an instance of the Rihndael class.
			// Create a encryptor.
			var decryptor = this.helper(password, false);
			// Return encrypted bytes.
			return this.cipherStreamWrite(decryptor, bytes);
		}
	};

	// rsa 加解密方法集
	window.rsaUtil = {
		// rsa 的位数
		_keySize: 1024,
		// rsa 的key, 即私钥（其中公钥其实是私钥的一部分而已）以xml的字符串形式存在，可以从内存上读取
		_rsaKeyStr: '',
		// aes 密钥，先用一个比较复杂的静态的值(16位)（获取可以动态获取）
		_rsaSaveAesPwd: '987654321*&^%$#@',
		// 获取新的rsa provider
		getNewRsaProvider: function (dwKeySize) {
			// Create a new instance of RSACryptoServiceProvider.
			if (!dwKeySize) dwKeySize = this._keySize;
			return new System.Security.Cryptography.RSACryptoServiceProvider(dwKeySize);
		},
		// 重新生成新的rsa的key，并将私钥的值存在本地存储
		setNewRsaKey: function(){
			var rsa = this.getNewRsaProvider();
			this._rsaKeyStr = rsa.ToXmlString(true);
			return this._rsaKeyStr;
		},
		// 获取rsa key
		getRsaKey: function (includePrivateParameters, rsaKeyStr) {
			var rsa = this.getNewRsaProvider();
			// Import parameters from xml.
			rsa.FromXmlString(rsaKeyStr);
			// Export RSA key to RSAParameters and include:
			//    false - Only public key required for encryption.
			//    true  - Private key required for decryption.
			return rsa.ExportParameters(includePrivateParameters);
		},
		// 进行rsa加密
		encrypt: function(bytes, publishKey){
			var doOaepPadding = false;
			publishKey = publishKey || this._rsaKeyStr;
			var rsa = this.getNewRsaProvider();
			// Import the RSA Key information.
			rsa.ImportParameters(this.getRsaKey(false,publishKey));
			// Encrypt the passed byte array and specify OAEP padding.
			return rsa.Encrypt(bytes, doOaepPadding);
		},
		// 进行rsa加密并转化为base64输出
		encryptToBase64: function(data,publishKey){
			var bytes = System.Text.Encoding.UTF8.GetBytes(data);
			var encryptedBytes = this.encrypt(bytes,publishKey);
			return System.Convert.ToBase64String(encryptedBytes);
		},
		// rsa 解密
		decrypt: function(bytes){
			var doOaepPadding = false;
			var rsa = this.getNewRsaProvider();
			// Import the RSA Key information.
			rsa.ImportParameters(this.getRsaKey(true,this._rsaKeyStr));
			// Decrypt the passed byte array and specify OAEP padding.
			return rsa.Decrypt(bytes, doOaepPadding);
		},
		// 进行rsa解密并转化为base64输出
		decryptToBase64: function(data){
			var encryptedBytes = System.Convert.FromBase64String(data);
			var decryptedBytes = this.decrypt(encryptedBytes);
			return System.Text.Encoding.UTF8.GetString(decryptedBytes);
		},
		// 获取公钥
		getPublishKey: function(){
			return this._rsaKeyStr.replace(/(<\/Exponent>)(\S+)(<\/RSAKeyValue>)/gm,'$1$3');
		},
		// 设置key
		setRsaKeyValue: function(str){
			this._rsaKeyStr = str;
		}
	};
	// 最后变成e2ee的加密方式
	window.e2eeUtil = {
		// 获取e2ee的公钥
		getPublishKey: function(){
			return rsaUtil.getPublishKey();
		},
		// e2ee 加密
		encrypt: function(data,publishKey, aesKey){
			// 主要分为4部分拼凑
			// 第四部分-数据密文
			var aesKey = aesUtil.createAESKey();
			var data_4 = aesUtil.encryptToBase64(aesKey,data);
			// 第三部分- AES密钥,用rsa算法加密
			var data_3 = rsaUtil.encryptToBase64(aesKey,publishKey);
			// 第二部分-第三部分长度 （转化为base64刚好是8个字符）
			var data_2 = System.Convert.ToBase64String(System.BitConverter.GetBytes(data_3.length));
			// 第一部分- 第四部分长度 （转化为base64刚好是8个字符）
			var data_1 = System.Convert.ToBase64String(System.BitConverter.GetBytes(data_4.length));
			var result = data_1 + data_2 +data_3 +data_4;
			console.log("发送的e2ee报文为：" + result);
			return result;
		},
		// e2ee 解密
		decrypt: function(data){
			console.log("接收到发送过来的e2ee报文为:", data);
			// 开始拆
			var data_1 = data.substr(0,8);
			var data_2 = data.substr(8,8);
			// 获取第三部分的长度, 即rsa加密过的AES密钥
			var data_3_len = System.BitConverter.ToInt32(System.Convert.FromBase64String(data_2), 0);
			// 获取第四部分的长度，即数据密文
			var data_4_len = System.BitConverter.ToInt32(System.Convert.FromBase64String(data_1), 0);
			// 接下来获取第三部分的AES的密钥，要用rsa来解密
			var data_3 = data.substr(16, data_3_len).trim();
			var keyForAES = rsaUtil.decryptToBase64(data_3);
			// 接下来用AES的key来解密文
			var data_4 = data.substr(16 + data_3_len, data_4_len).trim();
			var decrypted = aesUtil.decryptFromBase64(keyForAES, data_4);
			console.log("解密后的报文为：", decrypted);
			return decrypted;
		}
	};
})();