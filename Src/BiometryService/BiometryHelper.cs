using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace BiometryService
{
	internal static class BiometryHelper
	{
		internal static byte[] GenerateKey()
		{
			using (var aes = Aes.Create())
			{
				aes.KeySize = 256;

				aes.GenerateKey();

				return aes.Key;
			}
		}

		internal static async Task<byte[]> EncryptData(byte[] data, byte[] key)
		{
			using (var aes = Aes.Create())
			{
				aes.BlockSize = 128;
				aes.KeySize = 256;
				aes.Mode = CipherMode.CBC;
				aes.Padding = PaddingMode.PKCS7;

				aes.Key = key;

				using (var outputStream = new MemoryStream())
				{
					await outputStream.WriteAsync(aes.IV, 0, aes.IV.Length);

					using (var cryptoStream = new CryptoStream(outputStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
					{
						await cryptoStream.WriteAsync(data, 0, data.Length);

						cryptoStream.Close();
					}

					return outputStream.ToArray();
				}
			}
		}

		internal static async Task<byte[]> DecryptData(byte[] data, byte[] key)
		{
			using (var aes = Aes.Create())
			{
				aes.BlockSize = 128;
				aes.KeySize = 256;
				aes.Mode = CipherMode.CBC;
				aes.Padding = PaddingMode.PKCS7;

				var iv = new byte[16];

				Array.ConstrainedCopy(data, 0, iv, 0, 16);

				aes.IV = iv;
				aes.Key = key;

				using (var inputStream = new MemoryStream(data))
				{
					inputStream.Seek(16, SeekOrigin.Begin);

					using (var cryptoStream = new CryptoStream(inputStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
					using (var outputStream = new MemoryStream())
					{
						await cryptoStream.CopyToAsync(outputStream);

						return outputStream.ToArray();
					}
				}
			}
		}
	}
}
