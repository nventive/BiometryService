using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace BiometryService
{
	public partial class BiometryEncryptionFlowService
	{
		public interface IPersistenceDelegate
		{
			/// <summary>
			/// Saves the encrypted result for future decryption.
			/// </summary>
			/// <param name="ct">Cancellation token</param>
			/// <param name="objectKey">Object's key</param>
			/// <param name="encryptedResult">Encrypted result</param>
			Task SaveEncryptedResult(CancellationToken ct, string objectKey, byte[] encryptedResult);

			/// <summary>
			/// Loads the encrypted result for decryption.
			/// </summary>
			/// <param name="ct">Cancellation token</param>
			/// <param name="objectKey">Object's key</param>
			/// <returns>Encrypted result</returns>
			Task<byte[]> LoadEncryptedResult(CancellationToken ct, string objectKey);

			/// <summary>
			/// Determines if the biometry encryption is enabled in the application.
			/// </summary>
			/// <param name="ct">Cancellation token</param>
			/// <param name="objectKey">Object's key</param>
			/// <returns>True if enabled; false otherwise</returns>
			Task<bool> GetIsBiometryEncryptionEnabled(CancellationToken ct, string objectKey);

			/// <summary>
			/// Sets if the biometry encryption is enabled in the application.
			/// </summary>
			/// <param name="ct">Cancellation token</param>
			/// <param name="objectKey">Object's key</param>
			/// <param name="isBiometryEncryptionEnabled">Is Biometry encryption enabled</param>
			Task SetIsBiometryEncryptionEnabled(CancellationToken ct, string objectKey, bool isBiometryEncryptionEnabled);
		}
	}
}
