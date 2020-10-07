using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace BiometryService
{
	public partial class BiometryEncryptionFlowService
	{
		public interface IEventsDelegate
		{
			/// <summary>
			/// Prompts the user if he wants to use Biometry encryption.
			/// </summary>
			/// <param name="ct">Cancellation token</param>
			/// <param name="objectKey">Object's key</param>
			/// <returns>True if the user agrees; false otherwise.</returns>
			Task<bool> RequestBiometryEncryptionUsage(CancellationToken ct, string objectKey);

			/// <summary>
			/// Happens when the encryptions fails.
			/// </summary>
			/// <param name="ct">Cancellation token</param>
			/// <param name="objectKey">Object's key</param>
			Task OnEncryptionFailed(CancellationToken ct, string objectKey);

			/// <summary>
			/// Happens when the decryption fails.
			/// </summary>
			/// <param name="ct">Cancellation token</param>
			/// <param name="objectKey">Object's key</param>
			Task OnDecryptionFailed(CancellationToken ct, string objectKey);

			/// <summary>
			/// Happens when the decryption failed and the data had to be reset.
			/// </summary>
			/// <param name="ct">Cancellation token</param>
			/// <param name="objectKey">Object's key</param>
			Task OnEncryptionReset(CancellationToken ct, string objectKey);
		}
	}
}
