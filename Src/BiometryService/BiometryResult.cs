using System;
using System.Collections.Generic;
using System.Text;

namespace BiometryService
{
	public class BiometryResult
	{
		public string Code { get; set; }
		public BiometryAuthenticationResult AuthenticationResult { get; set; }
		public string Message { get; set; }
	}

	public class AuthenticationError : Exception
	{
		public AuthenticationError(int code, string message) : base(message)
		{
			this.Code = code;
		}

		public int Code { get; }
	}

	/// <summary>
	///     Defines the possible results of user authentication using biometrics.
	/// </summary>
	public enum BiometryAuthenticationResult
	{
		/// <summary>
		///     The user has passed biometric authentication.
		/// </summary>
		Granted = 0,

		/// <summary>
		///     The user has failed biometric authentication.
		/// </summary>
		Denied,

		/// <summary>
		///     The user has refused biometric authentication.
		/// </summary>
		Cancelled
	}
}
