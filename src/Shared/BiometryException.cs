using System;

namespace BiometryService;

/// <summary>
/// Represents the <see cref="Exception"/> raised while trying to use biometry with <see cref="IBiometryService"/>.
/// </summary>
public sealed class BiometryException : Exception
{
	/// <summary>
	/// Initializes a new instance of the <see cref="BiometryException"/> class.
	/// </summary>
	/// <param name="reason"><see cref="BiometryExceptionReason"/>.</param>
	/// <param name="message">Exception message.</param>
	public BiometryException(BiometryExceptionReason reason, string message) : base(message)
	{
		Reason = reason;
	}

	/// <summary>
	/// Gets the <see cref="BiometryExceptionReason"/>.
	/// </summary>
	public BiometryExceptionReason Reason { get; }
}
