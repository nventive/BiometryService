using System;

namespace BiometryService;

/// <summary>
/// Represents the <see cref="Exception"/> raised while trying to use biometry with <see cref="IBiometryService"/>.
/// </summary>
public sealed class BiometryException : Exception
{
	public BiometryException(BiometryExceptionReason reason, string message)
		: base(message)
	{
		Reason = reason;
	}

	/// <summary>
	/// Gets the <see cref="BiometryExceptionReason"/>.
	/// </summary>
	public BiometryExceptionReason Reason { get; }
}
