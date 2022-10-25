using System;

namespace BiometryService;

/// <summary>
/// Defines the type of biometry that is available to the device.
/// </summary>
/// <remarks>
/// It is technically possible that a device has multiple biometric available.
/// That's the reason why this enum has <see cref="FlagsAttribute"/>.
/// </remarks>
[Flags]
public enum BiometryType : byte
{
	/// <summary>
	///	No biometric identifier.
	/// </summary>
	None,

	/// <summary>
	///	The device has a fingerprint biometric.
	/// </summary>
	Fingerprint,

	/// <summary>
	///	The device has a face biometric.
	/// </summary>
	Face,
}
