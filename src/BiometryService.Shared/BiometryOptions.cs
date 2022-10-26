namespace BiometryService
{
	/// <summary>
	///     Options for configuring application behaviour when using biometrics.
	/// </summary>
	public class BiometryOptions
	{
		/// <summary>
		///     The body text with the localized reason for the authentication dialog presented to the user. The title of the text
		///     is set by the device.
		/// </summary>
		/// <remarks>
		///     <para>
		///         For TouchID, <see cref="LocalizedReasonBodyText" /> is immediately shown to the user.
		///     </para>
		///     <para>
		///         For FaceID, <see cref="LocalizedReasonBodyText" /> is only shown when the face has not been recognized after
		///         several attempts where the user is given the choice to fallback to device passcode/password.
		///     </para>
		///     <para>
		///         To use the default text, set <see cref="LocalizedReasonBodyText" /> to <c>null</c>.
		///     </para>
		/// </remarks>
		public string LocalizedReasonBodyText { get; set; }

		/// <summary>
		///     The text for the button that is presented to the user that allows the user to fallback to entering
		///     the device passcode/password.
		/// </summary>
		/// <remarks>
		///     <para>
		///         To use the default text, set <see cref="LocalizedFallbackButtonText" /> to <c>null</c>.
		///     </para>
		///     <para>
		///         To hide the fallback button from the user, set <see cref="LocalizedFallbackButtonText" /> to
		///         <see cref="string.Empty" />.
		///     </para>
		/// </remarks>
		public string LocalizedFallbackButtonText { get; set; }

		/// <summary>
		///     The text for the button presented to the user that allows the user to cancel biometric authentication.
		/// </summary>
		/// <remarks>
		///     <para>
		///         To use the default text, set <see cref="LocalizedCancelButtonText" /> to <c>null</c>.
		///     </para>
		/// </remarks>
		public string LocalizedCancelButtonText { get; set; }
	}
}
