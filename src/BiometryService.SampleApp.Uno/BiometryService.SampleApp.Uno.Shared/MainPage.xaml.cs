using System.Threading;
using System.Threading.Tasks;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Core;
using System;
using Microsoft.Extensions.Logging;
#if __IOS__
using UIKit;
using LocalAuthentication;
#endif
#if __ANDROID__
using System.Reactive.Concurrency;
using BiometryService.SampleApp.Uno.Droid;
using AndroidX.Biometric;
#endif
#if WINDOWS_UWP
using System.Reactive.Concurrency;
#endif

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace BiometryService.SampleApp.Uno
{
	/// <summary>
	/// An empty page that can be used on its own or navigated to within a Frame.
	/// </summary>
	public sealed partial class MainPage : Page
	{
		private readonly IBiometryService _biometryService;
		private readonly CancellationToken _cancellationToken = CancellationToken.None;

		public MainPage()
		{
			this.InitializeComponent();

			// use LAPolicy.DeviceOwnerAuthenticationWithBiometrics for biometrics only with no fallback to passcode/password
			// use LAPolicy.DeviceOwnerAuthentication for biometrics+watch with fallback to passcode/password
#if __IOS__
			var laContext = new LAContext();
			laContext.LocalizedReason = "REASON THAT APP WANTS TO USE BIOMETRY :)";
			laContext.LocalizedFallbackTitle = "FALLBACK";
			laContext.LocalizedCancelTitle = "CANCEL";

			_biometryService = new BiometryService(
				laContext,
				"Biometrics_Confirm",
				LAPolicy.DeviceOwnerAuthentication,
				App.Instance.LoggerFactory);
#endif

			//Note that not all combinations of authenticator types are supported prior to Android 11 (API 30). Specifically, DEVICE_CREDENTIAL alone is unsupported prior to API 30, and BIOMETRIC_STRONG | DEVICE_CREDENTIAL is unsupported on API 28-29
#if __ANDROID__
			Func<BiometricPrompt.PromptInfo> promptBuilder;
			if (Android.OS.Build.VERSION.SdkInt <= Android.OS.BuildVersionCodes.Q)
			{
				promptBuilder = () => new BiometricPrompt.PromptInfo.Builder()
					.SetTitle("Biometrics SignIn")
					.SetSubtitle("Biometrics Confirm")
					//.SetAllowedAuthenticators(BiometricManager.Authenticators.BiometricWeak | BiometricManager.Authenticators.DeviceCredential) // Fallback on secure pin WARNING cannot Encrypt data with this settings
					.SetAllowedAuthenticators(BiometricManager.Authenticators.BiometricStrong) // used for Encrypt decrypt feature for device bellow Android 11
					.SetNegativeButtonText("Cancel")
					.Build();
			}
			else
			{
				promptBuilder = () => new BiometricPrompt.PromptInfo.Builder()
					.SetTitle("Biometrics SignIn")
					.SetSubtitle("Biometrics Confirm")
					// BiometricManager.Authenticators.DeviceCredential == Fallback on secure pin
					.SetAllowedAuthenticators(BiometricManager.Authenticators.BiometricStrong)
					// Do not set NegativeButtonText if BiometricManager.Authenticators.DeviceCredential is allowed with BiometricManager.Authenticators.BiometricStrong
					.SetNegativeButtonText("Cancel")
					.Build();
			}

			_biometryService = new BiometryService(
				MainActivity.Instance,
				promptBuilder,
				App.Instance.LoggerFactory
			);
#endif
#if WINDOWS_UWP
			_biometryService = new BiometryService(App.Instance.LoggerFactory);
#endif

			_ = LoadCapabilities(_cancellationToken);
		}

		private async Task LoadCapabilities(CancellationToken ct)
		{
			var capabilities = await _biometryService.GetCapabilities(ct);

			BiometryTypeTxt.Text = capabilities.BiometryType.ToString();
			IsSupportedTxt.Text = capabilities.IsSupported.ToString();
			IsEnabledTxt.Text = capabilities.IsEnabled.ToString();
			IsPasscodeSetTxt.Text = capabilities.IsPasscodeSet.ToString();
		}

		private async void AuthenticateButtonClick(object sender, RoutedEventArgs e)
		{
			await LoadCapabilities(_cancellationToken);

			try
			{
				await _biometryService.ScanBiometry(_cancellationToken);
				TxtAuthenticationStatus.Text = "Authentication Passed";
			}
			catch (BiometryException biometryException)
			{
				TxtAuthenticationStatus.Text = ParseBiometryException(biometryException);
			}
			catch (Exception ex)
			{
				TxtAuthenticationStatus.Text = ex.Message;
			}
		}

		private async void EncryptButtonClick(object sender, RoutedEventArgs e)
		{
			// Clear remove output message.
			TxtRemove.Text = string.Empty;

			await LoadCapabilities(_cancellationToken);
			try
			{
				await _biometryService.Encrypt(_cancellationToken, "Secret", TxtToEncrypt.Text);
				TxtEncryptionStatus.Text = "Encryption Succeeded";
			}
			catch (BiometryException biometryException)
			{
				TxtEncryptionStatus.Text = ParseBiometryException(biometryException);
			}
			catch (Exception ex)
			{
				TxtEncryptionStatus.Text = ex.Message;
			}
		}

		private async void DecryptButtonClick(object sender, RoutedEventArgs e)
		{
			// Clear remove output message.
			TxtRemove.Text = string.Empty;

			await LoadCapabilities(_cancellationToken);
			try
			{
				var result = await _biometryService.Decrypt(_cancellationToken, "Secret");
				TxtDecrypted.Text = result;
			}
			catch (BiometryException biometryException)
			{
				TxtDecrypted.Text = ParseBiometryException(biometryException);
			}
			catch (Exception ex)
			{
				TxtDecrypted.Text = ex.Message;
			}
		}

		private async void RemoveButtonClick(object sender, RoutedEventArgs e)
		{
			await LoadCapabilities(_cancellationToken);
			try
			{
				_biometryService.Remove("Secret");
				TxtRemove.Text = "Encrypted value removed successfully";
			}
			catch (BiometryException biometryException)
			{
				TxtRemove.Text = ParseBiometryException(biometryException);
			}
			catch (Exception ex)
			{
				TxtRemove.Text = ex.Message;
			}
		}

		private string ParseBiometryException(BiometryException e)
		{
			return "Reason:" + e.Reason + "\n" + "msg:" + e.Message;
		}
	}
}
