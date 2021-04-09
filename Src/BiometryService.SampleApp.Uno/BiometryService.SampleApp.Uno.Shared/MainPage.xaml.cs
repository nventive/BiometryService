using System.Threading;
using System.Threading.Tasks;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Core;
#if __IOS__
using UIKit;
using LocalAuthentication;
#endif
#if __ANDROID__
using System.Reactive.Concurrency;
using BiometryService.SampleApp.Uno.Droid;
using AndroidX.Biometric;
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

		public MainPage()
		{
			this.InitializeComponent();

			var options = new BiometryOptions();
			options.LocalizedReasonBodyText = "REASON THAT APP WANTS TO USE BIOMETRY :)";
			options.LocalizedFallbackButtonText = "FALLBACK";
			options.LocalizedCancelButtonText = "CANCEL";

			// use LAPolicy.DeviceOwnerAuthenticationWithBiometrics for biometrics only with no fallback to passcode/password
			// use LAPolicy.DeviceOwnerAuthentication for biometrics+watch with fallback to passcode/password
#if __IOS__
             _biometryService = new BiometryService(options, async ct => "Biometrics_Confirm", LAPolicy.DeviceOwnerAuthentication);
#endif
#if __ANDROID__
			_biometryService = new BiometryService(MainActivity.Instance,
												   global::Uno.UI.ContextHelper.Current,
												   CoreDispatcher.Main,
												   async ct => await Task.FromResult(new BiometricPrompt.PromptInfo.Builder()
												.SetTitle("Biometrics SignIn")
												.SetSubtitle("Biometrics Confirm")
												.SetAllowedAuthenticators(BiometricManager.Authenticators.BiometricWeak | BiometricManager.Authenticators.DeviceCredential) // Fallback on secure pin
												.Build()));
#endif
#if __UWP__
#endif
		}

		private async Task Authenticate(CancellationToken ct)
		{
			var capabilities = _biometryService.GetCapabilities();
			if (!capabilities.PasscodeIsSet || !capabilities.IsSupported || !capabilities.IsEnabled)
			{
				if (!capabilities.PasscodeIsSet)
				{
				}
				else if (!capabilities.IsSupported)
				{
				}
				else if (!capabilities.IsEnabled)
				{
				}
				return;
			}

			var result = await _biometryService.ValidateIdentity(ct);
			//switch (result)
			//{
			//	//case BiometryAuthenticationResult.Granted:
			//	//	View.BackgroundColor = UIColor.SystemGreenColor;
			//	//	break;
			//	//case BiometryAuthenticationResult.Denied:
			//	//	View.BackgroundColor = UIColor.SystemRedColor;
			//	//	break;
			//	//case BiometryAuthenticationResult.Cancelled:
			//	//	View.BackgroundColor = UIColor.SystemYellowColor;
			//	//	break;
			//}
		}

		private async void SubmitButtonClick(object sender, RoutedEventArgs e)
		{
			await Authenticate(CancellationToken.None);
		}

	}
}
