using System.Threading;
using System.Threading.Tasks;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Core;
using System;
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

        private byte[] arrayEncrypted;

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

            //Note that not all combinations of authenticator types are supported prior to Android 11 (API 30). Specifically, DEVICE_CREDENTIAL alone is unsupported prior to API 30, and BIOMETRIC_STRONG | DEVICE_CREDENTIAL is unsupported on API 28-29
#if __ANDROID__
			if (Android.OS.Build.VERSION.SdkInt <= Android.OS.BuildVersionCodes.Q)
            {
                _biometryService = new BiometryService(MainActivity.Instance,
                                                   CoreDispatcher.Main,
                                                   ct => Task.FromResult(new BiometricPrompt.PromptInfo.Builder()
                                                    .SetTitle("Biometrics SignIn")
                                                    .SetSubtitle("Biometrics Confirm")
                                                    //.SetAllowedAuthenticators(BiometricManager.Authenticators.BiometricWeak | BiometricManager.Authenticators.DeviceCredential) // Fallback on secure pin WARNING cannot Encrypt data with this settings
                                                    .SetAllowedAuthenticators(BiometricManager.Authenticators.BiometricStrong) // used for Encrypt decrypt feature for device bellow Android 11
                                                    .SetNegativeButtonText("Cancel")
                                                    .Build())); 
			}
            else
            {
			    _biometryService = new BiometryService(MainActivity.Instance,
												   CoreDispatcher.Main,
                                                   ct => Task.FromResult(new BiometricPrompt.PromptInfo.Builder()
												    .SetTitle("Biometrics SignIn")
												    .SetSubtitle("Biometrics Confirm")
												    .SetAllowedAuthenticators(BiometricManager.Authenticators.BiometricStrong | BiometricManager.Authenticators.DeviceCredential) // Fallback on secure pin
                                                    .SetNegativeButtonText("Cancel")
                                                    .Build()));
			}
#endif
#if WINDOWS_UWP
            _biometryService = new BiometryService(true, true, TaskPoolScheduler.Default.ToBackgroundScheduler());
#endif
        }

        private async Task Authenticate(CancellationToken ct)
        {
            var capabilities = await _biometryService.GetCapabilities();
            if (!capabilities.PasscodeIsSet || !capabilities.IsSupported || !capabilities.IsEnabled)
            {
                var message = "";
                if (!capabilities.PasscodeIsSet)
                {
                    message += "Passcode is not Set; ";
                }
                else if (!capabilities.IsSupported)
                {
                    message += "Biometry is not Supported; ";
                }
                else if (!capabilities.IsEnabled)
                {
                    message += "Biometry is not Enabled; ";
                }
                if (string.IsNullOrEmpty(message))
                {
                    message = "Authentication Passed";
                }

                TxtAuthenticationStatus.Text = message;

                return;
            }

            var result = await _biometryService.ValidateIdentity(ct);

            TxtAuthenticationStatus.Text = "Authentication Passed";
        }

        private async Task Encrypt(CancellationToken ct)
        {
            if (!string.IsNullOrEmpty(TxtToEncrypt.Text))
            {
				try
				{
                    await _biometryService.Encrypt(ct, "Secret", TxtToEncrypt.Text);
                    TxtEncryptionStatus.Text = "Encryption Succeeded";
                }
                catch (Exception ex)
				{
                    TxtEncryptionStatus.Text = ex.Message;
                }
            }
        }

        private async Task Decrypt(CancellationToken ct)
        {
            try
            {
                var result = await _biometryService.Decrypt(ct, "Secret");
                TxtDecrypted.Text = result;
            }
            catch (Exception ex)
            {
                TxtDecrypted.Text = ex.Message;
            }
        }

        private async void AuthenticateButtonClick(object sender, RoutedEventArgs e)
        {
            await Authenticate(CancellationToken.None);
        }

        private async void EncryptButtonClick(object sender, RoutedEventArgs e)
        {
            await Encrypt(CancellationToken.None);
        }

        private async void DecryptButtonClick(object sender, RoutedEventArgs e)
        {
            await Decrypt(CancellationToken.None);
        }
    }
}
