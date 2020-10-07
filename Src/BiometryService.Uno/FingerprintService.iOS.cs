#if __IOS__
using System;
using System.IO;
using System.Reactive;
using System.Reactive.Concurrency;
using System.Reactive.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using CoreFoundation;
using Foundation;
using LocalAuthentication;
using Microsoft.Extensions.Logging;
using ObjCRuntime;
using Security;
using UIKit;
using Uno;
using Uno.Extensions;
using Uno.Logging;
using AsyncLock = Uno.Threading.AsyncLock;

namespace BiometryService
{
	public class FingerprintService : IFingerprintService
	{
		FuncAsync<string> _description;
		IScheduler _dispatcher;
		AsyncLock _asyncLock;
		IObservable<bool> _isEnabled;
		IObservable<bool> _isSupported;
		private readonly bool _fallbackOnPasscodeAuthentication;

		private static readonly NSString kSecAttrApplicationTag;
		private static readonly NSString kSecAttrIsPermanent;
		private static readonly NSString kSecAttrKeyClass;
		private static readonly NSString kSecAttrKeyType;
		private static readonly NSString kSecAttrLabel;
		private static readonly NSString kSecClass;
		private static readonly NSString kSecReturnData;
		private static readonly NSString kSecValueRef;
		private static readonly NSString kSecPrivateKeyAttrs;
		private static readonly NSString kSecPublicKeyAttrs;

		static FingerprintService()
		{
			var securityLibrary = Dlfcn.dlopen(Constants.SecurityLibrary, 0);

			kSecAttrApplicationTag = Dlfcn.GetStringConstant(securityLibrary, "kSecAttrApplicationTag");
			kSecAttrIsPermanent = Dlfcn.GetStringConstant(securityLibrary, "kSecAttrIsPermanent");
			kSecAttrKeyClass = Dlfcn.GetStringConstant(securityLibrary, "kSecAttrKeyClass");
			kSecAttrKeyType = Dlfcn.GetStringConstant(securityLibrary, "kSecAttrKeyType");
			kSecAttrLabel = Dlfcn.GetStringConstant(securityLibrary, "kSecAttrLabel");
			kSecClass = Dlfcn.GetStringConstant(securityLibrary, "kSecClass");
			kSecReturnData = Dlfcn.GetStringConstant(securityLibrary, "kSecReturnData");
			kSecValueRef = Dlfcn.GetStringConstant(securityLibrary, "kSecValueRef");

			kSecPrivateKeyAttrs = Dlfcn.GetStringConstant(securityLibrary, "kSecPrivateKeyAttrs");
			kSecPublicKeyAttrs = Dlfcn.GetStringConstant(securityLibrary, "kSecPublicKeyAttrs");

			Dlfcn.dlclose(securityLibrary);
		}

		public FingerprintService(IObservable<Unit> applicationActivated, FuncAsync<string> description, IScheduler dispatcher, IScheduler backgroundScheduler, bool fallbackOnPasscodeAuthentication = false)
		{
			applicationActivated.Validation().NotNull(nameof(applicationActivated));
			description.Validation().NotNull(nameof(description));
			dispatcher.Validation().NotNull(nameof(dispatcher));
			backgroundScheduler.Validation().NotNull(nameof(backgroundScheduler));

			_description = description;

			_dispatcher = dispatcher;

			_asyncLock = new AsyncLock();

			_isSupported =
				applicationActivated
					.ObserveOn(backgroundScheduler)
					.StartWith(backgroundScheduler, Unit.Default)
					.Select(_ => CheckSupport())
					.Replay(1, backgroundScheduler)
					.RefCount();

			_isEnabled =
				_isSupported
					.Select(isSupported => isSupported && CheckEnrollment())
					.Replay(1, backgroundScheduler)
					.RefCount();

			_fallbackOnPasscodeAuthentication = fallbackOnPasscodeAuthentication;
		}

		private async Task AssertTouchIdIsEnabled(CancellationToken ct)
		{
			var enabled = await _isEnabled.FirstAsync();

			if (!enabled)
			{
				var supported = await _isSupported.FirstAsync();

				if (supported)
				{
					throw new InvalidOperationException("No fingerprint(s) registered.");
				}
				else
				{
					if (this.Log().IsEnabled(LogLevel.Warning))
					{
						this.Log().Warn("TouchID authentication is not available.");
					}

					throw new NotSupportedException("TouchID authentication is not available.");
				}
			}
		}

		public async Task<bool> Authenticate(CancellationToken ct)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug("Authenticating the fingerprint.");
			}

			await AssertTouchIdIsEnabled(ct);

			using (await _asyncLock.LockAsync(ct))
			{
				var context = new LAContext();

				// Using LAPolicy.DeviceOwnerAuthentication will make authentication fallback on the passcode if touch id fails.
				var authenticationPolicy = _fallbackOnPasscodeAuthentication ? LAPolicy.DeviceOwnerAuthentication : LAPolicy.DeviceOwnerAuthenticationWithBiometrys;

				// Must call CanEvaluatePolicy before LAContext.BiometryType can be read
				var canEvaluatePolicy = context.CanEvaluatePolicy(authenticationPolicy, out NSError error);

				if (canEvaluatePolicy && context.BiometryType == LABiometryType.FaceId)
				{
					// Verify that info.plist Contains NSFaceIDUsageDescription otherwise the app will crash when it tries to authenticate
					string faceIDUsageDescription = ((NSString)NSBundle.MainBundle.InfoDictionary["NSFaceIDUsageDescription"])?.ToString();

					if (string.IsNullOrEmpty(faceIDUsageDescription))
						throw new MissingFieldException("Please add a NSFaceIDUsageDescription key in Info.plist");
				}

				var (result, _) = await context.EvaluatePolicyAsync(authenticationPolicy, await _description(ct));

				if (this.Log().IsEnabled(LogLevel.Information))
				{
					this.Log().Info("Successfully authenticated the fingerprint.");
				}

				return result;
			}
		}

		private bool CheckEnrollment()
		{
			var context = new LAContext();

			return context.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrys, out var error) || (error.Code != -5 && error.Code != -7);
		}

		private bool CheckSupport()
		{
			var context = new LAContext();

			return UIDevice.CurrentDevice.CheckSystemVersion(9, 0) &&
				(context.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrys, out var error) || error.Code != -6);
		}

		public async Task<byte[]> Decrypt(CancellationToken ct, string keyName, byte[] data)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Decrypting the fingerprint for the key '{keyName}'.");
			}

			keyName.Validation().NotNullOrEmpty(nameof(keyName));
			data.Validation().NotNull(nameof(data));

			await AssertTouchIdIsEnabled(ct);

			using (await _asyncLock.LockAsync(ct))
			{
				try
				{
					var key = RetrieveKey(keyName, await _description(ct));

					if (key != null)
					{
						var result = await DecryptData(data, key);

						if (this.Log().IsEnabled(LogLevel.Information))
						{
							this.Log().Info($"Successfully decrypted the fingerprint for the key '{keyName}'.");
						}

						return result;
					}
					else
					{
						if (this.Log().IsEnabled(LogLevel.Information))
						{
							this.Log().Info($"Return null as the key is null.");
						}

						return null;
					}
				}
				catch (SecurityException ex)
				{
					throw new OperationCanceledException("Decryption was cancelled.", ex);
				}
			}
		}

		private async Task<byte[]> DecryptData(byte[] data, byte[] key)
		{
			using (var aes = Aes.Create())
			{
				aes.BlockSize = 128;
				aes.KeySize = 256;
				aes.Mode = CipherMode.CBC;
				aes.Padding = PaddingMode.PKCS7;

				var iv = new byte[16];

				Array.ConstrainedCopy(data, 0, iv, 0, 16);

				aes.IV = iv;
				aes.Key = key;

				using (var inputStream = new MemoryStream(data))
				{
					inputStream.Seek(16, SeekOrigin.Begin);

					using (var cryptoStream = new CryptoStream(inputStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
					using (var outputStream = new MemoryStream())
					{
						await cryptoStream.CopyToAsync(outputStream);

						return outputStream.ToArray();
					}
				}
			}
		}

		public async Task<byte[]> Encrypt(CancellationToken ct, string keyName, byte[] data)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Encrypting the fingerprint for the key '{keyName}'.");
			}

			keyName.Validation().NotNullOrEmpty(nameof(keyName));
			data.Validation().NotNull(nameof(data));

			await AssertTouchIdIsEnabled(ct);

			using (await _asyncLock.LockAsync(ct))
			{
				try
				{
					var key = GenerateKey();

					var result = await EncryptData(data, key);

					SaveKey(keyName, key);

					if (this.Log().IsEnabled(LogLevel.Information))
					{
						this.Log().Info($"The fingerprint is successfully encrypted for the key '{keyName}'.");
					}

					return result;
				}
				catch (SecurityException ex)
				{
					throw new OperationCanceledException("Encryption was cancelled.", ex);
				}
			}
		}

		private async Task<byte[]> EncryptData(byte[] data, byte[] key)
		{
			using (var aes = Aes.Create())
			{
				aes.BlockSize = 128;
				aes.KeySize = 256;
				aes.Mode = CipherMode.CBC;
				aes.Padding = PaddingMode.PKCS7;

				aes.Key = key;

				using (var outputStream = new MemoryStream())
				{
					await outputStream.WriteAsync(aes.IV, 0, aes.IV.Length);

					using (var cryptoStream = new CryptoStream(outputStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
					{
						await cryptoStream.WriteAsync(data, 0, data.Length);

						cryptoStream.Close();
					}

					return outputStream.ToArray();
				}
			}
		}

		public async Task Enroll(CancellationToken ct)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug("Enrolling the user for fingerprint authentication.");
			}

			var supported = await _isSupported.FirstAsync();

			if (supported)
			{
				DispatchQueue.MainQueue.DispatchAsync(() =>
				{

					var url = UIDevice.CurrentDevice.CheckSystemVersion(10, 0) ? "App-Prefs:root=" : "prefs:root=";

					UIApplication.SharedApplication.OpenUrl(new NSUrl(url));

					if (this.Log().IsEnabled(LogLevel.Information))
					{
						this.Log().Info("Successfully enrolled the user for fingerprint authentication.");
					}
				});
			}
			else
			{
				if (this.Log().IsEnabled(LogLevel.Warning))
				{
					this.Log().Warn("Fingerprint authentication is not available.");
				}

				throw new NotSupportedException("Fingerprint authentication is not available.");
			}
		}

		private byte[] GenerateKey()
		{
			using (var aes = Aes.Create())
			{
				aes.KeySize = 256;

				aes.GenerateKey();

				return aes.Key;
			}
		}

		public async Task<byte[]> GenerateKeyPair(CancellationToken ct, string name)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Generating a key pair (name: '{name}').");
			}

			name.Validation().NotNullOrEmpty(nameof(name));

			await AssertTouchIdIsEnabled(ct);

			using (await _asyncLock.LockAsync(ct))
			{
				var result = GenerateKeyPairCore(name);

				if (this.Log().IsEnabled(LogLevel.Information))
				{
					this.Log().Info($"Successfully generated a key pair (name: '{name}').");
				}

				return result;
			}
		}

		private byte[] GenerateKeyPairCore(string name)
		{
			using (var parameters = new SecRecord(SecKind.Key))
			{
				parameters.AccessControl = new SecAccessControl(SecAccessible.WhenPasscodeSetThisDeviceOnly, SecAccessControlCreateFlags.TouchIDCurrentSet | SecAccessControlCreateFlags.PrivateKeyUsage);
				parameters.KeyType = SecKeyType.EC;
				parameters.KeySizeInBits = 256;
				parameters.TokenID = SecTokenID.SecureEnclave;

				var privateKeyParameters = new NSMutableDictionary();
				privateKeyParameters.Add(kSecAttrApplicationTag, new NSString($"{name}_priv"));
				privateKeyParameters.Add(kSecAttrIsPermanent, NSNumber.FromBoolean(true));

				var publicKeyParameters = new NSMutableDictionary();
				publicKeyParameters.Add(kSecAttrApplicationTag, new NSString($"{name}_pub"));
				publicKeyParameters.Add(kSecAttrIsPermanent, NSNumber.FromBoolean(false));

				var mutableDictionary = (NSMutableDictionary)parameters.ToDictionary();
				mutableDictionary.Add(kSecPrivateKeyAttrs, new NSDictionary(privateKeyParameters));
				mutableDictionary.Add(kSecPublicKeyAttrs, new NSDictionary(publicKeyParameters));

				var result = SecKey.GenerateKeyPair((NSDictionary)mutableDictionary, out var publicKey, out var privateKey);

				if (result == SecStatusCode.Success)
				{
					privateKey.Dispose();

					using (var record = new SecRecord(SecKind.Key))
					{
						record.KeyClass = SecKeyClass.Public;
						record.KeyType = SecKeyType.EC;
						record.IsPermanent = false;
						record.Label = "Public Key";
						record.SetValueRef(publicKey);

						var dict = (NSMutableDictionary)record.ToDictionary();
						dict.Add(kSecReturnData, NSNumber.FromBoolean(true));

						var status = SecItemAdd(dict.Handle, out var publicKeyDataPtr);

						publicKey.Dispose();

						if (status == SecStatusCode.Success)
						{
							var publicKeyData = ObjCRuntime.Runtime.GetINativeObject<NSData>(publicKeyDataPtr, true);

							if (publicKeyData != null)
							{
								// Apple's SecurityFramework uses raw keys which need to be wrapped in proper ASN.1 for outside consumption
								// See : https://forums.developer.apple.com/thread/8030

								var header = NSData.FromArray(new byte[] { 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
																		   0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00 });

								var buffer = new NSMutableData(header.Length + publicKeyData.Length);
								buffer.AppendData(header);
								buffer.AppendData(publicKeyData);

								return buffer.ToArray();
							}
						}

						return null;
					}
				}
				else
				{
					throw new SecurityException(result);
				}
			}
		}

		public IObservable<bool> GetAndObserveIsEnabled() => _isEnabled;

		public IObservable<bool> GetAndObserveIsSupported() => _isSupported;

		public async Task<bool> RemoveKeyPair(CancellationToken ct, string name)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Removing the key pair (name: '{name}').");
			}

			name.Validation().NotNullOrEmpty(nameof(name));

			await AssertTouchIdIsEnabled(ct);

			using (await _asyncLock.LockAsync(ct))
			{
				var status = SecKeyChain.Remove(new SecRecord(SecKind.Key) { ApplicationTag = $"{name}_priv" });

				if (this.Log().IsEnabled(LogLevel.Information))
				{
					this.Log().Info($"Successfully removed the key pair (name: '{name}').");
				}

				return status == SecStatusCode.Success;
			}
		}

		private byte[] RetrieveKey(string keyName, string prompt)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Retrieving the key pair (key name: '{keyName}', prompt: '{prompt}').");
			}

			var record = new SecRecord(SecKind.GenericPassword)
			{
				Service = keyName.ToLowerInvariant(),
				UseOperationPrompt = prompt
			};

			var key = SecKeyChain.QueryAsRecord(record, out var result);

			switch (result)
			{
				case SecStatusCode.Success:

					if (this.Log().IsEnabled(LogLevel.Information))
					{
						this.Log().Info($"Successfully retrieved the key pair (key name: '{keyName}', prompt: '{prompt}').");
					}

					return key.Generic.ToArray();
				case SecStatusCode.AuthFailed:

					if (this.Log().IsEnabled(LogLevel.Information))
					{
						this.Log().Info($"Could not retrieve the key due to a failed authentication (key name: '{keyName}', prompt: '{prompt}').");
					}

					return default(byte[]);
				case SecStatusCode.ItemNotFound:
					throw new ArgumentException("Key not found.");
				default:
					throw new SecurityException(result);
			}
		}

		private void SaveKey(string keyName, byte[] keyData)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Saving the key (key name: '{keyName}').");
			}

			var record = new SecRecord(SecKind.GenericPassword)
			{
				Service = keyName.ToLowerInvariant(),
			};

			var status = SecKeyChain.Remove(record);

			if (status == SecStatusCode.Success || status == SecStatusCode.ItemNotFound)
			{
				record.AccessControl = new SecAccessControl(
					SecAccessible.WhenPasscodeSetThisDeviceOnly,
					_fallbackOnPasscodeAuthentication ? SecAccessControlCreateFlags.UserPresence : SecAccessControlCreateFlags.TouchIDCurrentSet
				);

				record.Generic = NSData.FromArray(keyData);

				var result = SecKeyChain.Add(record);

				if (result != SecStatusCode.Success)
				{
					throw new SecurityException(result);
				}

				if (this.Log().IsEnabled(LogLevel.Information))
				{
					this.Log().Info($"Successfully saved the key (key name: '{keyName}').");
				}
			}
			else
			{
				throw new SecurityException(status);
			}
		}

		[DllImport(Constants.SecurityLibrary)]
		private static extern SecStatusCode SecItemAdd(IntPtr dictHandle, out IntPtr result);

		public async Task<byte[]> Sign(CancellationToken ct, string pairName, byte[] data)
		{
			if (this.Log().IsEnabled(LogLevel.Debug))
			{
				this.Log().Debug($"Signing a key pair (pair name: '{pairName}').");
			}

			pairName.Validation().NotNullOrEmpty(nameof(pairName));
			data.Validation().NotNull(nameof(data));

			await AssertTouchIdIsEnabled(ct);

			using (await _asyncLock.LockAsync(ct))
			{
				try
				{
					var result = SignCore(pairName, data);

					if (this.Log().IsEnabled(LogLevel.Information))
					{
						this.Log().Info($"Successfully signed the key pair (pair name: '{pairName}').");
					}

					return result;
				}
				catch (SecurityException ex)
				{
					throw new OperationCanceledException("Signing was cancelled.", ex);
				}
			}
		}

		private byte[] SignCore(string pairName, byte[] data)
		{
			using (var record = new SecRecord(SecKind.Key))
			{
				record.ApplicationTag = $"{pairName}_priv";
				record.KeyClass = SecKeyClass.Private;
				record.KeyType = SecKeyType.EC;

				var result = SecKeyChain.QueryAsConcreteType(record, out var status);

				if (status == SecStatusCode.Success)
				{
					var privateKey = (SecKey)result;

					using (var sha256 = SHA256.Create())
					{
						var hash = sha256.ComputeHash(data);

						var signStatus = privateKey.RawSign(SecPadding.PKCS1, hash, out var signature);

						if (signStatus == SecStatusCode.Success)
						{
							return signature;
						}
						else
						{
							throw new SecurityException(signStatus);
						}

					}
				}
				else
				{
					throw new SecurityException(status);
				}
			}
		}
	}
}
#endif
