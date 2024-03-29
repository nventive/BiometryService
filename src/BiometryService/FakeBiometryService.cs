﻿using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System;

namespace BiometryService;

/// <summary>
/// Fake implementation of the <see cref="IBiometryService" /> for tests.
/// </summary>
/// <remarks>
/// This implementation does not encrypt anything and is only made for testing purposes.
/// The key and value pairs are stored in memory.
/// </remarks>
public sealed class FakeBiometryService : BaseBiometryService
{
	private readonly BiometryType _biometryType;
	private readonly bool _isBiometryEnabled;
	private readonly bool _isPasscodeSet;

	private readonly Dictionary<string, string> _keyValuePairs = new();

	/// <summary>
	/// Initializes a new instance of the <see cref="FakeBiometryService" /> class.
	/// </summary>
	/// <param name="loggerFactory">The logger factory.</param>
	/// <param name="biometryType">The biometry type for <see cref="IBiometryService.GetCapabilities(CancellationToken)"/>.</param>
	/// <param name="isBiometryEnabled">If the biometry is enabled for <see cref="IBiometryService.GetCapabilities(CancellationToken)"/>.</param>
	/// <param name="isPasscodeSet">If the passcode is set for <see cref="IBiometryService.GetCapabilities(CancellationToken)"/>.</param>
	public FakeBiometryService(
		ILoggerFactory loggerFactory = null,
		BiometryType biometryType = BiometryType.None,
		bool isBiometryEnabled = false,
		bool isPasscodeSet = false
	) : base(loggerFactory)
	{
		_biometryType = biometryType;
		_isBiometryEnabled = isBiometryEnabled;
		_isPasscodeSet = isPasscodeSet;
	}

	/// <inheritdoc/>
	public override async Task<string> Decrypt(CancellationToken ct, string key)
	{
		await ValidateBiometryCapabilities(ct);

		if (_keyValuePairs.TryGetValue(key, out var value))
		{
			if (Logger.IsEnabled(LogLevel.Debug))
			{
				Logger.LogDebug("The key '{key}' has been successfully decrypted.", key);
			}
			return value;
		}
		throw new BiometryException(BiometryExceptionReason.KeyInvalidated, $"Key '{key}' not found.");
	}

	/// <inheritdoc/>
	public override async Task Encrypt(CancellationToken ct, string key, string value)
	{
		try
		{
			await ValidateBiometryCapabilities(ct);

			if (_keyValuePairs.ContainsKey(key))
			{
				_keyValuePairs.Remove(key);
			}

			_keyValuePairs.Add(key, value);

			if (Logger.IsEnabled(LogLevel.Debug))
			{
				Logger.LogDebug("The key '{key}' has been successfully encrypted.", key);
			}
		}
		catch (Exception)
		{
			if (Logger.IsEnabled(LogLevel.Debug))
			{
				Logger.LogDebug("The key '{key}' has not been successfully encrypted.", key);
			}
			throw new BiometryException(BiometryExceptionReason.Failed, $"Something went wrong while saving the key '{key}'.");
		}
	}

	/// <inheritdoc/>
	public override Task<BiometryCapabilities> GetCapabilities(CancellationToken ct)
	{
		if (Logger.IsEnabled(LogLevel.Debug))
		{
			Logger.LogDebug("Biometry capabilities has been successfully assessed.");
		}
		return Task.FromResult(new BiometryCapabilities(_biometryType, _isBiometryEnabled, _isPasscodeSet));
	}

	/// <inheritdoc/>
	public override void Remove(string key)
	{
		if (_keyValuePairs.Remove(key))
		{
			if (Logger.IsEnabled(LogLevel.Debug))
			{
				Logger.LogDebug("The key '{key}' has been successfully removed.", key);
			}
		}
		throw new BiometryException(BiometryExceptionReason.Failed, $"Something went wrong while removing the key '{key}'.");
	}

	/// <inheritdoc/>
	public override async Task ScanBiometry(CancellationToken ct)
	{
		await ValidateBiometryCapabilities(ct);

		if (Logger.IsEnabled(LogLevel.Debug))
		{
			Logger.LogDebug("Biometry has been successfully scanned.");
		}
	}
}
