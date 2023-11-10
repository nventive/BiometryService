using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace BiometryService;

/// <summary>
/// Represents the base class for <see cref="IBiometryService"/> implementation.
/// </summary>
public abstract class BaseBiometryService : IBiometryService
{
	/// <summary>
	/// The logger.
	/// </summary>
	protected readonly ILogger Logger;

	/// <summary>
	/// Initializes a new instance of the <see cref="BaseBiometryService" /> class.
	/// </summary>
	/// <param name="loggerFactory">The logger factory.</param>
	public BaseBiometryService(ILoggerFactory loggerFactory = null)
	{
		Logger = loggerFactory?.CreateLogger<IBiometryService>() ?? NullLogger<IBiometryService>.Instance;
	}

	/// <inheritdoc/>
	public abstract Task<string> Decrypt(CancellationToken ct, string keyName);

	/// <inheritdoc/>
	public abstract Task Encrypt(CancellationToken ct, string keyName, string keyValue);

	/// <inheritdoc/>
	public abstract Task<BiometryCapabilities> GetCapabilities(CancellationToken ct);

	/// <inheritdoc/>
	public abstract void Remove(string keyName);

	/// <inheritdoc/>
	public abstract Task ScanBiometry(CancellationToken ct);

	/// <summary>
	/// Validates biometry capabilities and throw the right exception if they aren't valide.
	/// </summary>
	/// <param name="ct"><see cref="CancellationToken"/>.</param>
	/// <returns><see cref="Task"/>.</returns>
	/// <exception cref="BiometryException">.</exception>
	protected async Task ValidateBiometryCapabilities(CancellationToken ct)
	{
		if (Logger.IsEnabled(LogLevel.Debug))
		{
			Logger.LogDebug("Validating biometry capabilities.");
		}

		var biometryCapabilities = await GetCapabilities(ct);
		if (!biometryCapabilities.IsEnabled)
		{
			var reason = biometryCapabilities.IsSupported ? BiometryExceptionReason.NotEnrolled : BiometryExceptionReason.Unavailable;
			var message = biometryCapabilities.IsSupported ? "Biometrics are not enrolled on this device" : "Biometry is not available on this device";

			throw new BiometryException(reason, message);
		}

		if (Logger.IsEnabled(LogLevel.Information))
		{
			Logger.LogDebug("Biometry capabilities have been successfully validated.");
		}
	}
}
