// Copyright 2019-2020 Gohilla.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:async';
import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../../cryptography_flutter.dart';
import '../_flutter_cryptography_implementation.dart';
import '../_internal.dart';

/// Superclass for [Cipher] classes that use platform APIs.
abstract class FlutterCipher
    implements StreamingCipher, PlatformCryptographicAlgorithm {
  /// Default [CryptographyChannelPolicy] for communicating with the plugin.
  ///
  /// The values were chosen experimentally by observing performance.
  static final CryptographyChannelPolicy defaultChannelPolicy =
      CryptographyChannelPolicy(
    // Experimentally chosen value.
    minLength: 2000,

    // A too high value causes crashes on Android.
    maxLength: CryptographyChannelQueue.defaultInstance.maxConcurrentSize,
  );

  /// Raw-bytes decrypt (see `decryptRaw` in the Android plugin): one request
  /// buffer, and clear text read straight out of the reply, where the method
  /// channel's codec copies both into growing buffers on each side.
  static const _decryptChannel = 'cryptography_flutter/decrypt';

  /// Set once a platform turns out to have no raw decrypt handler — every
  /// platform but Android — so later calls go straight to the method channel.
  static bool _rawDecryptMissing = false;

  static const _statusOk = 0;
  static const _statusIncorrectMac = 1;
  static const _statusIncorrectPadding = 2;
  static const _statusUnsupported = 3;

  /// Null where the platform has no raw decrypt handler.
  static Future<Uint8List?> _decryptRaw({
    required String name,
    required Uint8List secretKey,
    required Uint8List nonce,
    required Uint8List aad,
    required List<int> cipherText,
    required Uint8List mac,
  }) async {
    if (_rawDecryptMissing) return null;
    final nameBytes = utf8.encode(name);
    final request = Uint8List(
      1 + nameBytes.length + 1 + secretKey.length + 1 + nonce.length + 4 + aad.length + cipherText.length + mac.length,
    );
    var i = 0;
    void put(List<int> bytes) {
      request.setAll(i, bytes);
      i += bytes.length;
    }

    request[i++] = nameBytes.length;
    put(nameBytes);
    request[i++] = secretKey.length;
    put(secretKey);
    request[i++] = nonce.length;
    put(nonce);
    ByteData.sublistView(request).setUint32(i, aad.length);
    i += 4;
    put(aad);
    put(cipherText);
    put(mac);

    final reply = await ServicesBinding.instance.defaultBinaryMessenger.send(_decryptChannel, ByteData.sublistView(request));
    if (reply == null) {
      _rawDecryptMissing = true;
      return null;
    }
    final body = Uint8List.sublistView(reply, 1);
    switch (reply.getUint8(0)) {
      case _statusOk:
        return body;
      case _statusIncorrectMac:
        throw SecretBoxAuthenticationError();
      case _statusIncorrectPadding:
        throw SecretBoxPaddingError(message: utf8.decode(body));
      case _statusUnsupported:
        throw UnsupportedError(utf8.decode(body));
      default:
        throw PlatformException(code: 'DECRYPT_FAILED', message: utf8.decode(body));
    }
  }

  @protected
  static Future<List<int>> decryptWithPlugin({
    required String name,
    required FlutterCipher cipher,
    Cipher? fallback,
    PaddingAlgorithm? paddingAlgorithm,
    required SecretBox secretBox,
    required SecretKey secretKey,
    required List<int> aad,
  }) async {
    final secretKeyData = await secretKey.extractBytes();
    final secretKeyUint8List = asUint8List(secretKeyData);
    final nonceUint8List = asUint8List(secretBox.nonce);
    final macUint8List = asUint8List(secretBox.mac.bytes);
    final aadUint8List = asUint8List(aad);

    if (secretKeyUint8List.length != cipher.secretKeyLength) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'Expected a secret key with ${cipher.secretKeyLength} bytes, got ${secretKeyUint8List.length} bytes.',
      );
    }
    if (nonceUint8List.length != cipher.nonceLength) {
      throw ArgumentError.value(
        secretBox,
        'secretBox',
        'Expected a nonce with ${cipher.nonceLength} bytes, got ${nonceUint8List.length} bytes.',
      );
    }
    final macAlgorithm = cipher.macAlgorithm;
    if (macUint8List.length != macAlgorithm.macLength) {
      throw SecretBoxAuthenticationError();
    }
    if (aadUint8List.isNotEmpty && !macAlgorithm.supportsAad) {
      throw ArgumentError(
        'AAD is not supported by $macAlgorithm, but parameter `aad` is non-empty.',
      );
    }

    final cipherText = secretBox.cipherText;
    final cipherTextSize = cipherText.length;
    final lock = CryptographyChannelQueue.defaultInstance.newLock(
      size: cipherTextSize,
    );
    await lock.lock();
    late Uint8List clearText;
    try {
      final raw = await _decryptRaw(
        name: name,
        secretKey: secretKeyUint8List,
        nonce: nonceUint8List,
        aad: aadUint8List,
        cipherText: secretBox.cipherText,
        mac: macUint8List,
      );
      if (raw != null) {
        clearText = raw;
      } else {
        final cipherTextUint8List = asUint8List(secretBox.cipherText);
        final result = await invokeMethod(
          'decrypt',
          {
            'algo': name,
            'data': cipherTextUint8List,
            'key': secretKeyUint8List,
            'nonce': nonceUint8List,
            'mac': macUint8List,
            'aad': aadUint8List,
          },
          useQueue: false, // We do queueing ourselves
        );
        clearText = result['clearText'] as Uint8List;
      }
    } on UnsupportedError {
      if (fallback == null) {
        rethrow;
      }
      return fallback.decrypt(
        secretBox,
        secretKey: secretKey,
        aad: aad,
      );
    } on PlatformException catch (error) {
      switch (error.code) {
        case 'INCORRECT_MAC':
          throw SecretBoxAuthenticationError();

        case 'INCORRECT_PADDING':
          throw SecretBoxPaddingError(
            message: error.message,
          );

        default:
          rethrow;
      }
    } finally {
      lock.unlock();
    }

    // Sanity check
    if (cipherTextSize != cipher.cipherTextLength(clearText.length)) {
      throw StateError(
        '${cipher.runtimeType}.decrypt sanity check failed: '
        'clearText.length (${clearText.length}) != '
        'cipherText.length ($cipherTextSize)',
      );
    }

    return clearText;
  }

  @protected
  static Future<SecretBox> encryptWithPlugin({
    required String name,
    required FlutterCipher cipher,
    Cipher? fallback,
    required List<int> clearText,
    required SecretKey secretKey,
    required List<int>? nonce,
    required List<int> aad,
  }) async {
    final secretKeyData = await secretKey.extractBytes();
    final secretKeyUint8List = asUint8List(secretKeyData);
    nonce ??= cipher.newNonce();
    final nonceUint8List = asUint8List(nonce);
    final aadUint8List = asUint8List(aad);

    if (secretKeyUint8List.length != cipher.secretKeyLength) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'Expected ${cipher.secretKeyLength} bytes, got ${secretKeyUint8List.length} bytes.',
      );
    }

    if (nonce.length != cipher.nonceLength) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Expected ${cipher.nonceLength} bytes, got ${nonce.length} bytes.',
      );
    }

    final macAlgorithm = cipher.macAlgorithm;
    if (aad.isNotEmpty && !macAlgorithm.supportsAad) {
      throw ArgumentError(
        'AAD is not supported by $macAlgorithm, but parameter `aad` is non-empty.',
      );
    }

    final clearTextSize = clearText.length;
    final lock = CryptographyChannelQueue.defaultInstance.newLock(
      size: clearTextSize,
    );
    await lock.lock();
    Map result;
    try {
      final clearTextUint8List = asUint8List(clearText);
      result = await invokeMethod(
        'encrypt',
        {
          'algo': name,
          'data': clearTextUint8List,
          'key': secretKeyUint8List,
          'nonce': nonceUint8List,
          'aad': aadUint8List,
        },
        useQueue: false, // We do queueing ourselves
      );
    } on UnsupportedError {
      if (fallback == null) {
        rethrow;
      }
      return fallback.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
        aad: aad,
      );
    } finally {
      lock.unlock();
    }

    final cipherText = result['cipherText'] as Uint8List;

    // Sanity check
    if (cipherText.length != cipher.cipherTextLength(clearTextSize)) {
      throw StateError(
        '${cipher.runtimeType}.encrypt sanity check failed: '
        'cipherText.length (${cipherText.length}) != '
        'clearText.length (size})',
      );
    }

    final macBytes = result['mac'] as Uint8List;
    return SecretBox(
      cipherText,
      nonce: nonce,
      mac: Mac(macBytes),
    );
  }
}

mixin FlutterCipherMixin
    implements FlutterCipher, PlatformCryptographicAlgorithm {
  String get channelCipherName;

  CryptographyChannelPolicy get channelPolicy;

  @override
  Cipher? get fallback;

  @override
  int cipherTextLength(int clearTextLength) {
    return clearTextLength;
  }

  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
    Uint8List? possibleBuffer,
  }) {
    if (!kIsWeb &&
        isSupportedPlatform &&
        FlutterCryptography.isPluginPresent &&
        channelPolicy.matches(length: secretBox.cipherText.length)) {
      return FlutterCipher.decryptWithPlugin(
        name: channelCipherName,
        cipher: this,
        fallback: this.fallback,
        secretBox: secretBox,
        secretKey: secretKey,
        aad: aad,
      );
    }

    final fallback = this.fallback;
    if (fallback == null) {
      throw UnsupportedError('No fallback was specified.');
    }

    return fallback.decrypt(
      secretBox,
      secretKey: secretKey,
      aad: aad,
    );
  }

  @override
  Stream<List<int>> decryptStream(
    Stream<List<int>> stream, {
    required SecretKey secretKey,
    required List<int> nonce,
    required FutureOr<Mac> mac,
    List<int> aad = const [],
    bool allowUseSameBytes = false,
  }) {
    // Currently streaming must be done in the main thread.
    return toSync().decryptStream(
      stream,
      secretKey: secretKey,
      nonce: nonce,
      mac: mac,
      aad: aad,
      allowUseSameBytes: allowUseSameBytes,
    );
  }

  @override
  Future<SecretBox> encrypt(
    List<int> clearText, {
    required SecretKey secretKey,
    List<int>? nonce,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
    Uint8List? possibleBuffer,
  }) {
    if (!kIsWeb &&
        isSupportedPlatform &&
        FlutterCryptography.isPluginPresent &&
        channelPolicy.matches(length: clearText.length)) {
      return FlutterCipher.encryptWithPlugin(
        name: channelCipherName,
        cipher: this,
        fallback: this.fallback,
        clearText: clearText,
        secretKey: secretKey,
        nonce: nonce,
        aad: aad,
      );
    }

    final fallback = this.fallback;
    if (fallback == null) {
      throw UnsupportedError('No fallback was specified.');
    }

    return fallback.encrypt(
      clearText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
  }

  @override
  Stream<List<int>> encryptStream(
    Stream<List<int>> stream, {
    required SecretKey secretKey,
    required List<int> nonce,
    required void Function(Mac mac) onMac,
    List<int> aad = const [],
    bool allowUseSameBytes = false,
  }) {
    // Currently streaming must be done in the main thread.
    return toSync().encryptStream(
      stream,
      secretKey: secretKey,
      nonce: nonce,
      onMac: onMac,
      aad: aad,
      allowUseSameBytes: allowUseSameBytes,
    );
  }

  @override
  CipherState newState() {
    // Currently streaming must be done in the main thread.
    return toSync().newState();
  }
}
