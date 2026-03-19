import 'dart:convert';
import 'dart:io' show Platform;
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';
import 'package:http/http.dart' as http;
import 'strava_config.dart';

/// Maneja OAuth2 con Strava: login, logout, refresh de tokens
class StravaAuthService {
  static final _storage = FlutterSecureStorage(
    mOptions: Platform.isMacOS
        ? const MacOsOptions(useDataProtectionKeyChain: false)
        : MacOsOptions.defaultOptions,
  );
  static const _keyAccessToken = 'strava_access_token';
  static const _keyRefreshToken = 'strava_refresh_token';
  static const _keyExpiresAt = 'strava_expires_at';
  static const _keyAthleteName = 'strava_athlete_name';
  static const _keyAthleteAvatar = 'strava_athlete_avatar';

  /// Verifica si hay tokens guardados
  Future<bool> get isAuthenticated async {
    final token = await _storage.read(key: _keyAccessToken);
    return token != null;
  }

  /// Nombre del atleta logueado
  Future<String?> get athleteName => _storage.read(key: _keyAthleteName);

  /// Avatar URL del atleta
  Future<String?> get athleteAvatar => _storage.read(key: _keyAthleteAvatar);

  String? _lastError;
  String? get lastError => _lastError;

  /// Inicia el flujo OAuth2 abriendo el browser
  Future<bool> login() async {
    try {
      _lastError = null;
      debugPrint('[STRAVA_AUTH] Starting OAuth flow...');

      final url = Uri.parse(
        '${StravaConfig.authorizeUrl}'
        '?client_id=${StravaConfig.clientId}'
        '&redirect_uri=${Uri.encodeComponent(StravaConfig.redirectUri)}'
        '&response_type=code'
        '&approval_prompt=auto'
        '&scope=${StravaConfig.scopes}',
      );

      debugPrint('[STRAVA_AUTH] OAuth URL: $url');
      debugPrint('[STRAVA_AUTH] Callback: ${StravaConfig.redirectUri}');

      final result = await FlutterWebAuth2.authenticate(
        url: url.toString(),
        callbackUrlScheme: StravaConfig.callbackUrlScheme,
        options: const FlutterWebAuth2Options(
          preferEphemeral: false,
        ),
      );

      debugPrint('[STRAVA_AUTH] Received callback: $result');

      final callbackUri = Uri.parse(result);
      final code = callbackUri.queryParameters['code'];
      final error = callbackUri.queryParameters['error'];

      if (error != null) {
        _lastError = 'Strava error: $error';
        debugPrint('[STRAVA_AUTH] ERROR from Strava: $error');
        return false;
      }

      if (code == null) {
        _lastError = 'No authorization code received. Callback: $result';
        debugPrint('[STRAVA_AUTH] ERROR: No code in callback. Full URL: $result');
        return false;
      }

      debugPrint('[STRAVA_AUTH] Got authorization code, exchanging...');
      return _exchangeCode(code);
    } catch (e, stackTrace) {
      _lastError = 'OAuth error: $e';
      debugPrint('[STRAVA_AUTH] ERROR: $e');
      debugPrint('[STRAVA_AUTH] Stack: $stackTrace');
      return false;
    }
  }

  /// Intercambia el código de autorización por tokens
  Future<bool> _exchangeCode(String code) async {
    try {
      debugPrint('[STRAVA_AUTH] Exchanging code for tokens...');
      final response = await http.post(
        Uri.parse(StravaConfig.tokenUrl),
        body: {
          'client_id': StravaConfig.clientId,
          'client_secret': StravaConfig.clientSecret,
          'code': code,
          'grant_type': 'authorization_code',
        },
      );

      debugPrint('[STRAVA_AUTH] Token response: ${response.statusCode}');
      if (response.statusCode != 200) {
        _lastError = 'Token exchange failed: ${response.body}';
        debugPrint('[STRAVA_AUTH] ERROR: ${response.body}');
        return false;
      }

      final data = json.decode(response.body) as Map<String, dynamic>;
      await _saveTokens(data);
      debugPrint('[STRAVA_AUTH] Tokens saved successfully!');
      return true;
    } catch (e, stackTrace) {
      _lastError = 'Token exchange error: $e';
      debugPrint('[STRAVA_AUTH] Exception in _exchangeCode: $e');
      debugPrint('[STRAVA_AUTH] Stack: $stackTrace');
      return false;
    }
  }

  /// Devuelve un access token válido, refrescando si es necesario
  Future<String?> getAccessToken() async {
    final expiresAtStr = await _storage.read(key: _keyExpiresAt);
    if (expiresAtStr != null) {
      final expiresAt = int.parse(expiresAtStr);
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      if (now >= expiresAt - 60) {
        final refreshed = await _refresh();
        if (!refreshed) return null;
      }
    }
    return _storage.read(key: _keyAccessToken);
  }

  /// Refresca el access token usando el refresh token
  Future<bool> _refresh() async {
    final refreshToken = await _storage.read(key: _keyRefreshToken);
    if (refreshToken == null) return false;

    final response = await http.post(
      Uri.parse(StravaConfig.tokenUrl),
      body: {
        'client_id': StravaConfig.clientId,
        'client_secret': StravaConfig.clientSecret,
        'refresh_token': refreshToken,
        'grant_type': 'refresh_token',
      },
    );

    if (response.statusCode != 200) return false;

    final data = json.decode(response.body) as Map<String, dynamic>;
    await _saveTokens(data);
    return true;
  }

  /// Persiste tokens y datos del atleta
  Future<void> _saveTokens(Map<String, dynamic> data) async {
    await _storage.write(key: _keyAccessToken, value: data['access_token'] as String);
    await _storage.write(key: _keyRefreshToken, value: data['refresh_token'] as String);
    await _storage.write(key: _keyExpiresAt, value: '${data['expires_at']}');

    final athlete = data['athlete'] as Map<String, dynamic>?;
    if (athlete != null) {
      final name = '${athlete['firstname'] ?? ''} ${athlete['lastname'] ?? ''}'.trim();
      await _storage.write(key: _keyAthleteName, value: name);
      await _storage.write(key: _keyAthleteAvatar, value: athlete['profile'] as String? ?? '');
    }
  }

  /// Cierra sesión borrando todos los tokens
  Future<void> logout() async {
    await _storage.delete(key: _keyAccessToken);
    await _storage.delete(key: _keyRefreshToken);
    await _storage.delete(key: _keyExpiresAt);
    await _storage.delete(key: _keyAthleteName);
    await _storage.delete(key: _keyAthleteAvatar);
  }
}
