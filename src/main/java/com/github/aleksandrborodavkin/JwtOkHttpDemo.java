package com.github.aleksandrborodavkin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import okhttp3.*;
import okhttp3.logging.HttpLoggingInterceptor;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;

// Record для простого описания контакта
record Contact(long id, String username, String firstName, String lastName, String photoUrl) {
}

public class JwtOkHttpDemo {

    // --- ИНСТРУМЕНТЫ ---
    private final OkHttpClient httpClient;
    private final ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    public JwtOkHttpDemo() {
        // Настраиваем логгер OkHttp для красивого вывода
        HttpLoggingInterceptor loggingInterceptor = new HttpLoggingInterceptor(message -> {
            // Убираем технические префиксы (дата, уровень INFO)
            if (message.startsWith("-->")) {
                String output = String.format("""
                        \u001B[32m%s   -->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->-->--> \u001B[0m
                        """, message
                );
                System.out.println(output);
            } else if (message.startsWith("<--")) {
                String output = String.format(""" 
                        \u001B[36m %s   <--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<--<-- \u001B[0m
                        """, message
                );
                System.out.println(output);
            } else {
                System.out.println("    " + message);
            }
        });
        loggingInterceptor.setLevel(HttpLoggingInterceptor.Level.BODY);

        this.httpClient = new OkHttpClient.Builder()
                .addInterceptor(loggingInterceptor)
                .build();
    }

    // --- СОСТОЯНИЕ АУТЕНТИФИКАЦИИ ---
    private String currentAccessToken;
    private String currentRefreshToken;
    private JwtParser jwtParser;

    // --- АДРЕСА НА СЕРВЕРЕ ---
    private String serverBaseUrl = "https://java41.ru/";
    private static final String PUB_KEY_PATH = "/public-key";
    private static final String LOGIN_PATH = "/auth/login";
    private static final String REFRESH_PATH = "/auth/refresh";
    private static final String CONTACTS_PATH = "/contacts";
    private static final MediaType JSON_MEDIA = MediaType.get("application/json; charset=utf-8");

    public static void main(String[] args) {
        JwtOkHttpDemo demo = new JwtOkHttpDemo();

        System.out.println("--- Демонстрация работы с JWT через OkHttp ---");
        System.out.println("Используется сервер: " + demo.serverBaseUrl);

        try {
            if (!demo.loadPublicKeyAction()) {
                System.err.println("\nОШИБКА: Не удалось загрузить публичный ключ. Демонстрация прервана.");
                return;
            }

            if (!demo.loginAction("user@example.com", "password123")) {
                System.err.println("\nОШИБКА: Не удалось войти. Демонстрация прервана.");
                return;
            }

            System.out.println("\n--- Попытка получить контакты #1 (после логина) ---");
            demo.getContactsAction();

            if (!demo.refreshAction()) {
                System.err.println("\nОШИБКА: Не удалось обновить токен.");
            }

            System.out.println("\n--- Попытка получить контакты #2 (после обновления токена) ---");
            demo.getContactsAction();

            System.out.println("\n--- Демонстрация проверки испорченного токена ---");
            if (demo.currentAccessToken != null && demo.jwtParser != null) {
                String tamperedToken = demo.currentAccessToken.substring(0, demo.currentAccessToken.length() - 5) + "XXXXX";
                verifyAndDisplayTokenStatic(tamperedToken, "Испорченный Access Token", demo.jwtParser, demo.objectMapper);
            } else {
                System.out.println("Нет Access Token или JwtParser для демонстрации испорченного токена.");
            }

        } catch (Exception e) {
            System.err.println("\nКРИТИЧЕСКАЯ ОШИБКА в ходе демонстрации: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private String buildFullUrl(String path) {
        String base = this.serverBaseUrl.trim();
        if (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        return base + path;
    }

    // --- 1. ЗАГРУЗКА ПУБЛИЧНОГО КЛЮЧА ---
    public boolean loadPublicKeyAction() {
        System.out.println("\n1. Загрузка публичного ключа...");
        jwtParser = null;

        Request request = new Request.Builder().url(buildFullUrl(PUB_KEY_PATH)).get().build();

        try (Response response = httpClient.newCall(request).execute()) {
            Thread.sleep(5000);
            String responseBodyString = response.body() != null ? response.body().string() : null;

            if (!response.isSuccessful()) {
                String errorMessage = extractErrorMessage(responseBodyString);
                System.err.println("   ОШИБКА СЕРВЕРА при загрузке ключа: " + response.code() + " " + response.message());
                System.err.println("   Сообщение от сервера: " + errorMessage);
                return false;
            }

            if (responseBodyString == null || responseBodyString.isEmpty()) {
                System.err.println("   ОШИБКА: Тело ответа от сервера пустое.");
                return false;
            }

            System.out.println("   Получен ключ (первые 100 символов):\n" + responseBodyString.substring(0, Math.min(responseBodyString.length(), 100)) + "...");

            String formattedPem = responseBodyString.replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "").replaceAll("\\s", "");
            byte[] decodedKey = Base64.getDecoder().decode(formattedPem);

            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decodedKey));
            jwtParser = Jwts.parser().verifyWith(publicKey).build();

            System.out.println("   Публичный ключ успешно загружен.");
            return true;
        } catch (Exception e) {
            System.err.println("   КРИТИЧЕСКАЯ ОШИБКА при обработке публичного ключа: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    // --- 2. ВХОД В СИСТЕМУ ---
    public boolean loginAction(String email, String password) {
        if (jwtParser == null) {
            System.err.println("   ОШИБКА: Публичный ключ не загружен.");
            return false;
        }
        System.out.println("\n2. Вход в систему...");
        currentAccessToken = null;
        currentRefreshToken = null;

        String jsonPayload;
        try {
            Map<String, String> payload = Map.of("email", email, "password", password);
            jsonPayload = objectMapper.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            System.err.println("   ОШИБКА: Не удалось сформировать JSON для входа: " + e.getMessage());
            return false;
        }
        RequestBody body = RequestBody.create(jsonPayload, JSON_MEDIA);

        Request request = new Request.Builder().url(buildFullUrl(LOGIN_PATH)).post(body).build();

        try (Response response = httpClient.newCall(request).execute()) {
            Thread.sleep(5000);
            String responseBodyString = response.body() != null ? response.body().string() : null;

            if (!response.isSuccessful()) {
                String errorMessage = extractErrorMessage(responseBodyString);
                System.err.println("   ОШИБКА СЕРВЕРА при входе: " + response.code() + " " + response.message());
                System.err.println("   Сообщение от сервера: " + errorMessage);
                return false;
            }

            if (responseBodyString == null || responseBodyString.isEmpty()) {
                System.err.println("   ОШИБКА: Тело ответа от сервера пустое.");
                return false;
            }

            Map<String, String> tokens = objectMapper.readValue(responseBodyString, new TypeReference<>() {
            });
            currentAccessToken = tokens.get("accessToken");
            currentRefreshToken = tokens.get("refreshToken");

            if (currentAccessToken == null) {
                System.err.println("   ОШИБКА: Сервер не вернул accessToken.");
                return false;
            }

            System.out.println("   Вход успешен.");
            verifyAndDisplayTokenStatic(currentAccessToken, "Access Token (после логина)", jwtParser, objectMapper);

            if (currentRefreshToken != null) {
                System.out.println("   Получен Refresh Token: " + currentRefreshToken.substring(0, Math.min(currentRefreshToken.length(), 20)) + "...");
            }

            return true;
        } catch (Exception e) {
            System.err.println("   КРИТИЧЕСКАЯ ОШИБКА при входе: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    // --- 3. ОБНОВЛЕНИЕ ТОКЕНА ---
    public boolean refreshAction() {
        if (jwtParser == null) {
            System.err.println("   ОШИБКА: Публичный ключ не загружен.");
            return false;
        }
        if (currentRefreshToken == null) {
            System.err.println("   ОШИБКА: Отсутствует Refresh Token для обновления.");
            return false;
        }
        System.out.println("\n3. Обновление Access Token...");

        String jsonPayload;
        try {
            Map<String, String> payload = Map.of("refreshToken", currentRefreshToken);
            jsonPayload = objectMapper.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            System.err.println("   ОШИБКА: Не удалось сформировать JSON для обновления токена: " + e.getMessage());
            return false;
        }
        RequestBody body = RequestBody.create(jsonPayload, JSON_MEDIA);

        Request request = new Request.Builder().url(buildFullUrl(REFRESH_PATH)).post(body).build();
        System.out.println("   Запрос на: " + request.url());

        try (Response response = httpClient.newCall(request).execute()) {
            Thread.sleep(5000);
            String responseBodyString = response.body() != null ? response.body().string() : null;

            if (!response.isSuccessful()) {
                String errorMessage = extractErrorMessage(responseBodyString);
                System.err.println("   ОШИБКА СЕРВЕРА при обновлении токена: " + response.code() + " " + response.message());
                System.err.println("   Сообщение от сервера: " + errorMessage);
                return false;
            }

            if (responseBodyString == null || responseBodyString.isEmpty()) {
                System.err.println("   ОШИБКА: Тело ответа от сервера пустое при обновлении токена (ожидался JSON с токенами).");
                return false;
            }

            Map<String, String> tokens = objectMapper.readValue(responseBodyString, new TypeReference<>() {
            });
            String newAccessToken = tokens.get("accessToken") != null ? tokens.get("accessToken") : tokens.get("access_token");
            String newRefreshToken = tokens.get("refreshToken") != null ? tokens.get("refreshToken") : tokens.get("refresh_token");

            if (newAccessToken == null) {
                System.err.println("   ОШИБКА: Сервер не вернул новый accessToken при обновлении. Тело ответа: \n" + tryPrettyPrintJsonElseRaw(responseBodyString, objectMapper));
                return false;
            }

            currentAccessToken = newAccessToken;
            if (newRefreshToken != null) {
                currentRefreshToken = newRefreshToken;
                System.out.println("   Сервер выдал новый Refresh Token.");
            }

            System.out.println("   Токен успешно обновлен.");
            verifyAndDisplayTokenStatic(currentAccessToken, "Access Token (после обновления)", jwtParser, objectMapper);
            return true;
        } catch (Exception e) {
            System.err.println("   КРИТИЧЕСКАЯ ОШИБКА при обновлении токена: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    // --- 4. ПОЛУЧЕНИЕ КОНТАКТОВ (ЗАЩИЩЕННЫЙ РЕСУРС) ---
    public void getContactsAction() {
        if (currentAccessToken == null) {
            System.err.println("   ОШИБКА: Отсутствует Access Token. Войдите или обновите токен.");
            return;
        }
        System.out.println("\n4. Запрос контактов...");

        Request request = new Request.Builder().url(buildFullUrl(CONTACTS_PATH)).get()
                .addHeader("Authorization", "Bearer " + currentAccessToken)
                .build();
        System.out.println("   Запрос на: " + request.url() + " с Authorization header.");

        try (Response response = httpClient.newCall(request).execute()) {
            Thread.sleep(5000);
            String responseBodyString = response.body() != null ? response.body().string() : null;

            if (!response.isSuccessful()) {
                String errorMessage = extractErrorMessage(responseBodyString);
                System.err.println("   ОШИБКА СЕРВЕРА при получении контактов: " + response.code() + " " + response.message());
                System.err.println("   Сообщение от сервера: " + errorMessage);
                if (response.code() == 401 || response.code() == 403) {
                    System.err.println("   ДОСТУП ЗАПРЕЩЕН. Ваш Access Token мог истечь или недействителен. Попробуйте обновить его.");
                }
                return;
            }

            if (responseBodyString == null || responseBodyString.isEmpty()) {
                System.err.println("   ОШИБКА: Тело ответа от сервера пустое при получении контактов (ожидался JSON со списком контактов).");
                return;
            }

            List<Contact> contacts = objectMapper.readValue(responseBodyString, new TypeReference<>() {
            });
            System.out.println("   Контакты получены:");
            if (contacts.isEmpty()) {
                System.out.println("     (список пуст)");
            } else {
                contacts.forEach(c -> System.out.printf("     ID: %d, Username: %s, FirstName: %s, LastName: %s, PhotoUrl: %s%n",
                        c.id(), c.username(), c.firstName(), c.lastName(), c.photoUrl() != null ? c.photoUrl() : "null"));
            }
        } catch (Exception e) {
            System.err.println("   КРИТИЧЕСКАЯ ОШИБКА при получении контактов: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
        }
    }

    // --- ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ---

    private String extractErrorMessage(String responseBodyString) {
        if (responseBodyString == null || responseBodyString.isEmpty()) {
            return "Тело ответа пустое или отсутствует";
        }
        try {
            Map<String, String> errorResponse = objectMapper.readValue(responseBodyString, new TypeReference<>() {
            });
            return errorResponse.getOrDefault("error", "Неизвестная ошибка от сервера");
        } catch (JsonProcessingException e) {
            return "Не удалось разобрать JSON ответа: " + responseBodyString;
        }
    }

    private static String tryPrettyPrintJsonElseRaw(String text, ObjectMapper mapper) {
        if (text == null || text.isEmpty()) {
            return text; // Возвращаем как есть (null или пустую строку)
        }
        try {
            String trimmedText = text.trim();
            // Простая проверка, похожа ли строка на JSON объект или массив
            if ((trimmedText.startsWith("{") && trimmedText.endsWith("}")) ||
                    (trimmedText.startsWith("[") && trimmedText.endsWith("]"))) {
                Object jsonObject = mapper.readValue(trimmedText, Object.class);
                return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject);
            }
        } catch (JsonProcessingException e) {
            // Не удалось распарсить или отформатировать как JSON, ничего страшного, вернем как есть
        }
        return text; // Возвращаем исходный текст
    }

    private static void verifyAndDisplayTokenStatic(String token, String tokenLabel, JwtParser jwtParser, ObjectMapper mapper) {
        if (jwtParser == null) {
            System.out.println("   JwtParser не инициализирован для " + tokenLabel);
            return;
        }
        if (token == null) {
            System.out.println("   " + tokenLabel + " is null, cannot verify.");
            return;
        }

        System.out.println("   --- Информация о токене: " + tokenLabel + " ---");
        System.out.println("   RAW: " + token.substring(0, Math.min(token.length(), 60)) + "...");
        Jws<Claims> claimsJws;
        try {
            claimsJws = jwtParser.parseSignedClaims(token);
            System.out.println("   ПОДПИСЬ ПРОВЕРЕНА! Токен аутентичен.");
        } catch (ExpiredJwtException eje) {
            System.out.println("   ПРОВЕРКА НЕ ПРОШЛА: Просроченный токен (ExpiredJwtException) - " + eje.getMessage());
            decodeAndShowPartsForDebugStatic(token, mapper);
            return;
        } catch (UnsupportedJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e) {
            System.out.println("   ПРОВЕРКА НЕ ПРОШЛА или токен невалиден: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            decodeAndShowPartsForDebugStatic(token, mapper);
            return;
        } catch (Exception e) { // Более общий перехватчик для неожиданных ошибок парсинга
            System.out.println("   Неожиданная ошибка при проверке токена: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            decodeAndShowPartsForDebugStatic(token, mapper);
            return;
        }

        String[] parts = token.split("\\.");
        try {
            String header = new String(Base64.getUrlDecoder().decode(parts[0]));
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));

            System.out.println("   ЗАГОЛОВОК ТОКЕНА (декодированный):\n" + tryPrettyPrintJsonElseRaw(header, mapper));
            System.out.println("   ПОЛЕЗНАЯ НАГРУЗКА ТОКЕНА (декодированная):\n" + tryPrettyPrintJsonElseRaw(payload, mapper));

            StringBuilder claimsStr = new StringBuilder("   ПРОВЕРЕННЫЕ УТВЕРЖДЕНИЯ (CLAIMS) из полезной нагрузки:\n");
            claimsJws.getPayload().forEach((k, v) -> claimsStr.append(String.format("       %s: %s\n", k, v)));
            System.out.println(claimsStr.toString());

        } catch (Exception e) { // Ошибка декодирования Base64 или другая
            System.out.println("   Ошибка при декодировании или отображении частей токена: " + e.getMessage());
        }
    }

    private static void decodeAndShowPartsForDebugStatic(String token, ObjectMapper mapper) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length >= 2) { // Нужны как минимум заголовок и полезная нагрузка
                String headerDecoded = new String(Base64.getUrlDecoder().decode(parts[0]));
                String payloadDecoded = new String(Base64.getUrlDecoder().decode(parts[1]));
                System.out.println("   ДЕКОДИРОВАННЫЙ ЗАГОЛОВОК (без проверки подписи):\n" + tryPrettyPrintJsonElseRaw(headerDecoded, mapper));
                System.out.println("   ДЕКОДИРОВАННАЯ ПОЛЕЗНАЯ НАГРУЗКА (без проверки подписи):\n" + tryPrettyPrintJsonElseRaw(payloadDecoded, mapper));
            } else {
                System.out.println("   Токен не содержит ожидаемого количества частей (header.payload.signature) для декодирования.");
            }
        } catch (IllegalArgumentException e) { // Ошибка декодирования Base64
            System.out.println("   Не удалось декодировать части токена из Base64Url (возможно, неверный формат): " + e.getMessage());
        } catch (Exception e) { // Другие неожиданные ошибки
            System.out.println("   Не удалось декодировать части токена для отладки: " + e.getClass().getSimpleName() + " - " + e.getMessage());
        }
    }
}