#include <SPI.h>
#include <MFRC522.h>
#include <WiFi.h>
#include <HTTPClient.h>

// WiFi credentials
const char* ssid = "your_ssid";
const char* password = "your_pass";

// Server URL
const char* serverUrl = "http://your_sever_ip:5000/api";

// RFID Pins
#define SS_PIN 5
#define RST_PIN 22

// Initialize RFID
MFRC522 mfrc522(SS_PIN, RST_PIN);

// Token counter
int tokenNumber = 1;

void setup() {
  // Initialize Serial Monitor
  Serial.begin(115200);

  // Initialize RFID
  SPI.begin();
  mfrc522.PCD_Init();

  // Connect to Wi-Fi
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }
  Serial.println("Connected to WiFi");
}

void loop() {
  // Check for new RFID card
  if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
    // Get card UID
    String cardUID = "";
    for (byte i = 0; i < mfrc522.uid.size; i++) {
      cardUID += String(mfrc522.uid.uidByte[i], HEX);
    }
    Serial.println("Card UID: " + cardUID);

    // Assign token number
    Serial.println("Token: " + String(tokenNumber));

    // Send data to server
    sendToServer(cardUID, tokenNumber);

    // Increment token number
    tokenNumber++;

    // Halt PICC
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
  }
}

void sendToServer(String cardUID, int tokenNumber) {
  if (WiFi.status() == WL_CONNECTED) {
    HTTPClient http;
    String url = String(serverUrl) + "?cardUID=" + cardUID + "&token=" + String(tokenNumber);
    http.begin(url);

    int httpCode = http.GET();
    if (httpCode > 0) {
      String payload = http.getString();
      Serial.println("Server Response: " + payload);
    } else {
      Serial.println("Error sending data to server");
    }
    http.end();
  }
}