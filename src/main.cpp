/*
   NFCDoorController

   Check permission of mifare classic cards, if access granted, open door

   Connect PN532 on esp8266 SPI bus, chip select on D3
   Connect door transistor/relais on D2
 */

#include <ESP8266WiFi.h>
#include <ESP8266WiFiMulti.h>
#include <ESP8266mDNS.h>
#include <WiFiUdp.h>
#include <ArduinoOTA.h>
#include <ESP8266HTTPClient.h>
#include <Wire.h>
#include <SPI.h>
#include <PN532_SPI.h>
#include <PN532.h>
#include "FS.h"
#include <stdio.h>
#include <ESP8266TrueRandom.h>
#include <ArduinoJson.h>

#include "AuthData.h"

#define BUZZ_SIZE 1024

PN532_SPI pn532spi(SPI, D3);
PN532 nfc(pn532spi);
ESP8266WiFiMulti wifiMulti;
HTTPClient http;

void syncGrants();
void logNew(String);
void logKnownError(String);
void logKnownGranted(String);
void openDoor();
void readNFC();
void nfcInit();

String response;
String pathLogs = "/logs/";
String pathGrants = "/grants/";
String pathOTPs = "/otps/";
String pathStatus = "/init_done";

uint8_t defAuthKey[6];
uint8_t data[16];
uint8_t doorPin = D2;

void setup(void) {
        Serial.begin(115200);
        Serial.println("Booting");

        nfcInit();
        SPIFFS.begin();

        if(!SPIFFS.exists(pathStatus)) {
                SPIFFS.format();
                File fPathStatus = SPIFFS.open(pathStatus, "w");
                fPathStatus.println("Init done.");
                fPathStatus.close();
        }

        // Prepare keyData - all keys are set to FFFFFFFFFFFFh at chip delivery from the factory.
        for (byte i = 0; i < 6; i++) {
                defAuthKey[i] = 0xFF;
        }

        wifiMulti.addAP(ssid1, password1);



        // No authentication by default
        ArduinoOTA.setPassword(otaPass);

        ArduinoOTA.onStart([] () {Serial.println("Start"); });
        ArduinoOTA.onEnd([] () { Serial.println("\nEnd"); });
        ArduinoOTA.onProgress([] (unsigned int progress, unsigned int total) {Serial.printf("Progress: %u%%\r", (progress / (total / 100))); });
        ArduinoOTA.onError([] (ota_error_t error) {
                                   Serial.printf("Error[%u]: ", error);
                                   if (error == OTA_AUTH_ERROR) Serial.println("Auth Failed");
                                   else if (error == OTA_BEGIN_ERROR) Serial.println("Begin Failed");
                                   else if (error == OTA_CONNECT_ERROR) Serial.println("Connect Failed");
                                   else if (error == OTA_RECEIVE_ERROR) Serial.println("Receive Failed");
                                   else if (error == OTA_END_ERROR) Serial.println("End Failed");
                           });
        ArduinoOTA.begin();

        pinMode(doorPin, OUTPUT);
        digitalWrite(doorPin, LOW);

}

float lastSync = 0;
bool synced = false;
bool readNFCTask = false;
void loop(void) {
        wifiMulti.run();
        ArduinoOTA.handle();

        //sync data every hour
        if(!synced || millis() - lastSync > 36e6) {
                syncGrants();
                lastSync = millis();
        }

        uint8_t success;
        uint8_t uid[] = { 0, 0, 0, 0, 0, 0, 0 };    // Buffer to store the returned UID
        uint8_t uidLength;                          // Length of the UID (4 or 7 bytes depending on ISO14443A card type)

        // Wait for an ISO14443A type cards (Mifare, etc.).  When one is found
        // 'uid' will be populated with the UID, and uidLength will indicate
        // if the uid is 4 bytes (Mifare Classic) or 7 bytes (Mifare Ultralight)

        if( nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength) ) {

                String sUid = "";
                if (uidLength == 4)
                {
                        for (byte i = 0; i < uidLength; i++) {
                                //uid += mfrc522.uid.uidByte[i] < 0x10 ? " 0" : "_";
                                sUid += "_";
                                sUid += uid[i], HEX;
                        }
                }

                if(!SPIFFS.exists(String(pathGrants + sUid))) {
                        logNew(sUid);
                        delay(500);
                        return;
                }

                String otpFromFile = "";
                String otpPath = String(pathOTPs + sUid);
                bool otpFound = false;
                if(SPIFFS.exists(otpPath)) {
                        File otpFile = SPIFFS.open(otpPath, "r");
                        otpFromFile = otpFile.readStringUntil('\n');
                        otpFile.close();
                        otpFound = true;
                }

                Serial.println("OTP From File");
                Serial.println(otpFromFile);

                //if auth goes well, read block data
                if(nfc.mifareclassic_AuthenticateBlock (uid, uidLength, selectBlock, 1, defAuthKey)) {
                        if(nfc.mifareclassic_ReadDataBlock(selectBlock, data)) {
                                String otpFromChip = "";
                                for (byte i = 0; i < 16; i++) {
                                        //uid += mfrc522.uid.uidByte[i] < 0x10 ? " 0" : "_";
                                        otpFromChip += "_";
                                        otpFromChip += data[i], HEX;
                                }

                                Serial.println("OTP From chip before update");
                                Serial.println(otpFromChip);
                                //if otp available localy, compare, otherwise create
                                bool otpMatch = false;
                                if( strncmp(otpFromChip.c_str(), otpFromFile.c_str(), 32) == 0 || !otpFound) {
                                        Serial.println("otps matched or new");
                                        otpMatch = true;
                                }else{
                                        Serial.println("otps not matched");
                                        Serial.println(otpFromChip.c_str());
                                        Serial.println(otpFromFile.c_str());
                                }
                                //create new otp
                                uint8_t newOtp[16];
                                ESP8266TrueRandom.uuid(newOtp);
                                String sNewOtp = "";
                                for (byte i = 0; i < 16; i++) {
                                        //uid += mfrc522.uid.uidByte[i] < 0x10 ? " 0" : "_";
                                        sNewOtp += "_";
                                        sNewOtp += newOtp[i], HEX;
                                }
                                if(otpMatch && nfc.mifareclassic_WriteDataBlock(selectBlock, newOtp)) {
                                        File fPathStatus = SPIFFS.open(otpPath, "w");
                                        fPathStatus.println(sNewOtp);
                                        fPathStatus.close();
                                        logKnownGranted(sUid);
                                        Serial.println("all done, open the door");
                                        //Serial.println("OTP after update");
                                        //Serial.println(sNewOtp);
                                        openDoor();
                                }else{
                                        logKnownError(sUid);
                                        Serial.println("something went wrong");
                                        //SPIFFS.remove(otpPath);
                                }
                                Serial.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                        }
                }
                delay(1000);
        }

        //check nfc health and reset if needed
        uint32_t versiondata = nfc.getFirmwareVersion();

        if (!versiondata) {
                Serial.print("Didn't find PN53x board.");
                //ESP.deepSleep(36e6); // 20e6 is 20 microseconds
                //delay(100);
                nfcInit();
        }

        delay(500);
}

void nfcInit(){
  pinMode(D1, OUTPUT);

  //reset
  digitalWrite(D1, HIGH);
  delay(250);
  digitalWrite(D1, LOW);
  delay(400);

  nfc.begin();

  uint32_t versiondata = nfc.getFirmwareVersion();

  if (!versiondata) {
          Serial.print("Didn't find PN53x board, going for sleep now...");
          ESP.deepSleep(36e6); // 20e6 is 20 microseconds
          delay(100);
  }
  // configure board to read RFID tags
  nfc.SAMConfig();
  nfc.setPassiveActivationRetries(0xFF);

}

void readNFC(){
        readNFCTask = true;
}

void logNew(String sUid){
        if(wifiMulti.run() == WL_CONNECTED) {
                http.begin(String(serverUrl + "logs")); //HTTP
                http.addHeader("Authorization", authHeader);
                // start connection and send HTTP header
                http.addHeader("Content-Type", "application/x-www-form-urlencoded");
                int httpCode = http.POST(String("chip_uuid=" + sUid + "&data=" + "unknown"));
                http.end();
                Serial.println("logNew send");
        }else{
                Serial.println("no wifi yet");
        }
}
void logKnownError(String sUid){
        if(wifiMulti.run() == WL_CONNECTED) {
                http.begin(String(serverUrl + "logs")); //HTTP
                http.addHeader("Authorization", authHeader);
                // start connection and send HTTP header
                http.addHeader("Content-Type", "application/x-www-form-urlencoded");
                int httpCode = http.POST(String("chip_uuid=" + sUid + "&data=" + "known-error"));
                http.end();
                Serial.println("logKnownError send");
        }else{
                Serial.println("no wifi yet");
        }
}
void logKnownGranted(String sUid){
        if(wifiMulti.run() == WL_CONNECTED) {
                http.begin(String(serverUrl + "logs")); //HTTP
                http.addHeader("Authorization", authHeader);
                // start connection and send HTTP header
                http.addHeader("Content-Type", "application/x-www-form-urlencoded");
                int httpCode = http.POST(String("chip_uuid=" + sUid + "&data=" + "known-granted"));
                http.end();
                Serial.println("logKnownGranted send");
        }else{
                Serial.println("no wifi yet");
        }
}

void syncGrants(){
        if(wifiMulti.run() == WL_CONNECTED) {
                http.begin(String(serverUrl + "doorUserGrants")); //HTTP
                http.addHeader("Authorization", authHeader);
                // start connection and send HTTP header
                int httpCode = http.GET();
                if(httpCode > 0 && httpCode == HTTP_CODE_OK) {
                        DynamicJsonBuffer jsonBuffer(1024);
                        String payload = http.getString();
                        JsonObject& root = jsonBuffer.parseObject(payload);
                        if (root.success()) {
                                JsonObject& object = root["permissions"];
                                //clear all grants in /grants
                                Dir dir = SPIFFS.openDir(pathGrants);
                                while (dir.next()) {
                                        String filename = dir.fileName();
                                        SPIFFS.remove(filename);
                                }
                                for(JsonObject::iterator it=object.begin(); it!=object.end(); ++it)
                                {
                                        // *it contains the key/value pair
                                        const char* key = it->key;

                                        File fPathStatus = SPIFFS.open(
                                                String(pathGrants + String(key)), "w"
                                                );
                                        fPathStatus.println(1);
                                        fPathStatus.close();
                                }
                        }
                }
                http.end();

                synced = true;
        }else{
                Serial.println("no wifi yet");
        }
}

void openDoor(){
        digitalWrite(doorPin, HIGH);
        delay(3000);
        digitalWrite(doorPin, LOW);
}
