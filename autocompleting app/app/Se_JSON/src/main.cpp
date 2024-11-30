#include <Arduino.h>
#include <ArduinoJson.h>

#define LED_PIN 2  // Define the pin for the LED

String receivedId = "";  // Initialize the variable to store the received ID
bool idReceived = false;  // Flag to indicate if the ID has been received

void setup() {
    Serial.begin(115200);  // Initialize serial communication
    pinMode(LED_PIN, OUTPUT);  // Set the LED pin as an output
    digitalWrite(LED_PIN, HIGH);  // Turn on the LED initially

    // Display a message on startup
    Serial.println("ESP32 is ready. Waiting for ID...");
}

void loop() {
    if (Serial.available()) {
        String input = Serial.readStringUntil('\n');
        input.trim();  // Remove any newline or extra spaces

        if (input.startsWith("{")) {  // If the input is JSON
            StaticJsonDocument<200> doc;
            DeserializationError error = deserializeJson(doc, input);
            if (!error) {
                digitalWrite(LED_PIN, LOW);  // Turn off the LED
                Serial.println("JSON_RECEIVED");
            }
        } else {  // If the input is not JSON, assume it's the ID
            receivedId = input;
            idReceived = true;  // Set the flag to true
            Serial.print("ID Received: ");
            Serial.println(receivedId);
        }
    }

    // Display the ID if it has been received
    if (idReceived) {
        Serial.print("Stored ID: ");
        Serial.println(receivedId);
        delay(5000);  // Wait for 5 seconds before showing the ID again
    }
}
